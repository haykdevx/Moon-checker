"""
The checker-facing API (JSON over HTTPS). Flow:

  1. POST /api/v1/claim                      {code, client, protocol}
                                             -> {sessionId, token, upload: {protocol, nonce, deadline}, ...}
  2. POST /api/v1/sessions/<id>/progress     Bearer token     (every few seconds while scanning)
  3. POST /api/v1/sessions/<id>/report       Bearer token     gzip(canonical evidence JSON)

What each piece establishes (and what it does not) is in docs/report-assurance.md:

- the code works exactly once, only for its admin, and only until it expires;
- the bearer token (random, stored as SHA-256) shows later requests come from whoever claimed it;
- the upload value (protocol 3, random, stored as SHA-256) must be inside the report together with
  this session's id: a report made for another check, or an unmodified old report, is refused,
  and the value is consumed atomically so exactly one report is accepted;
- none of this shows that an unmodified checker produced the report: everything in the report,
  including its build hash, is what the player's PC says.
"""
import hashlib
import hmac
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from accounts.models import hash_token
from core import ratelimit
from core.audit import client_ip, record
from core.models import SiteSettings

from . import codes, ingest, trust
from .models import CheckSession, FindingRow, Report, TrustedBuild

log = logging.getLogger("moon.api")

HEARTBEAT_SECONDS = 5
JSON_LIMIT = 64 * 1024


def _error(status, code, message, **extra):
    resp = JsonResponse({"error": code, "message": message, **extra}, status=status)
    if status == 429:
        resp["Retry-After"] = str(extra.get("retryAfter", 600))
    return resp


def _small_json(request):
    return ingest.parse_json_object(ingest.read_body(request, JSON_LIMIT))


@csrf_exempt
@require_GET
def ping(request):
    site = SiteSettings.load()
    return JsonResponse({"service": "moon-panel", "api": 1, "serverTime": timezone.now().isoformat(),
                         "minCheckerVersion": site.min_checker_version})


@csrf_exempt
@require_POST
def claim(request):
    ip = client_ip(request)
    if ratelimit.exceeded("claim-fail", ip, 10):
        return _error(429, "too_many_attempts", "Too many wrong codes from this network. Try again in 10 minutes.")
    if ratelimit.hit("claim-ip", ip, 600) > 60:
        return _error(429, "too_many_attempts", "Too many requests. Try again in 10 minutes.")
    try:
        body = _small_json(request)
    except ingest.IngestError as e:
        return _error(e.status, e.code, e.message)

    def wrong(status, code, message):
        ratelimit.hit("claim-fail", ip, 600)
        return _error(status, code, message)

    code = codes.normalize(body.get("code"))
    if code is None:
        return wrong(404, "invalid_code", "This code does not exist. Check it with your admin.")
    client = ingest.sanitize_client(body.get("client"))
    site = SiteSettings.load()
    if ingest.version_tuple(client["appVersion"]) < ingest.version_tuple(site.min_checker_version):
        return _error(426, "checker_outdated",
                      f"This checker is outdated. Download version {site.min_checker_version} or newer.",
                      download=f"{settings.PUBLIC_URL}{settings.MOON_DOWNLOAD_URL}")
    if site.block_untrusted_builds and not TrustedBuild.objects.filter(sha256=client["selfHashFull"]).exists():
        return _error(403, "untrusted_build", "This copy of the checker is not an official build. "
                                              "Download it again from the official site.",
                      download=f"{settings.PUBLIC_URL}{settings.MOON_DOWNLOAD_URL}")

    protocol = ingest.claimed_protocol(body)
    bound = protocol >= settings.MOON_UPLOAD_PROTOCOL
    if not bound and not site.accept_unbound_reports:
        return _error(426, "checker_outdated",
                      "This checker is outdated: it cannot bind its report to the check. "
                      "Download the current version.",
                      download=f"{settings.PUBLIC_URL}{settings.MOON_DOWNLOAD_URL}")

    now = timezone.now()
    nonce = secrets.token_urlsafe(32) if bound else ""
    with transaction.atomic():
        session = CheckSession.objects.select_for_update().select_related("admin").filter(code=code).first()
        if session is None:
            return wrong(404, "invalid_code", "This code does not exist. Check it with your admin.")
        if session.status == CheckSession.WAITING and session.expires_at <= now:
            session.status = CheckSession.EXPIRED
            session.save(update_fields=["status"])
        if session.status == CheckSession.EXPIRED:
            return wrong(410, "code_expired", "This code has expired. Ask your admin for a new one.")
        if session.status == CheckSession.CANCELLED:
            return wrong(410, "code_cancelled", "The admin cancelled this check.")
        if session.status != CheckSession.WAITING or not session.admin.is_active:
            return wrong(409, "code_used", "This code was already used. Ask your admin for a new one.")
        token = secrets.token_urlsafe(32)
        session.status = CheckSession.CONNECTED
        session.claimed_at = session.last_seen_at = now
        session.claimed_ip = ip
        session.client = client
        session.token_hash = hash_token(token)
        session.protocol = settings.MOON_UPLOAD_PROTOCOL if bound else protocol
        session.upload_nonce_hash = hash_token(nonce) if bound else ""
        session.upload_deadline = now + timedelta(minutes=settings.MOON_UPLOAD_WINDOW_MINUTES)
        session.save()
    record(request, "check.connected", str(session.pk), actor=None, code=code,
           host=client["hostname"], app=client["appVersion"])
    from .player import issue_player_token
    from django.urls import reverse
    status_url = settings.PUBLIC_URL + reverse("player:status", args=[issue_player_token(session)])
    upload = {"protocol": session.protocol, "deadline": session.upload_deadline.isoformat()}
    if bound:
        upload["nonce"] = nonce
    return JsonResponse({
        "sessionId": str(session.pk),
        "token": token,
        "upload": upload,
        "admin": {"alias": session.admin.username, "name": session.admin.label},
        "player": {"name": session.player_name},
        "heartbeatSeconds": HEARTBEAT_SECONDS,
        "statusUrl": status_url,
        "serverTime": now.isoformat(),
    })


def _authenticate(request, session_id):
    """Returns the session for a valid bearer token, or an error response."""
    ip = client_ip(request)
    if ratelimit.exceeded("token-fail", ip, 20):
        return None, _error(429, "too_many_attempts", "Too many failed requests.")
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
    session = CheckSession.objects.filter(pk=session_id).first() if token else None
    if session is None or not session.token_hash or not hmac.compare_digest(session.token_hash, hash_token(token)):
        ratelimit.hit("token-fail", ip, 600)
        return None, _error(401, "unauthorized", "Session is not valid.")
    return session, None


def _gone_or_conflict(session):
    if session.status == CheckSession.COMPLETED:
        return _error(409, "already_completed", "This check was already delivered.",
                      verificationCode=session.verification_code)
    if session.status == CheckSession.CANCELLED:
        return _error(410, "cancelled", "The admin cancelled this check.")
    if session.status not in (CheckSession.CONNECTED, CheckSession.SCANNING, CheckSession.ABANDONED):
        return _error(409, "bad_state", "This check is not running.")
    return None


@csrf_exempt
@require_POST
def progress(request, session_id):
    session, err = _authenticate(request, session_id)
    if err:
        return err
    # a heartbeat every few seconds is normal; a flood of writes is not
    if ratelimit.hit("progress", str(session.pk), 60) > 120:
        return _error(429, "too_many_requests", "Progress updates are too frequent.", retryAfter=30)
    try:
        data = ingest.sanitize_progress(_small_json(request))
    except ingest.IngestError as e:
        return _error(e.status, e.code, e.message)
    now = timezone.now()
    with transaction.atomic():
        session = CheckSession.objects.select_for_update().get(pk=session.pk)
        err = _gone_or_conflict(session)
        if err:
            return err
        if session.status == CheckSession.ABANDONED and session.scan_started_at is not None:
            session.interruptions += 1
        if session.scan_started_at is None and data["total"]:
            session.scan_started_at = now
        session.status = CheckSession.SCANNING if session.scan_started_at else CheckSession.CONNECTED
        session.last_seen_at = now
        session.progress_done, session.progress_total = data["done"], data["total"]
        session.progress_module = data["module"]
        session.live_counts = data["counts"]
        session.save(update_fields=["status", "scan_started_at", "last_seen_at", "progress_done", "progress_total",
                                    "progress_module", "live_counts", "interruptions"])
    return JsonResponse({"ok": True})


@csrf_exempt
@require_POST
def report(request, session_id):
    session, err = _authenticate(request, session_id)
    if err:
        return err
    err = _gone_or_conflict(session)
    if err:
        return err
    try:
        raw = ingest.decode_report_body(request)
        claimed_sha = request.headers.get("X-Moon-Sha256", "").strip().lower()
        sha = hashlib.sha256(raw).hexdigest()
        if claimed_sha and not hmac.compare_digest(claimed_sha, sha):
            raise ingest.IngestError(400, "checksum_mismatch", "Upload was corrupted in transit.")
        data = ingest.validate_report(ingest.parse_json_object(raw))
    except ingest.IngestError as e:
        log.warning("report for %s rejected: %s", session.pk, e.message)
        return _error(e.status, e.code, e.message)

    now = timezone.now()
    try:
        _check_bound_to_session(session, data, now)
    except ingest.IngestError as e:
        log.warning("report for %s refused: %s", session.pk, e.message)
        return _error(e.status, e.code, e.message)
    code = ingest.verification_code(raw)
    was_abandoned = session.status == CheckSession.ABANDONED
    try:
        with transaction.atomic():
            # consume the upload exactly once: a conditional UPDATE is atomic on every database
            # (SQLite has no row locks), so of two concurrent uploads only one changes the row
            won = CheckSession.objects.filter(
                pk=session.pk, status__in=_UPLOADABLE, upload_nonce_hash=session.upload_nonce_hash,
            ).update(status=CheckSession.COMPLETED, upload_nonce_hash="", completed_at=now)
            if won != 1:
                raise _Lost()
            session = CheckSession.objects.select_related("admin").get(pk=session.pk)
            _store(request, session, data, raw, sha, code, now, was_abandoned)
    except (_Lost, IntegrityError):
        session.refresh_from_db()
        return _gone_or_conflict(session) or _error(409, "already_completed", "This check was already delivered.",
                                                    verificationCode=session.verification_code)
    legacy = {"score": data["score"]} if data["score"] is not None else {}  # v1 reports only
    record(request, "check.completed", str(session.pk), actor=None, verdict=data["verdict"], trust=session.trust,
           findings=len(data["findings"]), **legacy)
    return JsonResponse({"ok": True, "verificationCode": code})


_UPLOADABLE = (CheckSession.CONNECTED, CheckSession.SCANNING, CheckSession.ABANDONED)


class _Lost(Exception):
    """Another upload for the same check won the race."""


# what the checker said about itself when it claimed the code must be what the report says
_SAME_AT_UPLOAD = (("hostname", "hostname"), ("user", "user"), ("os", "os"), ("appVersion", "appVersion"))


def _check_bound_to_session(session, data, now):
    """Refuses a report that was not made for this check, arrives too late or contradicts the claim."""
    reject = ingest.IngestError
    if session.upload_deadline is not None and now > session.upload_deadline:
        raise reject(410, "upload_expired", "This check ran too long ago; ask the admin for a new code.")
    binding = data.get("binding")
    if session.protocol >= settings.MOON_UPLOAD_PROTOCOL:
        if data["schema"] != ingest.SCHEMA_V2 or binding is None:
            raise reject(422, "unbound_report", "The report is not bound to this check.")
        if binding["panelSessionId"] != str(session.pk):
            raise reject(409, "wrong_session", "This report was made for a different check.")
        if binding["protocol"] != session.protocol:
            raise reject(422, "protocol_mismatch", "The report uses a different upload protocol than the check.")
        if not session.upload_nonce_hash or not hmac.compare_digest(session.upload_nonce_hash,
                                                                    hash_token(binding["uploadNonce"])):
            raise reject(409, "stale_upload", "This report does not carry this check's upload value.")
    elif binding is not None and binding["panelSessionId"] != str(session.pk):
        raise reject(409, "wrong_session", "This report was made for a different check.")
    client, env = session.client or {}, data["environment"]
    for claim_key, report_key in _SAME_AT_UPLOAD:
        if (client.get(claim_key) or "") != (env.get(report_key) or ""):
            raise reject(422, "inconsistent_report",
                         f"The report's {report_key} differs from what the checker sent when the code was entered.")
    short = (env.get("selfHash") or "").lower()
    if short and client.get("selfHashFull") and not client["selfHashFull"].startswith(short):
        raise reject(422, "inconsistent_report", "The report names a different program file than the one that "
                                                 "entered the code.")
    if CheckSession.objects.filter(client_check_id=data["checkId"]).exclude(pk=session.pk).exists():
        raise reject(409, "replayed_report", "This report was already delivered in another check.")


def _store(request, session, data, raw, sha, code, now, was_abandoned):
    """Writes the accepted report, its findings and the server's checks (inside the consuming transaction)."""
    if was_abandoned and session.scan_started_at is not None:
        session.interruptions += 1
    session.report_ip = client_ip(request)
    Report.objects.create(
        session=session, raw_gzip=ingest.gzip_bytes(raw), sha256=sha, size_bytes=len(raw),
        environment=data["environment"], modules=data["modules"],
        meta={k: data[k] for k in ("schema", "checkId", "startedAt", "finishedAt", "durationSeconds",
                                   "signatureVersion", "signatureOrigin", "coverage", "assurance",
                                   "reasons", "consent", "rules", "clientOutcome")}
        | {"bound": data.get("binding") is not None, "protocol": session.protocol})
    FindingRow.objects.bulk_create(
        [FindingRow(session=session, rule_id=f["rule"], **{k: v for k, v in f.items() if k != "rule"})
         for f in data["findings"]], batch_size=1000)
    counts = {s.lower(): 0 for s in ingest.SEVERITIES}
    for f in data["findings"]:
        counts[f["severity"].lower()] += 1
    flags, level = trust.evaluate(session, data, now)
    session.status = CheckSession.COMPLETED
    session.completed_at = session.last_seen_at = now
    session.verdict, session.score, session.counts = data["verdict"], data["score"], counts
    session.client_outcome = data["clientOutcome"]
    session.verification_code = code
    session.client_check_id = data["checkId"]
    session.flags, session.trust = flags, level
    session.progress_done = session.progress_total
    session.notify_state = "pending" if session.admin.discord_webhook else ""
    session.save()

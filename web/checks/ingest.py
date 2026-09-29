"""
Boundary validation for everything the checker sends. The checker runs on the
player's PC, so every byte here is untrusted: sizes are capped before and after
decompression, the JSON shape is checked field by field and all strings are
truncated to the column sizes.
"""
import gzip
import hashlib
import hmac
import json
import re
import zlib

from django.conf import settings

from . import policy

SCHEMA = "moon-check/1"          # checker 1.0/1.1-pre: flat findings + weighted score
SCHEMA_V2 = "moon-evidence/2"    # evidence / coverage / assurance / verdict sections
VERDICTS = set(policy.LEGACY_VERDICTS)
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
MODULE_STATES = {"PENDING", "RUNNING", "OK", "SKIPPED", "ERROR", "TIMEOUT"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CHECK_ID = re.compile(r"MOON-[0-9]{6}-[A-Z0-9]{4,8}")  # fullmatch: no trailing newline, ASCII digits only
_VERSION = re.compile(r"^\d+(\.\d+){0,3}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class IngestError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def clip(value, limit):
    """Text for a column: NULs dropped, unpaired surrogates replaced (neither can be stored), at most ``limit``."""
    if value is None or isinstance(value, (dict, list)):
        return ""  # a container where text belongs is malformed; str() of a deep one also exhausts the stack
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\x00", "")
    if not value.isascii():
        value = value.encode("utf-8", "replace").decode("utf-8")
    return value[:limit]


def _one_of(value, allowed):
    """Membership that cannot raise: JSON lists and objects are unhashable."""
    return isinstance(value, str) and value in allowed


def version_tuple(value):
    if not isinstance(value, str) or not _VERSION.match(value.strip()):
        return (0,)
    return tuple(int(p) for p in value.strip().split("."))


def read_body(request, limit):
    body = request.read(limit + 1)
    if len(body) > limit:
        raise IngestError(413, "too_large", "Upload is too large.")
    return body


def gunzip_limited(data, limit):
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, limit + 1)
        if len(out) > limit or d.unconsumed_tail:
            raise IngestError(413, "too_large", "Report is too large after decompression.")
        if not d.eof:
            raise IngestError(400, "bad_encoding", "Truncated gzip stream.")
        return out
    except zlib.error:
        raise IngestError(400, "bad_encoding", "Body is not valid gzip.") from None


def decode_report_body(request):
    body = read_body(request, settings.MOON_MAX_UPLOAD_BYTES)
    encoding = request.headers.get("Content-Encoding", "").strip().lower()
    if encoding == "gzip":
        body = gunzip_limited(body, settings.MOON_MAX_REPORT_BYTES)
    elif encoding not in ("", "identity"):
        raise IngestError(415, "bad_encoding", "Only gzip or identity encoding is accepted.")
    if len(body) > settings.MOON_MAX_REPORT_BYTES:
        raise IngestError(413, "too_large", "Report is too large.")
    return body


def parse_json_object(raw):
    try:
        # strict UTF-8: json.loads(bytes) would let UTF-8-encoded surrogates through
        obj = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    except (ValueError, UnicodeDecodeError, RecursionError):  # RecursionError: nesting deeper than the stack
        raise IngestError(400, "bad_json", "Body is not valid JSON.") from None
    if not isinstance(obj, dict):
        raise IngestError(400, "bad_json", "Expected a JSON object.")
    return obj


def verification_code(canonical_bytes):
    """Same derivation as core/Integrity.shortCode in the checker, so both screens show one code."""
    mac = hmac.new(settings.MOON_VERIFICATION_KEY.encode(), canonical_bytes, hashlib.sha256).hexdigest().upper()
    return f"{mac[0:4]}-{mac[4:8]}-{mac[8:10]}"


def sanitize_client(value):
    """What the checker reports about itself when it claims a code."""
    c = value if isinstance(value, dict) else {}
    full = clip(c.get("selfHashFull"), 64).lower()
    return {
        "hostname": clip(c.get("hostname"), 100),
        "user": clip(c.get("user"), 100),
        "os": clip(c.get("os"), 100),
        "appVersion": clip(c.get("appVersion"), 20),
        "selfHash": clip(c.get("selfHash"), 16),
        "selfHashFull": full if _HEX64.match(full) else "",
        "jvm": clip(c.get("jvm"), 100),
        "elevated": c.get("elevated") is True,
        "offsetMinutes": c.get("utcOffsetMinutes") if isinstance(c.get("utcOffsetMinutes"), int)
        and -900 <= c.get("utcOffsetMinutes") <= 900 else None,
    }


def claimed_protocol(body):
    """The upload protocol a checker says it speaks when it claims a code (0 = before protocol 3)."""
    value = body.get("protocol")
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 else 0


def _int(value, lo, hi, default=0):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(lo, min(hi, value))


def sanitize_progress(obj):
    counts = obj.get("counts") if isinstance(obj.get("counts"), dict) else {}
    return {
        "done": _int(obj.get("done"), 0, 1000),
        "total": _int(obj.get("total"), 0, 1000),
        "module": clip(obj.get("module"), 64),
        "counts": {s.lower(): _int(counts.get(s.lower()), 0, 10 ** 6) for s in SEVERITIES},
    }


def _bad(msg):
    raise IngestError(422, "invalid_report", msg)


def validate_report(obj):
    """Returns a normalised dict (same shape for both schemas); raises IngestError(422)."""
    schema = obj.get("schema")
    if schema == SCHEMA_V2:
        return _validate_v2(obj)
    if schema != SCHEMA:
        _bad("Unsupported report schema.")
    return _validate_v1(obj)


def _validate_v1(obj):
    bad = _bad
    if not _one_of(obj.get("verdict"), VERDICTS):
        bad("Unknown verdict.")
    score = obj.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        bad("Score must be 0-100.")
    check_id = obj.get("checkId")
    if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
        bad("Bad checkId.")
    env = obj.get("environment")
    if not isinstance(env, dict):
        bad("Missing environment.")
    modules = obj.get("modules")
    if not isinstance(modules, dict) or len(modules) > 200:
        bad("Bad modules map.")
    findings = obj.get("findings")
    if not isinstance(findings, list):
        bad("Missing findings.")
    if len(findings) > settings.MOON_MAX_FINDINGS:
        bad("Too many findings.")

    clean_findings = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict) or not _one_of(f.get("severity"), SEVERITIES) or not isinstance(f.get("title"), str):
            bad(f"Finding #{i} is malformed.")
        clean_findings.append({
            "idx": i,
            "severity": f["severity"],
            "category": clip(f.get("category"), 24),
            "module": clip(f.get("module"), 40),
            "title": clip(f.get("title"), 300),
            "detail": clip(f.get("detail"), 4000),
            "evidence": clip(f.get("evidence"), 4000),
            "source": clip(f.get("source"), 120),
            "kind": "",
            "rule": "",
            "when": clip(f.get("when"), 40),
        })

    duration = obj.get("durationSeconds")
    return {
        "schema": SCHEMA,
        "checkId": check_id,
        "binding": None,
        "verdict": obj["verdict"],       # legacy score verdict: evidence kinds do not exist to recompute it
        "clientOutcome": obj["verdict"],
        "score": score,
        "coverage": None, "assurance": None, "reasons": [], "consent": None, "rules": None,
        "startedAt": clip(obj.get("startedAt"), 40),
        "finishedAt": clip(obj.get("finishedAt"), 40),
        "durationSeconds": duration if isinstance(duration, int) and not isinstance(duration, bool) else None,
        "signatureVersion": clip(obj.get("signatureVersion"), 40),
        "signatureOrigin": clip(obj.get("signatureOrigin"), 80),
        "environment": {
            "hostname": clip(env.get("hostname"), 100),
            "os": clip(env.get("os"), 100),
            "user": clip(env.get("user"), 100),
            "elevated": env.get("elevated") is True,
            "appVersion": clip(env.get("appVersion"), 20),
            "selfHash": clip(env.get("selfHash"), 16),
            "jvm": clip(env.get("jvm"), 100),
        },
        "modules": {clip(k, 40): (v if _one_of(v, MODULE_STATES) else "ERROR") for k, v in modules.items()},
        "findings": clean_findings,
    }


def _str_list(value, limit, item_len, what):
    if not isinstance(value, list) or len(value) > limit or not all(isinstance(x, str) for x in value):
        _bad(f"{what} must be a list of strings.")
    return [clip(x, item_len) for x in value]


def _validate_v2(obj):
    bad = _bad
    session = obj.get("session")
    collector = obj.get("collector")
    env = obj.get("environment")
    consent = obj.get("consent")
    evidence = obj.get("evidence")
    coverage = obj.get("coverage")
    assurance = obj.get("assurance")
    verdict = obj.get("verdict")
    for name, value in (("session", session), ("collector", collector), ("environment", env), ("consent", consent),
                        ("coverage", coverage), ("assurance", assurance), ("verdict", verdict)):
        if not isinstance(value, dict):
            bad(f"Missing {name} section.")

    check_id = session.get("checkId")
    if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
        bad("Bad checkId.")
    duration = session.get("durationSeconds")
    binding = _binding(session.get("binding"))

    if not isinstance(evidence, list):
        bad("Missing evidence list.")
    if len(evidence) > settings.MOON_MAX_FINDINGS:
        bad("Too many evidence items.")
    items = []
    for i, e in enumerate(evidence):
        if (not isinstance(e, dict) or e.get("id") != f"E{i + 1}" or not _one_of(e.get("kind"), policy.KINDS)
                or not _one_of(e.get("severity"), SEVERITIES) or not isinstance(e.get("title"), str)):
            bad(f"Evidence item #{i + 1} is malformed.")
        items.append({
            "idx": i,
            "kind": e["kind"],
            "rule": clip(e.get("rule"), 100),
            "severity": e["severity"],
            "category": clip(e.get("category"), 24),
            "module": clip(e.get("module"), 40),
            "title": clip(e.get("title"), 300),
            "detail": clip(e.get("detail"), 4000),
            "evidence": clip(e.get("evidence"), 4000),
            "source": clip(e.get("source"), 120),
            "when": clip(e.get("when"), 40),
        })

    modules = coverage.get("modules")
    if not isinstance(modules, dict) or len(modules) > 200:
        bad("Bad coverage.modules.")
    errors = coverage.get("errors") if isinstance(coverage.get("errors"), dict) else {}
    if len(errors) > 200:
        bad("Too many collection errors.")
    client_required = _str_list(coverage.get("required", []), 200, 40, "coverage.required")
    # the server decides what is required: a client that leaves a collector out of its own list
    # cannot turn that collector's failure into "no evidence"
    expected = policy.EXPECTED_REQUIRED.get(policy.platform_family(clip(env.get("os"), 100)), set())
    cov = {
        "modules": {clip(k, 40): (v if _one_of(v, MODULE_STATES) else "ERROR") for k, v in modules.items()},
        "required": sorted(set(client_required) | expected),
        "clientRequired": client_required,
        "errors": {clip(k, 40): clip(v, 300) for k, v in errors.items()},
        "elevated": coverage.get("elevated") is True,
        "platformSupported": coverage.get("platformSupported") is True,
        "platformNote": clip(coverage.get("platformNote"), 200),
    }
    rules_count = collector.get("rulesCount")
    rules = {
        "origin": clip(collector.get("rulesOrigin"), 40),
        "digest": clip(collector.get("rulesDigest"), 64),
        "count": rules_count if isinstance(rules_count, int) and not isinstance(rules_count, bool) else 0,
        "note": clip(collector.get("rulesNote"), 300),
    }
    cov["rulesOk"] = policy.rules_ok(rules)
    cov["complete"] = policy.coverage_complete(cov)
    cov["missing"] = sorted(m for m in cov["required"] if cov["modules"].get(m) != "OK")

    level = assurance.get("level")
    if not _one_of(level, ("STANDARD", "REDUCED", "LOW")):
        bad("Bad assurance level.")
    notes = assurance.get("reasons", [])
    if not isinstance(notes, list) or len(notes) > 200:
        bad("Bad assurance reasons.")
    assur = {"level": level, "reasons": [{"code": clip(n.get("code"), 100), "text": clip(n.get("text"), 400)}
                                         for n in notes if isinstance(n, dict)]}

    outcome = verdict.get("outcome")
    if not _one_of(outcome, policy.OUTCOMES):
        bad("Unknown verdict outcome.")
    raw_reasons = verdict.get("reasons", [])
    if not isinstance(raw_reasons, list) or len(raw_reasons) > 500:
        bad("Bad verdict reasons.")
    valid_ids = {f"E{i + 1}" for i in range(len(items))}
    reasons = []
    for r in raw_reasons:
        if not isinstance(r, dict):
            bad("Bad verdict reason.")
        refs = _str_list(r.get("evidence", []), 5000, 12, "verdict.reasons.evidence")
        if any(ref not in valid_ids for ref in refs):
            bad("Verdict reason cites evidence that is not in the report.")
        reasons.append({"code": clip(r.get("code"), 100), "text": clip(r.get("text"), 2000), "evidence": refs})

    channel = consent.get("channel")
    return {
        "schema": SCHEMA_V2,
        "checkId": check_id,
        "binding": binding,
        # the outcome shown to admins is recomputed here from the evidence and the server's own
        # coverage decision; the checker's statement is kept only for comparison
        "verdict": policy.expected_outcome(items, cov),
        "clientOutcome": outcome,
        "score": None,
        "startedAt": clip(session.get("startedAt"), 40),
        "finishedAt": clip(session.get("finishedAt"), 40),
        "durationSeconds": duration if isinstance(duration, int) and not isinstance(duration, bool) else None,
        "signatureVersion": clip(collector.get("rulesVersion"), 40),
        "signatureOrigin": clip(collector.get("rulesOrigin"), 80),
        "environment": {
            "hostname": clip(env.get("hostname"), 100),
            "os": clip(env.get("os"), 100),
            "user": clip(env.get("user"), 100),
            "elevated": env.get("elevated") is True,
            "appVersion": clip(collector.get("appVersion"), 20),
            "selfHash": clip(collector.get("selfHash"), 16),
            "jvm": clip(collector.get("jvm"), 100),
        },
        "modules": cov["modules"],
        "findings": items,
        "coverage": cov,
        "rules": rules,
        "assurance": assur,
        "reasons": reasons,
        "consent": {
            "textVersion": clip(consent.get("textVersion"), 20),
            "acceptedAt": clip(consent.get("acceptedAt"), 40),
            "channel": channel if _one_of(channel, ("gui", "cli", "none")) else "none",
        },
    }


def _binding(value):
    """session.binding of a protocol-3 report: which check it was made for and the single-use value."""
    if value is None:
        return None
    if not isinstance(value, dict):
        _bad("Bad session binding.")
    sid, nonce, protocol = value.get("panelSessionId"), value.get("uploadNonce"), value.get("protocol")
    if (not isinstance(sid, str) or not _UUID.fullmatch(sid) or not isinstance(nonce, str)
            or not _NONCE.fullmatch(nonce) or isinstance(protocol, bool) or not isinstance(protocol, int)):
        _bad("Bad session binding.")
    return {"panelSessionId": sid, "uploadNonce": nonce, "protocol": protocol}


def gzip_bytes(raw):
    return gzip.compress(raw, compresslevel=6)

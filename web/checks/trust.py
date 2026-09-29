"""
What the server can and cannot say about a delivered report.

The checker runs on a machine the player controls, so every value in the report — the
findings, the build hash, the host name, "ran as administrator", "completed" — is the
player's PC speaking. The panel keeps five questions apart and never lets one answer
stand in for another (docs/report-assurance.md):

  session      was it delivered for this check? (token + single-use upload value: checked)
  consistency  does the report agree with itself, the session and the server's clock? (checked)
  artifact     which checker build does it claim to be? (a claim: compared, not verified)
  collector    did an unmodified official checker really run and see the whole PC? (not verifiable here)
  device       what the checker says about the PC: rights, platform (self-reported)

``trust`` on the session is the worst level among the checks the server performed; "ok" means
those checks found nothing, never that the collection is trustworthy.
"""
from datetime import datetime

from django.utils.translation import gettext, gettext_noop

from core.models import SiteSettings

from . import policy
from .ingest import version_tuple
from .models import TrustedBuild

OK, INFO, WARN, BAD = "ok", "info", "warn", "bad"
SESSION, CONSISTENCY, ARTIFACT, COLLECTOR, DEVICE = "session", "consistency", "artifact", "collector", "device"
DIMENSIONS = (SESSION, CONSISTENCY, ARTIFACT, COLLECTOR, DEVICE)
_RANK = {OK: 0, INFO: 0, WARN: 1, BAD: 2}
_EXECUTION = gettext_noop(
    "Not independently verified: nothing the panel receives proves that an unmodified official checker ran "
    "or that it saw the whole PC. Findings, coverage and device facts are what the player's PC reported.")
_UNBOUND = gettext_noop(
    "Delivered with this check's session token, but this checker is too old to bind its report to the "
    "check: an unmodified report from another check could have been resubmitted.")


def _parse_instant(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def evaluate(session, report, now):
    """Returns (flags, level). ``report`` is the output of ingest.validate_report after the binding checks."""
    site = SiteSettings.load()
    flags = []

    def add(dim, level, key, msg, **params):
        # stored with the untranslated message and its parameters: shown in each member's language
        flags.append({"dim": dim, "level": level, "key": key, "msg": msg, "params": params, "text": msg % params})

    client = session.client or {}
    env = report["environment"]
    full_hash = client.get("selfHashFull", "")

    # --- session: checked by the server -------------------------------------------------
    if report.get("binding") is not None:
        add(SESSION, OK, "bound", gettext_noop(
            "Delivered with this check's session token and bound to it by a single-use upload value, now "
            "consumed. This shows the report was made (or edited) for this check after the code was entered."))
    else:
        add(SESSION, WARN, "unbound", _UNBOUND)

    # --- artifact: a claim, compared with the registered builds ---------------------------
    trusted = TrustedBuild.objects.filter(sha256=full_hash).first() if full_hash else None
    if trusted is not None:
        add(ARTIFACT, INFO, "build", gettext_noop(
            "The checker says it is the official build %(label)s. This file hash is sent by the player's PC; "
            "the panel cannot verify which program actually ran."), label=trusted.label)
    elif not TrustedBuild.objects.exists():
        add(ARTIFACT, WARN, "build", gettext_noop(
            "No official builds are registered, so the checker's claimed file hash was not compared with anything."))
    else:
        add(ARTIFACT, BAD, "build", gettext_noop(
            "The checker's claimed file hash (%(hash)s…) is not a registered official build: an outdated or "
            "modified copy."), hash=full_hash[:16] or "—")

    # --- collector: stated plainly on every report -----------------------------------------
    add(COLLECTOR, INFO, "execution", _EXECUTION)
    if report["verdict"] == "NO_EVIDENCE":
        add(COLLECTOR, INFO, "no-evidence", gettext_noop(
            "No evidence was reported. That is the report's content, not proof that the PC was inspected."))

    # --- device: self-reported --------------------------------------------------------------
    if env["elevated"]:
        add(DEVICE, INFO, "elevated", gettext_noop("The checker reports it ran with administrator rights."))
    else:
        add(DEVICE, WARN, "elevated", gettext_noop(
            "The checker reports it ran WITHOUT administrator rights — deep checks were skipped."))
    if "windows" not in env["os"].lower():
        add(DEVICE, INFO, "platform", gettext_noop("Checked on %(os)s; Windows-only modules were skipped."),
            os=env["os"] or "?")
    if version_tuple(env["appVersion"]) < version_tuple(site.min_checker_version):
        add(DEVICE, WARN, "version", gettext_noop("Checker %(got)s is older than the required %(min)s."),
            got=env["appVersion"], min=site.min_checker_version)

    # --- consistency: checked by the server ---------------------------------------------------
    coverage = report.get("coverage")
    if coverage is not None:
        missing = coverage.get("missing", [])
        if missing:
            add(CONSISTENCY, WARN, "modules", gettext_noop(
                "Required collectors that did not complete: %(list)s. Finding nothing there means nothing."),
                list=", ".join(f"{m} ({coverage['modules'].get(m, '?')})" for m in missing))
        else:
            add(CONSISTENCY, INFO, "modules", gettext_noop(
                "All %(n)s required collectors report that they completed (their own statement)."),
                n=len(coverage.get("required", [])))
    else:
        failed = sorted(k for k, v in report["modules"].items() if v in ("ERROR", "TIMEOUT", "PARTIAL"))
        if failed:
            add(CONSISTENCY, WARN, "modules", gettext_noop("Modules that did not finish: %(list)s."),
                list=", ".join(failed))

    start = session.scan_started_at or session.claimed_at
    if start is not None:
        measured = max(0, int((now - start).total_seconds()))
        if measured < site.fast_scan_seconds:
            add(CONSISTENCY, WARN, "fast", gettext_noop(
                "Scan finished %(s)ss after it started (server clock) — unusually fast."), s=measured)
        claimed = report["durationSeconds"]
        if claimed is not None and claimed - measured > 90:
            add(CONSISTENCY, BAD, "duration", gettext_noop(
                "Checker claims a %(claimed)ss scan but the server saw only %(measured)ss."),
                claimed=claimed, measured=measured)

    finished = _parse_instant(report["finishedAt"])
    if finished is not None and finished.tzinfo is not None:
        skew = abs((now - finished).total_seconds())
        if skew > 300:
            add(CONSISTENCY, WARN, "clock", gettext_noop("PC clock differs from the server by %(min)s min."),
                min=int(skew // 60))

    if session.claimed_ip and session.report_ip and session.claimed_ip != session.report_ip:
        add(CONSISTENCY, WARN, "ip", gettext_noop(
            "Report uploaded from %(upload)s, but the code was entered from %(claim)s."),
            upload=session.report_ip, claim=session.claimed_ip)

    if session.interruptions:
        add(CONSISTENCY, WARN, "interrupted", gettext_noop(
            "The checker stopped reporting %(n)s time(s) during the scan."), n=session.interruptions)

    if coverage is not None:
        if report["clientOutcome"] != report["verdict"]:
            add(CONSISTENCY, BAD, "verdict", gettext_noop(
                "The checker stated %(got)s, but its own evidence and coverage imply %(expected)s — produced or "
                "edited outside the official policy. The panel shows %(expected)s."),
                got=report["clientOutcome"], expected=report["verdict"])
        else:
            add(CONSISTENCY, OK, "verdict", gettext_noop(
                "The panel recomputed the outcome from the evidence and coverage; it matches the checker's."))
        shrunk = policy.missing_required(coverage, env["os"])
        if shrunk:
            add(CONSISTENCY, BAD, "required", gettext_noop(
                "The checker left required collectors out of its coverage list: %(list)s. The panel counts them "
                "as required."), list=", ".join(sorted(shrunk)))
        rules = report.get("rules") or {}
        if not policy.rules_ok(rules):
            add(CONSISTENCY, BAD, "rules", gettext_noop(
                "Detection rules did not come from the build or a signed update (origin '%(origin)s', %(count)s "
                "rules)."), origin=rules.get("origin") or "unknown", count=rules.get("count", 0))
        elif rules.get("note"):
            add(CONSISTENCY, WARN, "rules", gettext_noop("A rule file was placed next to the checker: %(note)s."),
                note=rules["note"])
        consent = report.get("consent") or {}
        if consent.get("channel") == "none" or not consent.get("acceptedAt"):
            add(CONSISTENCY, WARN, "consent", gettext_noop("No player consent was recorded in the report."))
    else:
        add(CONSISTENCY, INFO, "schema", gettext_noop(
            "Legacy report format (checker older than 1.1): no coverage, assurance or consent sections; the verdict "
            "is the old weighted score and could not be recomputed."))

    return flags, worst(flags)


# Signals stored before 1.3 (no "dim"): the ones that presented a claim as verified are shown with
# today's wording, so an old check no longer reads "Official checker build" / all green.
_LEGACY = {
    "build": (ARTIFACT, {OK: (INFO, gettext_noop(
        "The checker says it is the official build %(label)s. This file hash is sent by the player's PC; "
        "the panel cannot verify which program actually ran."))}),
    "elevated": (DEVICE, {OK: (INFO, gettext_noop("The checker reports it ran with administrator rights."))}),
    "platform": (DEVICE, {}),
    "version": (DEVICE, {}),
    "binary": (CONSISTENCY, {}), "identity": (CONSISTENCY, {}), "replay": (CONSISTENCY, {}),
}


def upgrade(flag):
    """A stored signal in the current shape (dimension, honest level)."""
    if flag.get("dim") in DIMENSIONS:
        return flag
    f = dict(flag)
    dim, relabel = _LEGACY.get(f.get("key"), (CONSISTENCY, {}))
    f["dim"] = dim
    if f.get("level") in relabel:
        f["level"], f["msg"] = relabel[f["level"]]
        f["text"] = f["msg"] % (f.get("params") or {"label": "?"}) if "%(" in f["msg"] else f["msg"]
    return f


def by_dimension(flags):
    """Stored flags grouped for display, old ones upgraded; every report states the collector question."""
    groups = {d: [] for d in DIMENSIONS}
    for f in flags or []:
        f = upgrade(f)
        groups[f["dim"]].append(f)
    if not groups[COLLECTOR]:
        groups[COLLECTOR].append({"dim": COLLECTOR, "level": INFO, "key": "execution", "params": {},
                                  "msg": _EXECUTION, "text": _EXECUTION})
    if not groups[SESSION]:
        groups[SESSION].append({"dim": SESSION, "level": WARN, "key": "unbound", "params": {},
                                "msg": _UNBOUND, "text": _UNBOUND})
    return groups


def worst(flags):
    return (OK, WARN, BAD)[max((_RANK.get(f.get("level"), 0) for f in flags), default=0)]


def flag_text(flag):
    """A stored signal in the current language (signals stored before 1.2 keep their English text)."""
    msg = flag.get("msg")
    if not msg:
        return gettext(flag.get("text", ""))  # parameterless messages stored before 1.2 still translate
    try:
        return gettext(msg) % (flag.get("params") or {})
    except (KeyError, TypeError, ValueError):
        return flag.get("text", "")

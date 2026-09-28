"""
Server-side trust signals for a completed check.

The checker runs on a machine the player controls, so the report alone can
never prove a PC is clean. What the server *can* do is cross-check the report
against things the player cannot easily fake at the same time: its own clock,
the connection metadata, the build hash sent at connect time and the history
of previous reports. Each signal is shown to the admin with a level.
"""
from datetime import datetime

from django.utils.translation import gettext, gettext_noop

from core.models import SiteSettings

from . import policy
from .ingest import version_tuple
from .models import CheckSession, TrustedBuild

OK, INFO, WARN, BAD = "ok", "info", "warn", "bad"


def _parse_instant(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def evaluate(session, report, now):
    """Returns (flags, overall_level). ``report`` is the output of ingest.validate_report."""
    site = SiteSettings.load()
    flags = []

    def add(level, key, msg, **params):
        # stored with the untranslated message and its parameters: shown in each member's language
        flags.append({"level": level, "key": key, "msg": msg, "params": params, "text": msg % params})

    client = session.client or {}
    env = report["environment"]
    full_hash = client.get("selfHashFull", "")

    # 1. is this an official build?
    trusted = TrustedBuild.objects.filter(sha256=full_hash).first() if full_hash else None
    if trusted is not None:
        add(OK, "build", gettext_noop("Official checker build: %(label)s."), label=trusted.label)
    elif not TrustedBuild.objects.exists():
        add(WARN, "build", gettext_noop("No trusted builds are configured, so the checker file was not verified."))
    else:
        add(BAD, "build", gettext_noop("Unknown checker build (sha256 %(hash)s…). The player may be running a "
                                       "modified or outdated checker."), hash=full_hash[:16] or "—")

    # 2. the binary that uploaded is the binary that connected
    if env["selfHash"] and full_hash and not full_hash.startswith(env["selfHash"].lower()):
        add(BAD, "binary", gettext_noop("The report was produced by a different program file than the one that "
                                        "connected. It may be forged: ask the player to run the check again while "
                                        "you watch."))

    # 3. same PC / user as at connect time
    if (client.get("hostname"), client.get("user")) != (env["hostname"], env["user"]):
        add(BAD, "identity", gettext_noop("PC/user changed between connect (%(before)s) and upload (%(after)s)."),
            before=f"{client.get('hostname')}/{client.get('user')}", after=f"{env['hostname']}/{env['user']}")

    # 4. administrator rights
    if env["elevated"]:
        add(OK, "elevated", gettext_noop("Checker ran with administrator rights."))
    else:
        add(BAD, "elevated", gettext_noop("Checker was NOT running as administrator — deep checks were skipped."))

    # 5. module completeness
    coverage = report.get("coverage")
    if coverage is not None:
        missing = coverage.get("missing", [])
        if missing:
            add(WARN, "modules", gettext_noop("Required collectors that did not complete: %(list)s. Finding "
                                              "nothing there means nothing."),
                list=", ".join(f"{m} ({coverage['modules'].get(m, '?')})" for m in missing))
        else:
            add(OK, "modules", gettext_noop("All %(n)s required collectors completed."),
                n=len(coverage.get("required", [])))
    else:
        failed = sorted(k for k, v in report["modules"].items() if v in ("ERROR", "TIMEOUT"))
        if failed:
            add(WARN, "modules", gettext_noop("Modules that did not finish: %(list)s."), list=", ".join(failed))
        else:
            add(OK, "modules", gettext_noop("All modules finished."))

    # 6. timing, measured with the server's own clock
    start = session.scan_started_at or session.claimed_at
    if start is not None:
        measured = max(0, int((now - start).total_seconds()))
        if measured < site.fast_scan_seconds:
            add(WARN, "fast", gettext_noop("Scan finished %(s)ss after it started (server clock) — unusually fast."),
                s=measured)
        claimed = report["durationSeconds"]
        if claimed is not None and claimed - measured > 90:
            add(BAD, "duration", gettext_noop("Checker claims a %(claimed)ss scan but the server saw only "
                                              "%(measured)ss."), claimed=claimed, measured=measured)

    # 7. PC clock
    finished = _parse_instant(report["finishedAt"])
    if finished is not None and finished.tzinfo is not None:
        skew = abs((now - finished).total_seconds())
        if skew > 300:
            add(WARN, "clock", gettext_noop("PC clock differs from the server by %(min)s min."), min=int(skew // 60))

    # 8. network path
    if session.claimed_ip and session.report_ip and session.claimed_ip != session.report_ip:
        add(WARN, "ip", gettext_noop("Report uploaded from %(upload)s, but the code was entered from %(claim)s."),
            upload=session.report_ip, claim=session.claimed_ip)

    # 9. replayed report
    if CheckSession.objects.filter(client_check_id=report["checkId"]).exclude(pk=session.pk).exists():
        add(BAD, "replay", gettext_noop("Report id %(id)s was already submitted in another check."),
            id=report["checkId"])

    # 10. connection drops
    if session.interruptions:
        add(WARN, "interrupted", gettext_noop("The checker stopped reporting %(n)s time(s) during the scan."),
            n=session.interruptions)

    # 11. the outcome must follow from the evidence and coverage (v2 reports)
    if report.get("coverage") is not None:
        expected = policy.expected_outcome(report["findings"], report["coverage"])
        if expected != report["verdict"]:
            add(BAD, "verdict", gettext_noop("The checker reported %(got)s but its own evidence and coverage imply "
                                             "%(expected)s — produced or edited outside the official policy."),
                got=report["verdict"], expected=expected)
        shrunk = policy.missing_required(report["coverage"], env["os"])
        if shrunk:
            add(BAD, "required", gettext_noop("The checker left required collectors out of its coverage list: "
                                              "%(list)s."), list=", ".join(sorted(shrunk)))
        rules = report.get("rules") or {}
        if not policy.rules_ok(rules):
            add(BAD, "rules", gettext_noop("Detection rules did not come from the build or a signed update "
                                           "(origin '%(origin)s', %(count)s rules)."),
                origin=rules.get("origin") or "unknown", count=rules.get("count", 0))
        elif rules.get("note"):
            add(WARN, "rules", gettext_noop("A rule file was placed next to the checker: %(note)s."),
                note=rules["note"])
        consent = report.get("consent") or {}
        if consent.get("channel") == "none" or not consent.get("acceptedAt"):
            add(WARN, "consent", gettext_noop("No player consent was recorded in the report."))
    else:
        add(INFO, "schema", gettext_noop("Legacy report format (checker older than 1.1): no coverage, assurance or "
                                         "consent sections; the verdict is the old weighted score."))

    # 12. versions / platform
    if version_tuple(env["appVersion"]) < version_tuple(site.min_checker_version):
        add(WARN, "version", gettext_noop("Checker %(got)s is older than the required %(min)s."),
            got=env["appVersion"], min=site.min_checker_version)
    if "windows" not in env["os"].lower():
        add(INFO, "platform", gettext_noop("Checked on %(os)s; Windows-only modules were skipped."),
            os=env["os"] or "?")

    levels = {f["level"] for f in flags}
    overall = BAD if BAD in levels else WARN if WARN in levels else OK
    return flags, overall


def flag_text(flag):
    """A stored signal in the current language (signals stored before 1.2 keep their English text)."""
    msg = flag.get("msg")
    if not msg:
        return gettext(flag.get("text", ""))  # parameterless messages stored before 1.2 still translate
    try:
        return gettext(msg) % (flag.get("params") or {})
    except (KeyError, TypeError, ValueError):
        return flag.get("text", "")

"""
Server-side trust signals for a completed check.

The checker runs on a machine the player controls, so the report alone can
never prove a PC is clean. What the server *can* do is cross-check the report
against things the player cannot easily fake at the same time: its own clock,
the connection metadata, the build hash sent at connect time and the history
of previous reports. Each signal is shown to the admin with a level.
"""
from datetime import datetime

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

    def add(level, key, text):
        flags.append({"level": level, "key": key, "text": text})

    client = session.client or {}
    env = report["environment"]
    full_hash = client.get("selfHashFull", "")

    # 1. is this an official build?
    trusted = TrustedBuild.objects.filter(sha256=full_hash).first() if full_hash else None
    if trusted is not None:
        add(OK, "build", f"Official checker build: {trusted.label}.")
    elif not TrustedBuild.objects.exists():
        add(WARN, "build", "No trusted builds are configured, so the checker file was not verified.")
    else:
        add(BAD, "build", f"Unknown checker build (sha256 {full_hash[:16] or 'missing'}…). "
                          "The player may be running a modified or outdated checker.")

    # 2. the binary that uploaded is the binary that connected
    if env["selfHash"] and full_hash and not full_hash.startswith(env["selfHash"].lower()):
        add(BAD, "binary", "The report was produced by a different program file than the one that connected.")

    # 3. same PC / user as at connect time
    if (client.get("hostname"), client.get("user")) != (env["hostname"], env["user"]):
        add(BAD, "identity", f"PC/user changed between connect ({client.get('hostname')}/{client.get('user')}) "
                             f"and upload ({env['hostname']}/{env['user']}).")

    # 4. administrator rights
    if env["elevated"]:
        add(OK, "elevated", "Checker ran with administrator rights.")
    else:
        add(BAD, "elevated", "Checker was NOT running as administrator — deep checks were skipped.")

    # 5. module completeness
    failed = sorted(k for k, v in report["modules"].items() if v in ("ERROR", "TIMEOUT"))
    if failed:
        add(WARN, "modules", "Modules that did not finish: " + ", ".join(failed) + ".")
    else:
        add(OK, "modules", "All modules finished.")

    # 6. timing, measured with the server's own clock
    start = session.scan_started_at or session.claimed_at
    if start is not None:
        measured = max(0, int((now - start).total_seconds()))
        if measured < site.fast_scan_seconds:
            add(WARN, "fast", f"Scan finished {measured}s after it started (server clock) — unusually fast.")
        claimed = report["durationSeconds"]
        if claimed is not None and claimed - measured > 90:
            add(BAD, "duration", f"Checker claims a {claimed}s scan but the server saw only {measured}s.")

    # 7. PC clock
    finished = _parse_instant(report["finishedAt"])
    if finished is not None and finished.tzinfo is not None:
        skew = abs((now - finished).total_seconds())
        if skew > 300:
            add(WARN, "clock", f"PC clock differs from the server by {int(skew // 60)} min.")

    # 8. network path
    if session.claimed_ip and session.report_ip and session.claimed_ip != session.report_ip:
        add(WARN, "ip", f"Report uploaded from {session.report_ip}, but the code was entered from "
                        f"{session.claimed_ip}.")

    # 9. replayed report
    if CheckSession.objects.filter(client_check_id=report["checkId"]).exclude(pk=session.pk).exists():
        add(BAD, "replay", f"Report id {report['checkId']} was already submitted in another check.")

    # 10. connection drops
    if session.interruptions:
        add(WARN, "interrupted", f"The checker stopped reporting {session.interruptions} time(s) during the scan.")

    # 11. the outcome must follow from the evidence and coverage (v2 reports)
    if report.get("coverage") is not None:
        expected = policy.expected_outcome(report["findings"], report["coverage"])
        if expected != report["verdict"]:
            add(BAD, "verdict", f"The checker reported {report['verdict']} but its own evidence and coverage "
                                f"imply {expected} — produced or edited outside the official policy.")
        shrunk = policy.missing_required(report["coverage"], env["os"])
        if shrunk:
            add(BAD, "required", "The checker left required collectors out of its coverage list: "
                                 + ", ".join(sorted(shrunk)) + ".")
        consent = report.get("consent") or {}
        if consent.get("channel") == "none" or not consent.get("acceptedAt"):
            add(WARN, "consent", "No player consent was recorded in the report.")
    else:
        add(INFO, "schema", "Legacy report format (checker older than 1.1): no coverage, assurance or "
                            "consent sections; the verdict is the old weighted score.")

    # 12. versions / platform
    if version_tuple(env["appVersion"]) < version_tuple(site.min_checker_version):
        add(WARN, "version", f"Checker {env['appVersion']} is older than the required {site.min_checker_version}.")
    if "windows" not in env["os"].lower():
        add(INFO, "platform", f"Checked on {env['os'] or 'an unknown OS'}; Windows-only modules were skipped.")

    levels = {f["level"] for f in flags}
    overall = BAD if BAD in levels else WARN if WARN in levels else OK
    return flags, overall

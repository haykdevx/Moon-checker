"""
Server-side copy of the checker's verdict policy (ru.moon.checker.core.VerdictEngine).

The client states an outcome, but the client runs on the player's PC, so the
panel recomputes it from the evidence kinds and the coverage the same report
carries. A disagreement means the report was produced or edited by something
other than the official policy and is flagged red.
"""

OUTCOMES = ("VALIDATED_DETECTION", "REVIEW_REQUIRED", "UNSUPPORTED_CONFIGURATION", "INCOMPLETE_SCAN", "NO_EVIDENCE")
LEGACY_VERDICTS = ("CLEAN", "SUSPICIOUS", "CHEAT", "INCONCLUSIVE")
KINDS = ("DETECTION", "INDICATOR", "CONCEALMENT", "CONFIGURATION", "CONTEXT")
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Collectors a checker >= 1.1 must list as required on each platform. A client
# that quietly drops one from its own "required" list could turn a failed
# collector into "no evidence"; the panel does not let it.
EXPECTED_REQUIRED = {
    "windows": {"cs2", "files", "deleted", "execution", "amcache", "persistence", "kernel", "environment",
                "antiforensic"},
    "linux": {"cs2", "linuxproc", "linuxfiles", "kernel", "linuxpersist"},
}


def platform_family(os_name):
    name = (os_name or "").lower()
    if "windows" in name:
        return "windows"
    if "linux" in name:
        return "linux"
    return None


TRUSTED_RULE_ORIGINS = ("bundled", "signed-override")


def rules_ok(rules):
    """Decided by the server from what the report says about its rules, not from the client's own flag."""
    return bool(rules) and rules.get("origin") in TRUSTED_RULE_ORIGINS and (rules.get("count") or 0) > 0


def coverage_complete(coverage):
    modules = coverage.get("modules", {})
    return (coverage.get("elevated") is True and coverage.get("platformSupported") is True
            and coverage.get("rulesOk") is True
            and all(modules.get(m) == "OK" for m in coverage.get("required", [])))


def expected_outcome(evidence, coverage):
    """Recomputes the outcome exactly as VerdictEngine does."""
    kinds = [(e["kind"], SEVERITY_RANK.get(e["severity"], 0)) for e in evidence]
    if any(k == "DETECTION" for k, _ in kinds):
        return "VALIDATED_DETECTION"
    if any(k in ("INDICATOR", "CONCEALMENT") and rank >= SEVERITY_RANK["MEDIUM"] for k, rank in kinds):
        return "REVIEW_REQUIRED"
    if coverage.get("platformSupported") is not True:
        return "UNSUPPORTED_CONFIGURATION"
    if not coverage_complete(coverage):
        return "INCOMPLETE_SCAN"
    return "NO_EVIDENCE"


def missing_required(coverage, os_name):
    """Expected-required collectors the client left out of its own required list."""
    family = platform_family(os_name)
    if family is None:
        return set()
    return EXPECTED_REQUIRED[family] - set(coverage.get("clientRequired", coverage.get("required", [])))

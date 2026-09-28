package ru.moon.checker.core;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The complete outcome of a scan: the evidence, and — kept apart from it — the
 * assessment (verdict, coverage, assurance) derived from that evidence.
 *
 * @param checkId          the run identifier shown on screen
 * @param env              machine metadata
 * @param assessment       verdict + reasons, coverage and assurance
 * @param findings         all findings, most severe first; evidence id = index + 1
 * @param moduleStatus     per-module completion status
 * @param signatureVersion signature DB version used
 * @param rules            where the detection rules came from, their digest and count
 * @param consent          the player's recorded consent
 * @param finishedAt       when the scan completed
 * @param duration         wall-clock scan time
 */
public record ScanResult(
        CheckId checkId,
        EnvironmentInfo env,
        Assessment assessment,
        List<Finding> findings,
        Map<String, ModuleStatus> moduleStatus,
        String signatureVersion,
        RulesProvenance rules,
        Consent consent,
        Instant finishedAt,
        Duration duration
) {
    /** Short provenance label for displays ("bundled", "signed-override", "none"). */
    public String signatureOrigin() {
        return rules.origin();
    }

    public Verdict verdict() {
        return assessment.outcome();
    }

    public Coverage coverage() {
        return assessment.coverage();
    }

    public long countBySeverity(Severity s) {
        return findings.stream().filter(f -> f.severity() == s).count();
    }

    public long countByKind(EvidenceKind k) {
        return findings.stream().filter(f -> f.kind() == k).count();
    }
}

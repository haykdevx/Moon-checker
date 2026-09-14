package ru.moon.checker.core;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The complete outcome of a scan.
 *
 * @param checkId          the run identifier shown on screen
 * @param env              machine metadata
 * @param verdict          overall verdict
 * @param score            0-100 aggregate suspicion score
 * @param findings         all findings, sorted most-severe first
 * @param moduleStatus     per-module completion status
 * @param signatureVersion signature DB version used
 * @param signatureOrigin  where signatures came from (bundled/external)
 * @param finishedAt       when the scan completed
 * @param duration         wall-clock scan time
 */
public record ScanResult(
        CheckId checkId,
        EnvironmentInfo env,
        Verdict verdict,
        int score,
        List<Finding> findings,
        Map<String, ModuleStatus> moduleStatus,
        String signatureVersion,
        String signatureOrigin,
        Instant finishedAt,
        Duration duration
) {
    public long countBySeverity(Severity s) {
        return findings.stream().filter(f -> f.severity() == s).count();
    }
}

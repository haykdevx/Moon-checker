package ru.moon.checker.core;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static ru.moon.checker.core.TestResults.ENV;
import static ru.moon.checker.core.TestResults.complete;
import static ru.moon.checker.core.TestResults.finding;

/** Each test pins one rule of the verdict policy (see VerdictEngine). */
class VerdictEngineTest {

    private static Assessment assess(List<Finding> fs, Coverage c) {
        return VerdictEngine.assess(fs, c, ENV);
    }

    @Test
    void nothingFoundWithFullCoverageIsNoEvidenceAndSaysItIsNotProof() {
        Assessment a = assess(List.of(), complete("files", "execution"));
        assertEquals(Verdict.NO_EVIDENCE, a.outcome());
        assertTrue(a.reasons().get(0).text().contains("not proof"), a.reasons().toString());
        assertEquals(Assurance.Level.STANDARD, a.assurance().level());
    }

    @Test
    void onlyAnExactHashCanValidate() {
        Finding hash = finding(EvidenceKind.DETECTION, Severity.CRITICAL, "files", "Sample cheat A");
        Finding name = finding(EvidenceKind.INDICATOR, Severity.CRITICAL, "environment", "Sample cheat B");
        assertEquals(Verdict.VALIDATED_DETECTION, assess(List.of(hash), complete("files")).outcome());
        // a CRITICAL name match is still only a reason to review
        assertEquals(Verdict.REVIEW_REQUIRED, assess(List.of(name), complete("files")).outcome());
    }

    @Test
    void correlatedTracesOfOneSubjectAreOneReason() {
        List<Finding> traces = List.of(
                finding(EvidenceKind.INDICATOR, Severity.HIGH, "files", "Sample loader"),
                finding(EvidenceKind.INDICATOR, Severity.HIGH, "execution", "Sample loader"),
                finding(EvidenceKind.INDICATOR, Severity.HIGH, "amcache", "Sample loader"),
                finding(EvidenceKind.INDICATOR, Severity.MEDIUM, "persistence", "Sample loader"));
        Assessment a = assess(traces, complete("files", "execution", "amcache", "persistence"));
        assertEquals(Verdict.REVIEW_REQUIRED, a.outcome(), "four correlated HIGH traces must not add up to more");
        assertEquals(1, a.reasons().size());
        assertEquals(List.of(1, 2, 3, 4), a.reasons().get(0).evidence());
        assertTrue(a.reasons().get(0).text().contains("counted once"), a.reasons().get(0).text());
    }

    @Test
    void securityConfigurationAloneNeverChangesTheVerdict() {
        List<Finding> config = List.of(
                finding(EvidenceKind.CONFIGURATION, Severity.HIGH, "environment", "Test signing"),
                finding(EvidenceKind.CONFIGURATION, Severity.HIGH, "kernel", "Boot integrity weakened"),
                finding(EvidenceKind.CONFIGURATION, Severity.MEDIUM, "environment", "Virtual machine"));
        Assessment a = assess(config, complete("environment", "kernel"));
        assertEquals(Verdict.NO_EVIDENCE, a.outcome());
        assertEquals(Assurance.Level.REDUCED, a.assurance().level(), "configuration lowers trust in the report instead");
        assertEquals(3, a.assurance().reasons().size());
    }

    @Test
    void lowIndicatorsAndContextDoNotAskForReview() {
        List<Finding> fs = List.of(
                finding(EvidenceKind.INDICATOR, Severity.LOW, "peripherals", "Macro software"),
                finding(EvidenceKind.CONTEXT, Severity.HIGH, "steam", "VAC ban on another account"));
        assertEquals(Verdict.NO_EVIDENCE, assess(fs, complete("files")).outcome());
    }

    @Test
    void concealmentAsksForReviewAndIsLabelledSo() {
        Assessment a = assess(List.of(finding(EvidenceKind.CONCEALMENT, Severity.HIGH, "antiforensic", "USN journal reset")),
                complete("antiforensic"));
        assertEquals(Verdict.REVIEW_REQUIRED, a.outcome());
        assertEquals("review.concealment", a.reasons().get(0).code());
    }

    @Test
    void aFailedRequiredCollectorIsNeverNoEvidence() {
        Coverage c = new Coverage(Map.of("files", ModuleStatus.OK, "execution", ModuleStatus.ERROR),
                Set.of("files", "execution"), true, true, "Windows 11", Map.of("execution", "IOException: denied"));
        Assessment a = assess(List.of(), c);
        assertEquals(Verdict.INCOMPLETE_SCAN, a.outcome());
        assertTrue(a.reasons().stream().anyMatch(r -> r.text().contains("execution (ERROR: IOException: denied)")),
                a.reasons().toString());
    }

    @Test
    void aTimedOutOrSkippedRequiredCollectorIsIncomplete() {
        for (ModuleStatus s : List.of(ModuleStatus.TIMEOUT, ModuleStatus.SKIPPED)) {
            Coverage c = new Coverage(Map.of("files", s), Set.of("files"), true, true, "Windows 11", Map.of());
            assertEquals(Verdict.INCOMPLETE_SCAN, assess(List.of(), c).outcome(), s.name());
        }
    }

    @Test
    void optionalCollectorsFailingDoNotBlockTheResult() {
        Coverage c = new Coverage(Map.of("files", ModuleStatus.OK, "browser", ModuleStatus.ERROR),
                Set.of("files"), true, true, "Windows 11", Map.of());
        assertEquals(Verdict.NO_EVIDENCE, assess(List.of(), c).outcome());
    }

    @Test
    void withoutAdminRightsNothingFoundIsIncompleteAndAssuranceLow() {
        Coverage c = new Coverage(Map.of("files", ModuleStatus.OK), Set.of("files"), false, true, "Windows 11", Map.of());
        Assessment a = assess(List.of(), c);
        assertEquals(Verdict.INCOMPLETE_SCAN, a.outcome());
        assertEquals(Assurance.Level.LOW, a.assurance().level());
        assertTrue(a.reasons().stream().anyMatch(r -> r.code().equals("coverage.privileges")));
    }

    @Test
    void unsupportedPlatformIsReportedAsSuchNotAsClean() {
        Coverage c = new Coverage(Map.of("files", ModuleStatus.OK), Set.of("files"), true, false,
                "Windows Server 2022 is not a validated Windows version", Map.of());
        Assessment a = assess(List.of(), c);
        assertEquals(Verdict.UNSUPPORTED_CONFIGURATION, a.outcome());
        assertEquals(Assurance.Level.LOW, a.assurance().level());
    }

    @Test
    void evidenceStillCountsWhenCoverageIsIncompleteAndBothAreStated() {
        Coverage c = new Coverage(Map.of("files", ModuleStatus.OK, "execution", ModuleStatus.TIMEOUT),
                Set.of("files", "execution"), true, true, "Windows 11", Map.of());
        Assessment a = assess(List.of(finding(EvidenceKind.DETECTION, Severity.CRITICAL, "files", "Sample cheat A")), c);
        assertEquals(Verdict.VALIDATED_DETECTION, a.outcome());
        assertTrue(a.reasons().stream().anyMatch(r -> r.code().equals("coverage.missing")),
                "the reviewer must also see that coverage was incomplete");
    }

    @Test
    void unidentifiedBuildReducesAssurance() {
        EnvironmentInfo dev = new EnvironmentInfo("PC", "Windows 11", "u", true, "1.1.0", "dev-run", "jvm");
        Assessment a = VerdictEngine.assess(List.of(), complete("files"), dev);
        assertEquals(Verdict.NO_EVIDENCE, a.outcome());
        assertEquals(Assurance.Level.REDUCED, a.assurance().level());
    }

    @Test
    void defaultKindsNeverClaimADetection() {
        for (Category cat : Category.values()) {
            for (Severity sev : Severity.values()) {
                Finding f = Finding.builder(cat, sev, "t").module("m").build();
                assertNotEquals(EvidenceKind.DETECTION, f.kind(), cat + "/" + sev);
            }
        }
        assertEquals("m:known-cheat-file-hash",
                Finding.builder(Category.FILES, Severity.CRITICAL, "Совпадение / Known cheat file hash")
                        .module("m").build().ruleId());
    }
}

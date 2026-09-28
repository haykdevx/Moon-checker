package ru.moon.checker.core;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Builds {@link ScanResult}s for tests through the real {@link VerdictEngine}. */
public final class TestResults {

    public static final EnvironmentInfo ENV =
            new EnvironmentInfo("PC-1", "Windows 11", "player", true, "1.1.0", "abcdef123456", "Temurin 21");

    private TestResults() {
    }

    /** Coverage where every listed collector is required and finished. */
    public static Coverage complete(String... modules) {
        Map<String, ModuleStatus> status = new LinkedHashMap<>();
        for (String m : modules) {
            status.put(m, ModuleStatus.OK);
        }
        return new Coverage(status, Set.of(modules), true, true, "Windows 11", Map.of());
    }

    public static ScanResult of(List<Finding> findings) {
        return of(findings, complete("files", "execution"), ENV);
    }

    public static ScanResult of(List<Finding> findings, Coverage coverage, EnvironmentInfo env) {
        Assessment a = VerdictEngine.assess(findings, coverage, env);
        return new ScanResult(CheckId.generate(), env, a, List.copyOf(findings), coverage.modules(),
                "test-rules", "bundled", Consent.cli(), Instant.now(), Duration.ofSeconds(42));
    }

    public static Finding finding(EvidenceKind kind, Severity severity, String module, String subject) {
        return Finding.builder(Category.FILES, severity, "title " + subject).module(module)
                .kind(kind).detail(subject).evidence("C:\\sample\\" + subject.replace(' ', '_')).build();
    }
}

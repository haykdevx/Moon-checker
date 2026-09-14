package ru.moon.checker.core;

import org.junit.jupiter.api.Test;
import ru.moon.checker.signatures.SignatureDb;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ScanEngineTest {

    private static CheckModule module(String id, boolean win, Runnable body) {
        return new CheckModule() {
            public String id() { return id; }
            public String displayName() { return id; }
            public Category category() { return Category.FILES; }
            public boolean windowsOnly() { return win; }
            public void run(ScanContext ctx) { body.run(); }
        };
    }

    @Test
    void runsModulesAggregatesAndNotifies() {
        AtomicInteger findings = new AtomicInteger();
        AtomicInteger completed = new AtomicInteger();

        CheckModule emitter = new CheckModule() {
            public String id() { return "emit"; }
            public String displayName() { return "emit"; }
            public Category category() { return Category.FILES; }
            public boolean windowsOnly() { return false; }
            public void run(ScanContext ctx) {
                ctx.emit(Finding.builder(Category.FILES, Severity.CRITICAL, "cheat").module("emit").build());
            }
        };
        CheckModule thrower = module("boom", false, () -> {
            throw new RuntimeException("kaboom");
        });

        ScanListener listener = new ScanListener() {
            public void onFinding(Finding f) { findings.incrementAndGet(); }
            public void onComplete(ScanResult r) { completed.incrementAndGet(); }
        };

        ScanEngine engine = new ScanEngine(List.of(emitter, thrower), listener);
        EnvironmentInfo env = new EnvironmentInfo("PC", "os", "user", true, "1.0.0", "abc", "jvm");
        ScanResult result = engine.run(SignatureDb.empty(), CheckId.generate(), env);

        assertEquals(1, findings.get());
        assertEquals(1, completed.get());
        assertEquals(1, result.findings().size());
        assertEquals(Verdict.CHEAT, result.verdict());
        assertEquals(ModuleStatus.OK, result.moduleStatus().get("emit"));
        assertEquals(ModuleStatus.ERROR, result.moduleStatus().get("boom"));
    }

    @Test
    void hangingModuleIsTimedOutNotFrozen() {
        CheckModule sleeper = module("sleeper", false, () -> {
            try {
                Thread.sleep(30_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });
        CheckModule fast = module("fast", false, () -> {});

        ScanEngine engine = new ScanEngine(List.of(sleeper, fast), ScanListener.NOOP,
                java.time.Duration.ofMillis(300), java.time.Duration.ofSeconds(10));
        long t0 = System.currentTimeMillis();
        EnvironmentInfo env = new EnvironmentInfo("PC", "os", "user", true, "1.0.0", "abc", "jvm");
        ScanResult r = engine.run(SignatureDb.empty(), CheckId.generate(), env);
        long elapsed = System.currentTimeMillis() - t0;

        assertTrue(elapsed < 5_000, "engine must not block on a hung module, took " + elapsed + "ms");
        assertEquals(ModuleStatus.TIMEOUT, r.moduleStatus().get("sleeper"));
        assertEquals(ModuleStatus.OK, r.moduleStatus().get("fast"));
    }

    @Test
    void cleanScanWithoutAdminIsInconclusive() {
        CheckModule noop = module("noop", false, () -> {});
        ScanEngine engine = new ScanEngine(List.of(noop), ScanListener.NOOP);
        EnvironmentInfo notElevated = new EnvironmentInfo("PC", "os", "user", false, "1.0.0", "abc", "jvm");
        ScanResult result = engine.run(SignatureDb.empty(), CheckId.generate(), notElevated);
        assertEquals(Verdict.INCONCLUSIVE, result.verdict());
    }
}

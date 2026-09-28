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

        ScanEngine engine = new ScanEngine(List.of(emitter, thrower), listener)
                .platformSupport(new Platform.Support(true, "test"));
        EnvironmentInfo env = new EnvironmentInfo("PC", "os", "user", true, "1.0.0", "abc", "jvm");
        ScanResult result = engine.run(SignatureDb.empty(), CheckId.generate(), env);

        assertEquals(1, findings.get());
        assertEquals(1, completed.get());
        assertEquals(1, result.findings().size());
        // a CRITICAL *indicator* asks for review; it is not a validated detection
        assertEquals(Verdict.REVIEW_REQUIRED, result.verdict());
        assertEquals(ModuleStatus.OK, result.moduleStatus().get("emit"));
        assertEquals(ModuleStatus.ERROR, result.moduleStatus().get("boom"));
        assertEquals("RuntimeException: kaboom", result.coverage().errors().get("boom"));
        assertEquals(List.of("boom"), result.coverage().missing());
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
        assertTrue(r.coverage().errors().get("sleeper").contains("time budget"), r.coverage().errors().toString());
        assertEquals(Verdict.INCOMPLETE_SCAN, r.verdict(), "a timed-out collector must not read as clean");
    }

    @Test
    void cleanScanWithoutAdminIsIncomplete() {
        CheckModule noop = module("noop", false, () -> {});
        ScanEngine engine = new ScanEngine(List.of(noop), ScanListener.NOOP)
                .platformSupport(new Platform.Support(true, "test"));
        EnvironmentInfo notElevated = new EnvironmentInfo("PC", "os", "user", false, "1.0.0", "abc", "jvm");
        ScanResult result = engine.run(SignatureDb.empty(), CheckId.generate(), notElevated);
        assertEquals(Verdict.INCOMPLETE_SCAN, result.verdict());
    }

    @Test
    void consentIsCarriedIntoTheResult() {
        CheckModule noop = module("noop", false, () -> {});
        ScanResult r = new ScanEngine(List.of(noop), ScanListener.NOOP)
                .platformSupport(new Platform.Support(true, "test"))
                .run(SignatureDb.empty(), CheckId.generate(),
                        new EnvironmentInfo("PC", "os", "user", true, "1.0.0", "abc", "jvm"), Consent.gui());
        assertEquals("gui", r.consent().channel());
        assertEquals(Consent.TEXT_VERSION, r.consent().textVersion());
        assertEquals(Verdict.NO_EVIDENCE, r.verdict());
    }
}

package ru.moon.checker.core;

import ru.moon.checker.signatures.SignatureDb;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs every {@link CheckModule} concurrently, streams progress to a
 * {@link ScanListener}, and aggregates the outcome into a {@link ScanResult}.
 *
 * <p>Hardened for a busy server: every module has a hard time budget enforced
 * by a watchdog, and the whole scan has an overall deadline. A module that
 * hangs (a stuck PowerShell call, an unresponsive disk, a slow network lookup)
 * is cancelled and marked {@link ModuleStatus#TIMEOUT} instead of freezing the
 * inspection — the admin always gets a result.
 */
public final class ScanEngine {

    /** Default per-module and overall time budgets. */
    public static final Duration DEFAULT_MODULE_TIMEOUT = Duration.ofMinutes(5);
    public static final Duration DEFAULT_OVERALL_TIMEOUT = Duration.ofMinutes(15);

    private final List<CheckModule> modules;
    private final ScanListener listener;
    private final Duration moduleTimeout;
    private final Duration overallTimeout;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public ScanEngine(List<CheckModule> modules, ScanListener listener) {
        this(modules, listener, DEFAULT_MODULE_TIMEOUT, DEFAULT_OVERALL_TIMEOUT);
    }

    public ScanEngine(List<CheckModule> modules, ScanListener listener,
                      Duration moduleTimeout, Duration overallTimeout) {
        this.modules = List.copyOf(modules);
        this.listener = listener == null ? ScanListener.NOOP : listener;
        this.moduleTimeout = moduleTimeout;
        this.overallTimeout = overallTimeout;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public ScanResult run(SignatureDb signatures, CheckId checkId, EnvironmentInfo env) {
        Instant start = Instant.now();
        List<Finding> findings = new CopyOnWriteArrayList<>();
        Map<String, ModuleStatus> status = new ConcurrentHashMap<>();
        java.util.Set<String> reported = ConcurrentHashMap.newKeySet();
        CountDownLatch latch = new CountDownLatch(modules.size());
        listener.onScanStart(modules.size());

        int threads = Math.max(2, Math.min(modules.size(), Runtime.getRuntime().availableProcessors() * 2));
        ExecutorService pool = Executors.newFixedThreadPool(threads, daemon("moon-check"));
        ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(daemon("moon-watchdog"));
        Map<String, Future<?>> futures = new ConcurrentHashMap<>();

        for (CheckModule module : modules) {
            status.put(module.id(), ModuleStatus.PENDING);
        }
        for (CheckModule module : modules) {
            Future<?> f = pool.submit(() ->
                    runOne(module, signatures, checkId, env, findings, status, reported, latch));
            futures.put(module.id(), f);
            watchdog.schedule(() -> {
                Future<?> fut = futures.get(module.id());
                if (fut != null && !fut.isDone()) {
                    fut.cancel(true); // interrupt the module thread
                    settle(module, ModuleStatus.TIMEOUT, status, reported, latch, 0);
                }
            }, moduleTimeout.toMillis(), TimeUnit.MILLISECONDS);
        }

        boolean completed;
        try {
            completed = latch.await(overallTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            completed = false;
        }
        if (!completed) {
            cancelled.set(true);
            for (CheckModule module : modules) {
                Future<?> f = futures.get(module.id());
                if (f != null) {
                    f.cancel(true);
                }
                settle(module, ModuleStatus.TIMEOUT, status, reported, latch, 0);
            }
        }
        watchdog.shutdownNow();
        pool.shutdownNow();

        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::module));

        ScoreCalculator.Score score = ScoreCalculator.calculate(sorted);
        Verdict verdict = adjustForReliability(score.verdict(), env);

        ScanResult result = new ScanResult(
                checkId, env, verdict, score.value(), List.copyOf(sorted),
                new LinkedHashMap<>(status),
                signatures.version(), originLabel(signatures),
                Instant.now(), Duration.between(start, Instant.now()));
        listener.onComplete(result);
        return result;
    }

    private void runOne(CheckModule module, SignatureDb signatures, CheckId checkId,
                        EnvironmentInfo env, List<Finding> findings, Map<String, ModuleStatus> status,
                        java.util.Set<String> reported, CountDownLatch latch) {
        if (cancelled.get()) {
            settle(module, ModuleStatus.SKIPPED, status, reported, latch, 0);
            return;
        }
        if (module.windowsOnly() && !Platform.isWindows()) {
            listener.onModuleStart(module);
            settle(module, ModuleStatus.SKIPPED, status, reported, latch, 0);
            return;
        }

        status.put(module.id(), ModuleStatus.RUNNING);
        listener.onModuleStart(module);

        AtomicInteger count = new AtomicInteger();
        ScanContext ctx = new ScanContext(signatures, checkId, env, listener, f -> {
            findings.add(f);
            count.incrementAndGet();
        }, cancelled);

        ModuleStatus outcome;
        try {
            module.run(ctx);
            outcome = ModuleStatus.OK;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            outcome = ModuleStatus.TIMEOUT;
        } catch (Throwable t) {
            if (Thread.currentThread().isInterrupted() || cancelled.get()) {
                outcome = ModuleStatus.TIMEOUT;
            } else {
                outcome = ModuleStatus.ERROR;
                Log.warn("module " + module.id() + " failed", t);
                ctx.log(module.displayName() + ": " + I18n.t("status.error") + " — " + t.getMessage());
            }
        }
        settle(module, outcome, status, reported, latch, count.get());
    }

    /** Records a module's final status exactly once (guards against watchdog races). */
    private void settle(CheckModule module, ModuleStatus outcome, Map<String, ModuleStatus> status,
                          java.util.Set<String> reported, CountDownLatch latch, int findingCount) {
        if (!reported.add(module.id())) {
            return; // already finalized
        }
        status.put(module.id(), outcome);
        try {
            listener.onModuleDone(module, outcome, findingCount);
        } catch (Throwable ignored) {
            // listener must never break the engine
        }
        latch.countDown();
    }

    private java.util.concurrent.ThreadFactory daemon(String name) {
        AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, name + "-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    /**
     * A "clean" result from a scan that never had admin rights is not
     * trustworthy — downgrade it to INCONCLUSIVE. Real cheat evidence still
     * stands regardless of elevation.
     */
    private Verdict adjustForReliability(Verdict verdict, EnvironmentInfo env) {
        if (verdict == Verdict.CLEAN && !env.elevated()) {
            return Verdict.INCONCLUSIVE;
        }
        return verdict;
    }

    private String originLabel(SignatureDb db) {
        return "v" + db.version() + " (" + db.ruleCount() + " rules)";
    }
}

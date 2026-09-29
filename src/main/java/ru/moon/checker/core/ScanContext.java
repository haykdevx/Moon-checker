package ru.moon.checker.core;

import ru.moon.checker.signatures.SignatureDb;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Shared state handed to every {@link CheckModule} during a run. Thread-safe:
 * modules run concurrently and all funnel findings/logs through here.
 */
public final class ScanContext {

    private final SignatureDb signatures;
    private final CheckId checkId;
    private final EnvironmentInfo env;
    private final ScanListener listener;
    private final FindingSink sink;
    private final AtomicBoolean cancelled;
    private final java.time.Instant deadline;
    private final java.util.List<String> shortfalls = new java.util.concurrent.CopyOnWriteArrayList<>();

    public ScanContext(SignatureDb signatures, CheckId checkId, EnvironmentInfo env,
                       ScanListener listener, FindingSink sink) {
        this(signatures, checkId, env, listener, sink, new AtomicBoolean(false));
    }

    /** Variant that shares a cancellation flag across per-module contexts. */
    public ScanContext(SignatureDb signatures, CheckId checkId, EnvironmentInfo env,
                       ScanListener listener, FindingSink sink, AtomicBoolean cancelled) {
        this(signatures, checkId, env, listener, sink, cancelled, null);
    }

    /** With the moment the engine will stop this collector, so long collectors can pace themselves. */
    public ScanContext(SignatureDb signatures, CheckId checkId, EnvironmentInfo env,
                       ScanListener listener, FindingSink sink, AtomicBoolean cancelled, java.time.Instant deadline) {
        this.deadline = deadline;
        this.signatures = signatures;
        this.checkId = checkId;
        this.env = env;
        this.listener = listener == null ? ScanListener.NOOP : listener;
        this.sink = sink;
        this.cancelled = cancelled;
    }

    public SignatureDb signatures() {
        return signatures;
    }

    public CheckId checkId() {
        return checkId;
    }

    public EnvironmentInfo env() {
        return env;
    }

    public boolean isElevated() {
        return env.elevated();
    }

    /** When the engine stops this collector (null: no limit, e.g. in tests). */
    public java.time.Instant deadline() {
        return deadline;
    }

    /**
     * Records that this collector could not cover part of what it is required to inspect (a
     * limit, an unreadable folder). The engine then settles it as {@link ModuleStatus#PARTIAL}
     * with these reasons, so the scan cannot read as complete. Expected exclusions (a file
     * type the collector does not handle) are not shortfalls; report those as context.
     */
    public void partial(String reason) {
        if (reason != null && !reason.isBlank()) {
            shortfalls.add(reason);
        }
    }

    public java.util.List<String> shortfalls() {
        return java.util.List.copyOf(shortfalls);
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    public void cancel() {
        cancelled.set(true);
    }

    /** Record a finding: stored for the result and pushed live to the UI. */
    public void emit(Finding f) {
        sink.accept(f);
        listener.onFinding(f);
    }

    /** Emit a live log line (what is being scanned right now). */
    public void log(String line) {
        listener.onLog(line);
    }

    /** Sink that accumulates findings for the final result. */
    @FunctionalInterface
    public interface FindingSink {
        void accept(Finding f);
    }
}

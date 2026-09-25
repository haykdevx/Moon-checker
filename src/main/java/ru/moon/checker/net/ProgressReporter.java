package ru.moon.checker.net;

import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Log;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.Severity;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Streams scan progress to the panel so the admin watches it live: module
 * counts, the module running now and findings per severity. Also acts as the
 * heartbeat — if it stops, the panel marks the check abandoned.
 *
 * <p>Scan threads only touch atomics; the single sender thread does all network
 * I/O, so a slow or dead connection can never stall the scan.
 */
public final class ProgressReporter implements ScanListener {

    private static final long MIN_GAP_MS = 1000;

    private final MoonApi api;
    private final SessionLink link;
    private final Runnable onServerCancelled;
    private final ScheduledExecutorService sender;
    private final AtomicInteger total = new AtomicInteger();
    private final AtomicInteger done = new AtomicInteger();
    private final Map<Severity, AtomicInteger> counts = new ConcurrentHashMap<>();
    private final AtomicLong lastSent = new AtomicLong();
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final AtomicBoolean cancelledByServer = new AtomicBoolean();
    private volatile String module = "";

    public ProgressReporter(MoonApi api, SessionLink link, Runnable onServerCancelled) {
        this.api = api;
        this.link = link;
        this.onServerCancelled = onServerCancelled;
        this.sender = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "moon-progress");
            t.setDaemon(true);
            return t;
        });
        for (Severity s : Severity.values()) {
            counts.put(s, new AtomicInteger());
        }
    }

    /** Starts the periodic heartbeat. */
    public void start(int totalModules) {
        total.set(totalModules);
        sender.scheduleWithFixedDelay(this::send, 0, link.heartbeatSeconds(), TimeUnit.SECONDS);
    }

    /** Stops heartbeats; call before uploading the report. */
    public void stop() {
        stopped.set(true);
        sender.shutdownNow();
    }

    @Override
    public void onScanStart(int totalModules) {
        total.set(totalModules);
        nudge();
    }

    @Override
    public void onModuleStart(CheckModule m) {
        module = m.id();
        nudge();
    }

    @Override
    public void onModuleDone(CheckModule m, ModuleStatus status, int findingCount) {
        done.incrementAndGet();
        nudge();
    }

    @Override
    public void onFinding(Finding f) {
        counts.get(f.severity()).incrementAndGet();
    }

    private void nudge() {
        if (!stopped.get() && System.currentTimeMillis() - lastSent.get() >= MIN_GAP_MS) {
            try {
                sender.execute(this::send);
            } catch (java.util.concurrent.RejectedExecutionException ignored) {
                // stopped concurrently
            }
        }
    }

    private void send() {
        if (stopped.get()) {
            return;
        }
        lastSent.set(System.currentTimeMillis());
        Map<String, Integer> c = new LinkedHashMap<>();
        for (Map.Entry<Severity, AtomicInteger> e : counts.entrySet()) {
            c.put(e.getKey().name().toLowerCase(java.util.Locale.ROOT), e.getValue().get());
        }
        try {
            api.progress(link, Math.min(done.get(), total.get()), total.get(), module, c);
        } catch (ApiException e) {
            if (("cancelled".equals(e.code()) || "bad_state".equals(e.code()))
                    && cancelledByServer.compareAndSet(false, true)) {
                Log.warn("panel reports the check is no longer running: " + e.getMessage());
                if (onServerCancelled != null) {
                    onServerCancelled.run();
                }
            } else {
                Log.warn("progress not delivered: " + e.getMessage());
            }
        } catch (RuntimeException e) {
            Log.warn("progress sender failed", e);
        }
    }

    public boolean cancelledByServer() {
        return cancelledByServer.get();
    }
}

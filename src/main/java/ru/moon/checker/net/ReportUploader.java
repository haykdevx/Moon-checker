package ru.moon.checker.net;

import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Log;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.report.JsonReport;

import java.util.function.Consumer;

/**
 * Delivers the finished evidence bundle to the admin's panel, retrying
 * transient failures, and confirms the server computed the same verification
 * code the player sees on screen.
 */
public final class ReportUploader {

    public enum State { SENDING, DELIVERED, MISMATCH, FAILED, OFFLINE }

    /** What the results screen shows about delivery. */
    public record Status(State state, String text) {
        public boolean retryAllowed() {
            return state == State.FAILED;
        }
    }

    static final long[] BACKOFF_MS = {2000, 5000, 10000};

    private ReportUploader() {
    }

    public static Status offline() {
        return new Status(State.OFFLINE, I18n.t("upload.offline"));
    }

    /** Blocking; reports intermediate states through {@code onUpdate}. */
    public static Status upload(MoonApi api, SessionLink link, ScanResult result, Consumer<Status> onUpdate) {
        return upload(api, link, result, onUpdate, BACKOFF_MS);
    }

    static Status upload(MoonApi api, SessionLink link, ScanResult result, Consumer<Status> onUpdate,
                         long[] backoff) {
        byte[] canonical = JsonReport.canonicalBytes(result);
        String localCode = JsonReport.verificationCode(result);
        int attempts = backoff.length + 1;
        onUpdate.accept(new Status(State.SENDING, I18n.t("upload.sending", link.adminAlias())));
        ApiException last = null;
        for (int i = 0; i < attempts; i++) {
            try {
                String serverCode = api.uploadReport(link, canonical);
                Status done = serverCode.equals(localCode)
                        ? new Status(State.DELIVERED, I18n.t("upload.delivered", link.adminAlias()))
                        : new Status(State.MISMATCH, I18n.t("upload.delivered.mismatch", link.adminAlias(), serverCode));
                Log.info("report delivered to " + link + " code=" + serverCode + " local=" + localCode);
                onUpdate.accept(done);
                return done;
            } catch (ApiException e) {
                last = e;
                Log.warn("report upload attempt " + (i + 1) + " failed: " + e.getMessage());
                if (!e.retryable() || i == attempts - 1) {
                    break;
                }
                onUpdate.accept(new Status(State.SENDING, I18n.t("upload.retrying", i + 2, attempts)));
                try {
                    Thread.sleep(backoff[i]);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        Status failed = new Status(State.FAILED, I18n.t("upload.failed",
                last == null ? "?" : last.describe(api.base().getHost())));
        onUpdate.accept(failed);
        return failed;
    }
}

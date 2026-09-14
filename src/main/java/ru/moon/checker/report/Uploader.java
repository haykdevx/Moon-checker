package ru.moon.checker.report;

import ru.moon.checker.core.Log;
import ru.moon.checker.core.ScanResult;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Opt-in submission of an evidence bundle to a collection endpoint.
 *
 * <p>Deliberately <b>never automatic</b>: the product decision for this server
 * is that the admin watches the check live over a Discord screen share and
 * nothing leaves the player's PC on its own. This exists for admins who choose
 * to archive results centrally, and is only invoked when an explicit
 * {@code --upload <url>} is passed (or a button is pressed).
 *
 * <p>The receiving service should re-verify the bundle server-side with the
 * same logic as {@link EvidenceVerifier} — never trust the client's own claim
 * that it is authentic.
 */
public final class Uploader {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private Uploader() {
    }

    public record Outcome(boolean ok, int status, String body) {
        static Outcome failed(String why) {
            return new Outcome(false, -1, why);
        }
    }

    public static Outcome upload(URI endpoint, ScanResult result) {
        return upload(endpoint, JsonReport.renderBytes(result));
    }

    public static Outcome upload(URI endpoint, byte[] evidenceJson) {
        if (endpoint == null || evidenceJson == null) {
            return Outcome.failed("no endpoint or payload");
        }
        try {
            HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(endpoint)
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .header("User-Agent", "MoonChecker/1.0")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(evidenceJson))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            boolean ok = response.statusCode() >= 200 && response.statusCode() < 300;
            if (!ok) {
                Log.warn("evidence upload rejected: HTTP " + response.statusCode());
            }
            return new Outcome(ok, response.statusCode(), response.body());
        } catch (Exception e) {
            Log.warn("evidence upload failed", e);
            return Outcome.failed(e.getMessage());
        }
    }
}

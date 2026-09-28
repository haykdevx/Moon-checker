package ru.moon.checker.net;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Hashing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * Client for the Moon panel's checker API ({@code /api/v1}). Blocking calls;
 * the UI runs them off the EDT. See {@code web/checks/api.py} for the server side.
 */
public final class MoonApi {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration UPLOAD_TIMEOUT = Duration.ofMinutes(3);

    private final URI base;
    private final HttpClient http;
    private final ObjectMapper json = new ObjectMapper();
    private final String userAgent;

    public MoonApi(URI base, String appVersion) {
        this.base = base;
        this.userAgent = "MoonChecker/" + appVersion + " (" + System.getProperty("os.name", "?") + ")";
        this.http = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER) // never let a redirect carry the token elsewhere
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public URI base() {
        return base;
    }

    /** Exchanges the admin's code for a session. */
    public SessionLink claim(String code, EnvironmentInfo env) throws ApiException {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("hostname", env.hostname());
        client.put("user", env.userName());
        client.put("os", env.osName());
        client.put("appVersion", env.appVersion());
        client.put("selfHash", env.selfHash());
        client.put("selfHashFull", Hashing.selfHashFull());
        client.put("jvm", env.jvm());
        client.put("elevated", env.elevated());
        client.put("utcOffsetMinutes", ZoneId.systemDefault().getRules()
                .getOffset(java.time.Instant.now()).getTotalSeconds() / 60);
        Map<String, Object> body = Map.of("code", code, "client", client);

        JsonNode r = send(post("/api/v1/claim", toJson(body), CALL_TIMEOUT, null).build());
        String id = r.path("sessionId").asText("");
        String token = r.path("token").asText("");
        if (id.isEmpty() || token.isEmpty()) {
            throw new ApiException(200, "protocol", "server answered without a session", null, null);
        }
        return new SessionLink(id, token,
                r.path("admin").path("alias").asText("?"),
                r.path("admin").path("name").asText(""),
                r.path("player").path("name").asText(""),
                Math.max(2, Math.min(60, r.path("heartbeatSeconds").asInt(5))),
                safeUrl(r.path("statusUrl").asText("")));
    }

    /** Only an https (or loopback http) link on the panel's own host is shown to the player. */
    String safeUrl(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            boolean sameHost = u.getHost() != null && u.getHost().equalsIgnoreCase(base.getHost());
            boolean scheme = "https".equals(u.getScheme()) || ("http".equals(u.getScheme()) && "http".equals(base.getScheme()));
            return sameHost && scheme ? u.toString() : "";
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /** Live progress / heartbeat. */
    public void progress(SessionLink s, int done, int total, String module, Map<String, Integer> counts)
            throws ApiException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("done", done);
        body.put("total", total);
        body.put("module", module == null ? "" : module);
        body.put("counts", counts);
        send(post("/api/v1/sessions/" + s.sessionId() + "/progress", toJson(body), CALL_TIMEOUT, s).build());
    }

    /**
     * Uploads the canonical evidence bytes (gzip on the wire) and returns the
     * verification code the server computed over them.
     */
    public String uploadReport(SessionLink s, byte[] canonical) throws ApiException {
        HttpRequest.Builder b = post("/api/v1/sessions/" + s.sessionId() + "/report", gzip(canonical),
                UPLOAD_TIMEOUT, s)
                .header("Content-Encoding", "gzip")
                .header("X-Moon-Sha256", ru.moon.checker.core.Integrity.sha256Hex(canonical));
        try {
            return send(b.build()).path("verificationCode").asText("");
        } catch (ApiException e) {
            if ("already_completed".equals(e.code()) && e.verificationCode() != null) {
                return e.verificationCode(); // a retry after a lost response: it did arrive
            }
            throw e;
        }
    }

    private HttpRequest.Builder post(String path, byte[] body, Duration timeout, SessionLink auth) {
        HttpRequest.Builder b = HttpRequest.newBuilder(base.resolve(path))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", userAgent)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (auth != null) {
            b.header("Authorization", "Bearer " + auth.token());
        }
        return b;
    }

    private JsonNode send(HttpRequest req) throws ApiException {
        HttpResponse<byte[]> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw ApiException.network(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw ApiException.network(e);
        }
        JsonNode node;
        try {
            node = json.readTree(resp.body());
        } catch (Exception e) {
            node = null;
        }
        int status = resp.statusCode();
        if (status >= 200 && status < 300 && node != null && node.isObject()) {
            return node;
        }
        if (node != null && node.hasNonNull("error")) {
            throw new ApiException(status, node.path("error").asText(), node.path("message").asText(""),
                    node.hasNonNull("download") ? node.path("download").asText() : null,
                    node.hasNonNull("verificationCode") ? node.path("verificationCode").asText() : null);
        }
        throw new ApiException(status, status >= 500 ? "server" : "protocol",
                "unexpected HTTP " + status, null, null);
    }

    private byte[] toJson(Object o) {
        try {
            return json.writeValueAsBytes(o);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] gzip(byte[] data) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length / 4));
            try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
                gz.write(data);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}

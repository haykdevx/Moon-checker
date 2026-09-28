package ru.moon.checker.net;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Integrity;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Verdict;
import ru.moon.checker.report.JsonReport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;

/** Talks to a stub of the panel API on a loopback port. */
class MoonApiTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final EnvironmentInfo ENV = new EnvironmentInfo("PC-1", "Windows 11", "player", true,
            "1.1.0", "abcdef123456", "Temurin 21");

    private HttpServer server;
    private MoonApi api;
    private final List<String> seen = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger reportCalls = new AtomicInteger();
    private volatile int failReportsWith = 0;
    private volatile byte[] lastReport;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/claim", ex -> {
            JsonNode body = JSON.readTree(ex.getRequestBody());
            seen.add("claim " + body.path("code").asText() + " " + body.path("client").path("hostname").asText());
            if (!body.path("code").asText().equals("K7MQ-4X2P")) {
                reply(ex, 404, "{\"error\":\"invalid_code\",\"message\":\"nope\"}");
                return;
            }
            reply(ex, 200, "{\"sessionId\":\"s-1\",\"token\":\"tok\",\"admin\":{\"alias\":\"shadow\",\"name\":\"Shadow\"},"
                    + "\"player\":{\"name\":\"Bob\"},\"heartbeatSeconds\":5}");
        });
        server.createContext("/api/v1/sessions/s-1/progress", ex -> {
            seen.add("progress " + ex.getRequestHeaders().getFirst("Authorization"));
            reply(ex, 200, "{\"ok\":true}");
        });
        server.createContext("/api/v1/sessions/s-1/report", ex -> {
            reportCalls.incrementAndGet();
            if (failReportsWith != 0) {
                int code = failReportsWith;
                reply(ex, code, code == 410 ? "{\"error\":\"cancelled\",\"message\":\"x\"}" : "oops");
                return;
            }
            assertEquals("gzip", ex.getRequestHeaders().getFirst("Content-Encoding"));
            byte[] raw = new GZIPInputStream(ex.getRequestBody()).readAllBytes();
            assertEquals(Integrity.sha256Hex(raw), ex.getRequestHeaders().getFirst("X-Moon-Sha256"));
            lastReport = raw;
            reply(ex, 200, "{\"ok\":true,\"verificationCode\":\"" + Integrity.shortCode(raw) + "\"}");
        });
        server.start();
        api = new MoonApi(URI.create("http://127.0.0.1:" + server.getAddress().getPort()), "1.1.0");
        I18n.setLocale(I18n.ENGLISH);
    }

    @AfterEach
    void stop() {
        server.stop(0);
        I18n.setLocale(I18n.RUSSIAN);
    }

    private static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private static ScanResult result() {
        return ru.moon.checker.core.TestResults.of(List.of());
    }

    @Test
    void claimProgressAndUpload() throws Exception {
        SessionLink link = api.claim("K7MQ-4X2P", ENV);
        assertEquals("shadow", link.adminAlias());
        assertEquals("Bob", link.playerName());
        assertFalse(link.toString().contains("tok"), "token must not leak into logs");

        api.progress(link, 1, 10, "files", Map.of("high", 1));
        assertTrue(seen.contains("progress Bearer tok"));

        ScanResult r = result();
        List<ReportUploader.Status> states = new ArrayList<>();
        ReportUploader.Status st = ReportUploader.upload(api, link, r, states::add, new long[]{0, 0});
        assertEquals(ReportUploader.State.DELIVERED, st.state(), st.text());
        assertEquals(ReportUploader.State.SENDING, states.get(0).state());
        assertArrayEquals(JsonReport.canonicalBytes(r), lastReport, "server receives the exact canonical bytes");
        assertTrue(st.text().contains("shadow"));
    }

    @Test
    void refusedCodeIsExplained() {
        ApiException e = assertThrows(ApiException.class, () -> api.claim("AAAA-AAAA", ENV));
        assertEquals("invalid_code", e.code());
        assertFalse(e.retryable());
        assertEquals("This code does not exist. Check it with your admin.", e.describe("host"));
    }

    @Test
    void transientFailuresAreRetriedThenGiveUp() throws Exception {
        SessionLink link = api.claim("K7MQ-4X2P", ENV);
        failReportsWith = 503;
        ReportUploader.Status st = ReportUploader.upload(api, link, result(), s -> { }, new long[]{0, 0});
        assertEquals(ReportUploader.State.FAILED, st.state());
        assertEquals(3, reportCalls.get(), "1 try + 2 retries");
        assertTrue(st.retryAllowed());

        reportCalls.set(0);
        failReportsWith = 410; // cancelled by the admin: final, no retry
        st = ReportUploader.upload(api, link, result(), s -> { }, new long[]{0, 0});
        assertEquals(ReportUploader.State.FAILED, st.state());
        assertEquals(1, reportCalls.get());
        assertTrue(st.text().contains("cancelled"), st.text());
    }

    @Test
    void unreachableServerIsANetworkError() throws Exception {
        MoonApi dead = new MoonApi(URI.create("http://127.0.0.1:1"), "1.1.0");
        ApiException e = assertThrows(ApiException.class, () -> dead.claim("K7MQ-4X2P", ENV));
        assertEquals("network", e.code());
        assertTrue(e.retryable());
        assertTrue(e.describe("moon.example.org").contains("moon.example.org"));
    }
}

package ru.moon.checker.report;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** The opt-in uploader, exercised against a real local HTTP server. */
class UploaderTest {

    private HttpServer start(int status, AtomicReference<String> captured) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/checks", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            captured.set(body);
            byte[] response = "{\"stored\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        return server;
    }

    @Test
    void postsTheEvidenceBundle() throws Exception {
        AtomicReference<String> captured = new AtomicReference<>();
        HttpServer server = start(200, captured);
        try {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/checks");
            byte[] payload = "{\"schema\":\"moon-check/1\",\"verdict\":\"CHEAT\"}"
                    .getBytes(StandardCharsets.UTF_8);

            Uploader.Outcome outcome = Uploader.upload(uri, payload);

            assertTrue(outcome.ok(), "expected success, got " + outcome);
            assertEquals(200, outcome.status());
            assertTrue(outcome.body().contains("stored"));
            assertTrue(captured.get().contains("moon-check/1"), "server must receive the bundle");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void reportsServerRejection() throws Exception {
        AtomicReference<String> captured = new AtomicReference<>();
        HttpServer server = start(500, captured);
        try {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/checks");
            Uploader.Outcome outcome = Uploader.upload(uri, "{}".getBytes(StandardCharsets.UTF_8));
            assertFalse(outcome.ok());
            assertEquals(500, outcome.status());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void failsGracefullyWhenUnreachable() {
        // port 1 on loopback: nothing listening
        Uploader.Outcome outcome = Uploader.upload(URI.create("http://127.0.0.1:1/checks"),
                "{}".getBytes(StandardCharsets.UTF_8));
        assertFalse(outcome.ok());
        assertEquals(-1, outcome.status());
    }

    @Test
    void nullsAreRejected() {
        assertFalse(Uploader.upload(null, new byte[0]).ok());
        assertFalse(Uploader.upload(URI.create("http://127.0.0.1:1/"), (byte[]) null).ok());
    }
}

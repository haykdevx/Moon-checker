package ru.moon.checker.net;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** A player told what went wrong on the way to the panel — and what to do. */
class NetworkErrorsTest {

    @Test
    void connectionProblemsAreToldApart() {
        assertEquals("dns", ApiException.classify(new ConnectException("x") {{
            initCause(new UnknownHostException("moon.example.org"));
        }}));
        assertEquals("timeout", ApiException.classify(new HttpTimeoutException("request timed out")));
        assertEquals("tls", ApiException.classify(new SSLHandshakeException(
                "PKIX path building failed: unable to find valid certification path")));
        assertEquals("proxy", ApiException.classify(new java.io.IOException("Unable to tunnel through proxy. 407")));
        assertEquals("unreachable", ApiException.classify(new ConnectException("Connection refused")));
        assertEquals("network", ApiException.classify(new java.io.IOException("reset")));
    }

    @Test
    void aCertificateProblemIsNotRetriedBlindly() {
        ApiException tls = ApiException.network(new SSLHandshakeException("PKIX path building failed"));
        assertFalse(tls.retryable(), "retrying cannot fix an antivirus re-signing HTTPS");
        assertTrue(ApiException.network(new ConnectException("refused")).retryable());
    }

    @Test
    void aWifiLoginPageIsRecognised() {
        byte[] html = "<!DOCTYPE html><html><title>Вход в сеть</title>".getBytes(StandardCharsets.UTF_8);
        assertEquals("captive", ApiException.classifyHttp(200, html));
        assertEquals("captive", ApiException.classifyHttp(302, new byte[0]));
        assertEquals("proxy", ApiException.classifyHttp(407, new byte[0]));
        assertEquals("server", ApiException.classifyHttp(502, "bad gateway".getBytes(StandardCharsets.UTF_8)));
        assertEquals("protocol", ApiException.classifyHttp(418, "{}".getBytes(StandardCharsets.UTF_8)));
    }
}

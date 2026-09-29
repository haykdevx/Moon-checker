package ru.moon.checker.report;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Integrity;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Severity;
import ru.moon.checker.core.Verdict;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceTest {

    private ScanResult sample(boolean elevated, String title) {
        EnvironmentInfo env = new EnvironmentInfo("PC", "Windows 11", "player", elevated, "1.0.0", "abc123", "jvm");
        Finding f = Finding.builder(Category.FILES, Severity.CRITICAL, title)
                .module("files").evidence("C:\\x\\cheat.dll").source("sha256")
                .when(Instant.parse("2026-01-01T00:00:00Z")).build();
        return ru.moon.checker.core.TestResults.of(List.of(f), ru.moon.checker.core.TestResults.complete("files"), env);
    }

    @Test
    void jsonBundleContainsIntegrityBlock() {
        String json = JsonReport.render(sample(true, "cheat"));
        assertTrue(json.contains("\"integrity\""));
        assertTrue(json.contains("\"sha256\""));
        assertTrue(json.contains("\"hmac\""));
        assertTrue(json.contains("\"code\""));
        assertTrue(json.contains("\"schema\" : \"moon-evidence/2\""));
        for (String section : new String[]{"\"evidence\"", "\"coverage\"", "\"assurance\"", "\"verdict\"",
                "\"consent\"", "\"collector\"", "\"session\""}) {
            assertTrue(json.contains(section), "missing section " + section);
        }
        assertTrue(json.contains("\"id\" : \"E1\""), "evidence items carry stable ids");
        assertFalse(json.contains("\"score\""), "no score in the bundle");
        assertFalse(json.contains("\"weight\""), "no weights in the bundle");
    }

    @Test
    void canonicalBytesAreDeterministic() {
        ScanResult r = sample(true, "cheat");
        assertArrayEquals(JsonReport.canonicalBytes(r), JsonReport.canonicalBytes(r));
        assertEquals(JsonReport.verificationCode(r), JsonReport.verificationCode(r));
    }

    @Test
    void tamperingChangesTheCode() {
        String codeA = JsonReport.verificationCode(sample(true, "cheat A"));
        String codeB = JsonReport.verificationCode(sample(true, "cheat B"));
        String codeC = JsonReport.verificationCode(sample(false, "cheat A"));
        assertNotEquals(codeA, codeB, "different finding must change the code");
        assertNotEquals(codeA, codeC, "different coverage/assurance must change the code");
    }

    @Test
    void hmacIsStableAndCodeFormatted() {
        byte[] data = "hello".getBytes();
        assertEquals(Integrity.hmacHex(data), Integrity.hmacHex(data));
        assertNotEquals(Integrity.sha256Hex(data), Integrity.hmacHex(data));
        String code = Integrity.shortCode(data);
        assertTrue(code.matches("[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}"), "code was " + code);
    }

    @Test
    void aBoundReportCarriesItsCheckAndTheCodeCoversIt() {
        ScanResult offline = sample(true, "cheat");
        ScanResult bound = withBinding(offline, new ru.moon.checker.core.SessionBinding(
                "3f1e2d4c-5b6a-4789-9abc-def012345678", "n".repeat(43), 3));
        String json = new String(JsonReport.canonicalBytes(bound), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(json.contains("\"binding\":{\"panelSessionId\":\"3f1e2d4c-5b6a-4789-9abc-def012345678\","
                + "\"protocol\":3,\"uploadNonce\":\"" + "n".repeat(43) + "\"}"), json);
        assertFalse(new String(JsonReport.canonicalBytes(offline), java.nio.charset.StandardCharsets.UTF_8)
                .contains("binding"), "an offline check has no binding");
        ScanResult otherNonce = withBinding(offline, new ru.moon.checker.core.SessionBinding(
                "3f1e2d4c-5b6a-4789-9abc-def012345678", "m".repeat(43), 3));
        assertNotEquals(JsonReport.verificationCode(bound), JsonReport.verificationCode(otherNonce),
                "the on-screen code covers the binding, so it still matches the panel's");
    }

    private static ScanResult withBinding(ScanResult r, ru.moon.checker.core.SessionBinding b) {
        return new ScanResult(r.checkId(), r.env(), r.assessment(), r.findings(), r.moduleStatus(),
                r.signatureVersion(), r.rules(), r.consent(), r.finishedAt(), r.duration(), b);
    }

    @Test
    void theUploadValueNeverAppearsInTheSessionsToString() {
        var link = new ru.moon.checker.net.SessionLink("id", "secret-token", "adm", "", "p", 5, "", 3, "secret-nonce");
        assertFalse(link.toString().contains("secret"), link.toString());
        assertEquals("secret-nonce", link.binding().uploadNonce());
        assertNull(new ru.moon.checker.net.SessionLink("id", "t", "a", "", "p", 5, "", 0, "").binding(),
                "a panel that issued no value gets no binding");
    }
}

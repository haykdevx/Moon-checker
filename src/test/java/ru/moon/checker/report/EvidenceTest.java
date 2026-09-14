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

    private ScanResult sample(int score, String title) {
        CheckId id = CheckId.generate();
        EnvironmentInfo env = new EnvironmentInfo("PC", "Windows 11", "player", true, "1.0.0", "abc123", "jvm");
        Finding f = Finding.builder(Category.FILES, Severity.CRITICAL, title)
                .module("files").evidence("C:\\x\\cheat.dll").source("sha256")
                .when(Instant.parse("2026-01-01T00:00:00Z")).build();
        return new ScanResult(id, env, Verdict.CHEAT, score, List.of(f),
                Map.of("files", ModuleStatus.OK), "2026.09.13", "bundled",
                Instant.parse("2026-01-01T00:05:00Z"), Duration.ofSeconds(42));
    }

    @Test
    void jsonBundleContainsIntegrityBlock() {
        String json = JsonReport.render(sample(100, "cheat"));
        assertTrue(json.contains("\"integrity\""));
        assertTrue(json.contains("\"sha256\""));
        assertTrue(json.contains("\"hmac\""));
        assertTrue(json.contains("\"code\""));
        assertTrue(json.contains("\"schema\" : \"moon-check/1\""));
    }

    @Test
    void canonicalBytesAreDeterministic() {
        ScanResult r = sample(100, "cheat");
        assertArrayEquals(JsonReport.canonicalBytes(r), JsonReport.canonicalBytes(r));
        assertEquals(JsonReport.verificationCode(r), JsonReport.verificationCode(r));
    }

    @Test
    void tamperingChangesTheCode() {
        String codeA = JsonReport.verificationCode(sample(100, "cheat A"));
        String codeB = JsonReport.verificationCode(sample(100, "cheat B"));
        String codeC = JsonReport.verificationCode(sample(50, "cheat A"));
        assertNotEquals(codeA, codeB, "different finding must change the code");
        assertNotEquals(codeA, codeC, "different score must change the code");
    }

    @Test
    void hmacIsStableAndCodeFormatted() {
        byte[] data = "hello".getBytes();
        assertEquals(Integrity.hmacHex(data), Integrity.hmacHex(data));
        assertNotEquals(Integrity.sha256Hex(data), Integrity.hmacHex(data));
        String code = Integrity.shortCode(data);
        assertTrue(code.matches("[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}"), "code was " + code);
    }
}

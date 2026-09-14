package ru.moon.checker.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Severity;
import ru.moon.checker.core.Verdict;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** End-to-end proof that the evidence bundle is genuinely tamper-evident. */
class EvidenceVerifierTest {

    private ScanResult sample(Verdict verdict, int score, String title) {
        EnvironmentInfo env = new EnvironmentInfo("PC", "Windows 11", "player", true,
                "1.0.0", "abc123", "jvm");
        Finding f = Finding.builder(Category.FILES, Severity.CRITICAL, title)
                .module("files").evidence("C:\\x\\cheat.dll").source("sha256")
                .when(Instant.parse("2026-01-01T00:00:00Z")).build();
        return new ScanResult(CheckId.generate(), env, verdict, score, List.of(f),
                Map.of("files", ModuleStatus.OK), "2026.09.13b", "bundled",
                Instant.parse("2026-01-01T00:05:00Z"), Duration.ofSeconds(42));
    }

    @Test
    void freshBundleVerifiesAsAuthentic() {
        byte[] json = JsonReport.renderBytes(sample(Verdict.CHEAT, 100, "cheat found"));
        EvidenceVerifier.Result r = EvidenceVerifier.verify(json);
        assertTrue(r.wellFormed(), r.detail());
        assertTrue(r.hashOk(), "sha-256 must match: " + r.detail());
        assertTrue(r.hmacOk(), "hmac must match: " + r.detail());
        assertTrue(r.authentic());
    }

    @Test
    void editingTheVerdictIsDetected() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] json = JsonReport.renderBytes(sample(Verdict.CHEAT, 100, "cheat found"));
        @SuppressWarnings("unchecked")
        Map<String, Object> doc = om.readValue(json, Map.class);

        // a cheater edits the saved report to say they were clean
        doc.put("verdict", "CLEAN");
        doc.put("score", 0);
        byte[] tampered = om.writeValueAsBytes(doc);

        EvidenceVerifier.Result r = EvidenceVerifier.verify(tampered);
        assertTrue(r.wellFormed());
        assertFalse(r.hashOk(), "tampering must break the hash");
        assertFalse(r.authentic());
        assertTrue(r.detail().contains("MODIFIED"), r.detail());
    }

    @Test
    void editingAFindingIsDetected() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] json = JsonReport.renderBytes(sample(Verdict.CHEAT, 100, "cheat found"));
        @SuppressWarnings("unchecked")
        Map<String, Object> doc = om.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> findings = (List<Map<String, Object>>) doc.get("findings");
        findings.clear(); // delete the evidence
        byte[] tampered = om.writeValueAsBytes(doc);

        assertFalse(EvidenceVerifier.verify(tampered).authentic());
    }

    @Test
    void forgedIntegrityBlockIsDetected() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] json = JsonReport.renderBytes(sample(Verdict.CHEAT, 100, "cheat found"));
        @SuppressWarnings("unchecked")
        Map<String, Object> doc = om.readValue(json, Map.class);
        doc.put("verdict", "CLEAN");
        // recompute only the sha (attacker without the HMAC key)
        @SuppressWarnings("unchecked")
        Map<String, Object> integrity = (Map<String, Object>) doc.get("integrity");
        Map<String, Object> payload = new java.util.TreeMap<>(doc);
        payload.remove("integrity");
        byte[] canonical = new ObjectMapper()
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .writeValueAsBytes(payload);
        integrity.put("sha256", ru.moon.checker.core.Integrity.sha256Hex(canonical));
        byte[] forged = om.writeValueAsBytes(doc);

        EvidenceVerifier.Result r = EvidenceVerifier.verify(forged);
        assertTrue(r.hashOk(), "attacker can recompute the plain hash");
        assertFalse(r.hmacOk(), "but not the HMAC without the key");
        assertFalse(r.authentic());
    }

    @Test
    void rejectsNonEvidenceFiles() {
        assertFalse(EvidenceVerifier.verify("{\"hello\":1}".getBytes(StandardCharsets.UTF_8)).wellFormed());
        assertFalse(EvidenceVerifier.verify("not json".getBytes(StandardCharsets.UTF_8)).wellFormed());
        assertFalse(EvidenceVerifier.verify(new byte[0]).wellFormed());
    }
}

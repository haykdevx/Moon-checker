package ru.moon.checker.report;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Integrity;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanResult;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Produces a machine-readable, tamper-evident evidence bundle (JSON) for the
 * admin's records and for server-side verification/disputes. The bundle embeds
 * a SHA-256 and an HMAC ({@link Integrity}) computed over the canonical payload,
 * plus a short verification code that also appears on screen and in the HTML
 * report — so the three must agree.
 */
public final class JsonReport {

    /** Canonical mapper: sorted keys, no indentation — deterministic bytes. */
    private static final ObjectMapper CANON = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private static final ObjectMapper PRETTY = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private JsonReport() {
    }

    /** The canonical payload (no integrity block), used for hashing. */
    public static Map<String, Object> payload(ScanResult r) {
        Map<String, Object> m = new TreeMap<>();
        m.put("schema", "moon-check/1");
        m.put("checkId", r.checkId().value());
        m.put("startedAt", r.checkId().startedAt().toString());
        m.put("finishedAt", r.finishedAt().toString());
        m.put("durationSeconds", r.duration().toSeconds());
        m.put("verdict", r.verdict().name());
        m.put("score", r.score());
        m.put("signatureVersion", r.signatureVersion());
        m.put("signatureOrigin", r.signatureOrigin());

        Map<String, Object> env = new TreeMap<>();
        env.put("hostname", r.env().hostname());
        env.put("os", r.env().osName());
        env.put("user", r.env().userName());
        env.put("elevated", r.env().elevated());
        env.put("appVersion", r.env().appVersion());
        env.put("selfHash", r.env().selfHash());
        env.put("jvm", r.env().jvm());
        m.put("environment", env);

        Map<String, Object> modules = new TreeMap<>();
        for (Map.Entry<String, ModuleStatus> e : r.moduleStatus().entrySet()) {
            modules.put(e.getKey(), e.getValue().name());
        }
        m.put("modules", modules);

        List<Object> findings = new ArrayList<>();
        for (Finding f : r.findings()) {
            Map<String, Object> fm = new TreeMap<>();
            fm.put("severity", f.severity().name());
            fm.put("category", f.category().name());
            fm.put("module", f.module());
            fm.put("title", f.title());
            fm.put("detail", f.detail());
            fm.put("evidence", f.evidence());
            fm.put("source", f.source());
            fm.put("weight", f.weight());
            fm.put("when", f.when() == null ? null : f.when().toString());
            findings.add(fm);
        }
        m.put("findings", findings);
        return m;
    }

    /** Canonical bytes for hashing (compact, sorted). */
    public static byte[] canonicalBytes(ScanResult r) {
        try {
            return CANON.writeValueAsBytes(payload(r));
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /** Short verification code, also shown on screen and in the HTML report. */
    public static String verificationCode(ScanResult r) {
        return Integrity.shortCode(canonicalBytes(r));
    }

    /** The full JSON evidence bundle (pretty), including the integrity block. */
    public static String render(ScanResult r) {
        byte[] canon = canonicalBytes(r);
        Map<String, Object> full = new TreeMap<>(payload(r));
        Map<String, Object> integrity = new TreeMap<>();
        integrity.put("algorithm", "SHA-256 + HMAC-SHA256");
        integrity.put("sha256", Integrity.sha256Hex(canon));
        integrity.put("hmac", Integrity.hmacHex(canon));
        integrity.put("code", Integrity.shortCode(canon));
        full.put("integrity", integrity);
        try {
            return PRETTY.writeValueAsString(full);
        } catch (Exception e) {
            return "{\"error\":\"serialization failed\"}";
        }
    }

    public static byte[] renderBytes(ScanResult r) {
        return render(r).getBytes(StandardCharsets.UTF_8);
    }
}

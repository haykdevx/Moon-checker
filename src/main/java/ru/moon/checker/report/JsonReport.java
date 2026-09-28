package ru.moon.checker.report;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ru.moon.checker.core.Assessment;
import ru.moon.checker.core.Assurance;
import ru.moon.checker.core.Coverage;
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
 * The evidence bundle, schema {@code moon-evidence/2}. Four concerns are kept
 * in separate sections so none can stand in for another:
 *
 * <ul>
 *   <li>{@code evidence} — what was observed (ids E1…En, kind, rule, source)</li>
 *   <li>{@code coverage} — what was actually inspected, and what failed</li>
 *   <li>{@code assurance} — why the report itself should (or should not) be trusted</li>
 *   <li>{@code verdict} — what the evidence supports, with the evidence it rests on</li>
 * </ul>
 *
 * <p>An integrity block (SHA-256 and HMAC over the canonical payload) makes hand
 * edits detectable and yields the on-screen verification code. The HMAC key
 * ships inside the client, so it is <b>not</b> proof of origin: the panel binds a
 * report to a check through the per-session token issued when the code is
 * entered, and judges the build by its file hash.
 */
public final class JsonReport {

    public static final String SCHEMA = "moon-evidence/2";

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
        m.put("schema", SCHEMA);

        Map<String, Object> session = new TreeMap<>();
        session.put("checkId", r.checkId().value());
        session.put("startedAt", r.checkId().startedAt().toString());
        session.put("finishedAt", r.finishedAt().toString());
        session.put("durationSeconds", r.duration().toSeconds());
        m.put("session", session);

        Map<String, Object> collector = new TreeMap<>();
        collector.put("appVersion", r.env().appVersion());
        collector.put("selfHash", r.env().selfHash());
        collector.put("jvm", r.env().jvm());
        collector.put("rulesVersion", r.signatureVersion());
        collector.put("rulesOrigin", r.signatureOrigin());
        m.put("collector", collector);

        Map<String, Object> env = new TreeMap<>();
        env.put("hostname", r.env().hostname());
        env.put("os", r.env().osName());
        env.put("user", r.env().userName());
        env.put("elevated", r.env().elevated());
        m.put("environment", env);

        Map<String, Object> consent = new TreeMap<>();
        consent.put("textVersion", r.consent().textVersion());
        consent.put("acceptedAt", r.consent().acceptedAt() == null ? null : r.consent().acceptedAt().toString());
        consent.put("channel", r.consent().channel());
        m.put("consent", consent);

        List<Object> evidence = new ArrayList<>();
        List<Finding> fs = r.findings();
        for (int i = 0; i < fs.size(); i++) {
            Finding f = fs.get(i);
            Map<String, Object> fm = new TreeMap<>();
            fm.put("id", "E" + (i + 1));
            fm.put("kind", f.kind().name());
            fm.put("rule", f.ruleId());
            fm.put("module", f.module());
            fm.put("category", f.category().name());
            fm.put("severity", f.severity().name());
            fm.put("title", f.title());
            fm.put("detail", f.detail());
            fm.put("evidence", f.evidence());
            fm.put("source", f.source());
            fm.put("when", f.when() == null ? null : f.when().toString());
            evidence.add(fm);
        }
        m.put("evidence", evidence);

        Assessment a = r.assessment();
        Coverage c = a.coverage();
        Map<String, Object> coverage = new TreeMap<>();
        Map<String, Object> modules = new TreeMap<>();
        for (Map.Entry<String, ModuleStatus> e : c.modules().entrySet()) {
            modules.put(e.getKey(), e.getValue().name());
        }
        coverage.put("modules", modules);
        coverage.put("required", new ArrayList<>(new java.util.TreeSet<>(c.required())));
        coverage.put("missing", c.missing());
        coverage.put("errors", new TreeMap<>(c.errors()));
        coverage.put("elevated", c.elevated());
        coverage.put("platformSupported", c.platformSupported());
        coverage.put("platformNote", c.platformNote());
        coverage.put("complete", c.complete());
        m.put("coverage", coverage);

        Map<String, Object> assurance = new TreeMap<>();
        assurance.put("level", a.assurance().level().name());
        List<Object> notes = new ArrayList<>();
        for (Assurance.Note n : a.assurance().reasons()) {
            notes.add(new TreeMap<>(Map.of("code", n.code(), "text", n.text())));
        }
        assurance.put("reasons", notes);
        m.put("assurance", assurance);

        Map<String, Object> verdict = new TreeMap<>();
        verdict.put("outcome", a.outcome().name());
        List<Object> reasons = new ArrayList<>();
        for (Assessment.Reason reason : a.reasons()) {
            Map<String, Object> rm = new TreeMap<>();
            rm.put("code", reason.code());
            rm.put("text", reason.text());
            rm.put("evidence", reason.evidence().stream().map(i -> "E" + i).toList());
            reasons.add(rm);
        }
        verdict.put("reasons", reasons);
        m.put("verdict", verdict);
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
        integrity.put("algorithm", "SHA-256 + HMAC-SHA256 (tamper evidence, not proof of origin)");
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

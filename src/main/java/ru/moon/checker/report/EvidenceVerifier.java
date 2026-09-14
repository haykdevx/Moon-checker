package ru.moon.checker.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ru.moon.checker.core.Integrity;

import java.util.Map;
import java.util.TreeMap;

/**
 * Verifies a saved evidence bundle. This is the other half of
 * {@link JsonReport}: it recomputes the canonical hash and HMAC over the
 * payload and compares them with the embedded {@code integrity} block, so an
 * admin can prove a JSON a player sent them was produced by the real checker
 * and has not been edited.
 *
 * <p>Works offline — no server required. The same check is what a backend would
 * run server-side (see {@code prompts/05}).
 */
public final class EvidenceVerifier {

    private static final ObjectMapper CANON = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    private static final ObjectMapper PARSER = new ObjectMapper();

    private EvidenceVerifier() {
    }

    /**
     * @param wellFormed the file parsed and carried an integrity block
     * @param hashOk     the SHA-256 over the payload matches
     * @param hmacOk     the HMAC matches (proves it came from the real build)
     * @param code       verification code recomputed from the payload
     * @param detail     human explanation
     */
    public record Result(boolean wellFormed, boolean hashOk, boolean hmacOk,
                         String code, String detail) {
        public boolean authentic() {
            return wellFormed && hashOk && hmacOk;
        }
    }

    @SuppressWarnings("unchecked")
    public static Result verify(byte[] json) {
        if (json == null || json.length == 0) {
            return new Result(false, false, false, null, "empty file");
        }
        try {
            Map<String, Object> full = PARSER.readValue(json, Map.class);
            Object integrityObj = full.remove("integrity");
            if (!(integrityObj instanceof Map)) {
                return new Result(false, false, false, null,
                        "no integrity block — not a Moon evidence bundle");
            }
            Map<String, Object> integrity = (Map<String, Object>) integrityObj;

            // re-serialise the remaining payload exactly as JsonReport does
            byte[] canonical = CANON.writeValueAsBytes(new TreeMap<>(full));
            String sha = Integrity.sha256Hex(canonical);
            String hmac = Integrity.hmacHex(canonical);
            String code = Integrity.shortCode(canonical);

            boolean hashOk = sha.equalsIgnoreCase(str(integrity.get("sha256")));
            boolean hmacOk = hmac.equalsIgnoreCase(str(integrity.get("hmac")));

            String detail;
            if (hashOk && hmacOk) {
                detail = "authentic and unmodified";
            } else if (!hashOk) {
                detail = "CONTENT MODIFIED — the report no longer matches its own hash";
            } else {
                detail = "HMAC mismatch — not produced by this build (or key rotated)";
            }
            return new Result(true, hashOk, hmacOk, code, detail);
        } catch (Exception e) {
            return new Result(false, false, false, null, "unreadable JSON: " + e.getMessage());
        }
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString();
    }
}

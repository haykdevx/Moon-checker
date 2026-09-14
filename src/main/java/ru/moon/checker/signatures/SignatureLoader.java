package ru.moon.checker.signatures;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Loads the signature database. The rules bundled inside the jar are always
 * available; if an {@code signatures.json} sits next to the executable it is
 * used <em>instead</em>, so admins can update detections without a rebuild.
 */
public final class SignatureLoader {

    public static final String RESOURCE = "/signatures.json";
    public static final String OVERRIDE_FILE = "signatures.json";

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private SignatureLoader() {
    }

    /** Result of a load, including where the rules came from (shown in UI). */
    public record Result(SignatureDb db, String origin, String error) {
    }

    public static Result load(Path exeDir) {
        // 1. external override next to the exe
        if (exeDir != null) {
            Path external = exeDir.resolve(OVERRIDE_FILE);
            if (Files.isRegularFile(external)) {
                try {
                    SignatureDb db = MAPPER.readValue(external.toFile(), SignatureDb.class);
                    return new Result(db, "external:" + external, null);
                } catch (Exception e) {
                    // fall through to bundled, but report why the override failed
                    return loadBundled("external file invalid: " + e.getMessage());
                }
            }
        }
        return loadBundled(null);
    }

    private static Result loadBundled(String priorError) {
        try (InputStream in = SignatureLoader.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return new Result(SignatureDb.empty(), "none", "bundled signatures.json missing");
            }
            SignatureDb db = MAPPER.readValue(in, SignatureDb.class);
            return new Result(db, "bundled", priorError);
        } catch (Exception e) {
            return new Result(SignatureDb.empty(), "none", "bundled parse error: " + e.getMessage());
        }
    }
}

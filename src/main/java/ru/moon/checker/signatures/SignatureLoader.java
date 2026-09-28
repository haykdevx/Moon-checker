package ru.moon.checker.signatures;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import ru.moon.checker.core.Integrity;
import ru.moon.checker.core.RulesProvenance;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Loads the detection rules. The rules bundled inside the build are the default.
 * A {@code signatures.json} next to the checker replaces them only if
 * {@code signatures.json.sig} holds a valid Ed25519 signature over its exact bytes
 * by a key in {@code rules-keys.txt}, and its version is not older than the bundled
 * one. Anything else is ignored and noted — otherwise a player could drop an empty
 * rule file next to the checker and every scan would find nothing.
 */
public final class SignatureLoader {

    public static final String RESOURCE = "/signatures.json";
    public static final String OVERRIDE_FILE = "signatures.json";
    public static final String SIGNATURE_FILE = "signatures.json.sig";
    private static final String KEYS_RESOURCE = "/rules-keys.txt";
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private SignatureLoader() {
    }

    /** Result of a load: the rules, their provenance, and any problem worth logging. */
    public record Result(SignatureDb db, RulesProvenance provenance, String error) {
        public String origin() {
            return provenance.origin();
        }
    }

    public static Result load(Path exeDir) {
        return load(exeDir, trustedKeys());
    }

    static Result load(Path exeDir, List<PublicKey> keys) {
        Result bundled = loadBundled();
        if (exeDir == null) {
            return bundled;
        }
        Path external = exeDir.resolve(OVERRIDE_FILE);
        if (!Files.isRegularFile(external)) {
            return bundled;
        }
        String why;
        try {
            byte[] bytes = Files.readAllBytes(external);
            Path sigFile = exeDir.resolve(SIGNATURE_FILE);
            if (!Files.isRegularFile(sigFile)) {
                why = "unsigned " + OVERRIDE_FILE + " next to the checker was ignored";
            } else if (!verify(bytes, Files.readString(sigFile, StandardCharsets.US_ASCII).strip(), keys)) {
                why = OVERRIDE_FILE + " next to the checker has an invalid signature and was ignored";
            } else {
                SignatureDb db = MAPPER.readValue(bytes, SignatureDb.class);
                if (compareVersions(db.version(), bundled.db().version()) < 0) {
                    why = "signed " + OVERRIDE_FILE + " v" + db.version() + " is older than the bundled v"
                            + bundled.db().version() + " and was ignored";
                } else {
                    return new Result(db, new RulesProvenance("signed-override", Integrity.sha256Hex(bytes),
                            db.ruleCount(), null), null);
                }
            }
        } catch (Exception e) {
            why = OVERRIDE_FILE + " next to the checker could not be read: " + e.getMessage();
        }
        RulesProvenance p = bundled.provenance();
        return new Result(bundled.db(), new RulesProvenance(p.origin(), p.digest(), p.count(), why), why);
    }

    private static Result loadBundled() {
        try (InputStream in = SignatureLoader.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return none("bundled signatures.json missing");
            }
            byte[] bytes = in.readAllBytes();
            SignatureDb db = MAPPER.readValue(bytes, SignatureDb.class);
            return new Result(db, new RulesProvenance("bundled", Integrity.sha256Hex(bytes), db.ruleCount(), null),
                    null);
        } catch (Exception e) {
            return none("bundled parse error: " + e.getMessage());
        }
    }

    private static Result none(String why) {
        return new Result(SignatureDb.empty(), new RulesProvenance("none", "", 0, why), why);
    }

    static boolean verify(byte[] data, String signatureB64, List<PublicKey> keys) {
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(signatureB64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        for (PublicKey key : keys) {
            try {
                Signature v = Signature.getInstance("Ed25519");
                v.initVerify(key);
                v.update(data);
                if (v.verify(sig)) {
                    return true;
                }
            } catch (Exception ignored) {
                // wrong key type or malformed signature: try the next key
            }
        }
        return false;
    }

    static List<PublicKey> trustedKeys() {
        List<PublicKey> keys = new ArrayList<>();
        try (InputStream in = SignatureLoader.class.getResourceAsStream(KEYS_RESOURCE)) {
            if (in == null) {
                return keys;
            }
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            for (String line : new String(in.readAllBytes(), StandardCharsets.US_ASCII).split("\\R")) {
                String l = line.strip();
                if (!l.isEmpty() && !l.startsWith("#")) {
                    keys.add(kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(l))));
                }
            }
        } catch (Exception e) {
            return List.of(); // no usable keys: overrides are never accepted
        }
        return keys;
    }

    /** Compares versions like "2026.09.14-cs2": numeric parts numerically, others as text. */
    static int compareVersions(String a, String b) {
        String[] x = a.split("[.\\-]");
        String[] y = b.split("[.\\-]");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            String p = i < x.length ? x[i] : "";
            String q = i < y.length ? y[i] : "";
            int c;
            if (p.matches("\\d+") && q.matches("\\d+")) {
                c = Long.compare(Long.parseLong(p), Long.parseLong(q));
            } else {
                c = p.compareTo(q);
            }
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }
}

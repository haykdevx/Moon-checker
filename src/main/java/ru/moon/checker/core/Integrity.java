package ru.moon.checker.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Integrity signing for evidence bundles.
 *
 * <p>A SHA-256 of the canonical JSON detects any edit to a saved report; an
 * HMAC-SHA256 with a shared key lets the server verify that a report was
 * produced by the official checker and not altered. The key is embedded in the
 * build, so this deters casual forgery rather than a determined attacker — the
 * point is that a screenshot or a copy-pasted, hand-edited report no longer
 * matches its verification code, and the server (holding the same key) can
 * confirm a submitted JSON is authentic.
 *
 * <p>To rotate the key: change {@link #KEY} here and on the server, rebuild.
 */
public final class Integrity {

    /** Shared HMAC key. Keep the server copy identical. */
    public static final String KEY = "moon-cs2-2026::integrity::v1";

    private Integrity() {
    }

    public static String sha256Hex(byte[] data) {
        try {
            return Hashing.toHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            return "";
        }
    }

    public static String hmacHex(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Hashing.toHex(mac.doFinal(data));
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Short human-readable verification code shown on screen and in the report,
     * derived from the HMAC. Grouped for easy reading over a screen share, e.g.
     * {@code 7F3A-9C21-B4}.
     */
    public static String shortCode(byte[] canonical) {
        String hmac = hmacHex(canonical).toUpperCase();
        if (hmac.length() < 10) {
            return "----";
        }
        String s = hmac.substring(0, 10);
        return s.substring(0, 4) + "-" + s.substring(4, 8) + "-" + s.substring(8, 10);
    }
}

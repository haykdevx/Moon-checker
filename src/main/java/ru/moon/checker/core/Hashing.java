package ru.moon.checker.core;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

/** SHA-256 helpers used for file signature matching and the self-hash badge. */
public final class Hashing {

    private Hashing() {
    }

    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return toHex(md.digest(data));
        } catch (Exception e) {
            return null;
        }
    }

    /** Streaming SHA-256 of a file; null on any error. */
    public static String sha256File(Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            return toHex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * SHA-256 of the running program's own jar/exe, first 12 hex chars, so the
     * admin can confirm the player launched the official unmodified build.
     */
    public static String selfHashShort() {
        try {
            Path self = Path.of(Hashing.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            if (Files.isRegularFile(self)) {
                String full = sha256File(self);
                return full != null ? full.substring(0, 12) : "unknown";
            }
            return "dev-run";
        } catch (Exception e) {
            return "unknown";
        }
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}

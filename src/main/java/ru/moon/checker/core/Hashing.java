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

    private static volatile String selfFull;

    /**
     * SHA-256 of the running program's own jar/exe, first 12 hex chars, so the
     * admin can confirm the player launched the official unmodified build.
     */
    public static String selfHashShort() {
        String full = selfHashFull();
        return full.isEmpty() ? (isDevRun() ? "dev-run" : "unknown") : full.substring(0, 12);
    }

    /**
     * Full SHA-256 of the running jar/exe (computed once), or "" for a dev run
     * from class folders. The panel matches it against its trusted build list.
     */
    public static String selfHashFull() {
        String v = selfFull;
        if (v == null) {
            v = "";
            try {
                Path self = selfPath();
                if (self != null && Files.isRegularFile(self)) {
                    String full = sha256File(self);
                    v = full != null ? full : "";
                }
            } catch (Exception ignored) {
                // leave empty
            }
            selfFull = v;
        }
        return v;
    }

    private static boolean isDevRun() {
        Path self = selfPath();
        return self != null && Files.isDirectory(self);
    }

    private static Path selfPath() {
        try {
            return Path.of(Hashing.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception e) {
            return null;
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

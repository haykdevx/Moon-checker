package ru.moon.checker.parse;

import java.time.Instant;

/**
 * Decoder for HKCU UserAssist entries
 * ({@code ...\Explorer\UserAssist\{GUID}\Count}). Value names are ROT13-encoded
 * program paths; the binary value data carries a run count and the last
 * execution time (FILETIME). UserAssist is one of the strongest "this program
 * was actually launched by the user" artefacts.
 */
public final class UserAssist {

    private UserAssist() {
    }

    public record Entry(String path, int runCount, Instant lastRun) {
    }

    /** ROT13 decode the value name into a readable path. */
    public static String decodeName(String encoded) {
        if (encoded == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(encoded.length());
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            if (c >= 'a' && c <= 'z') {
                sb.append((char) ('a' + (c - 'a' + 13) % 26));
            } else if (c >= 'A' && c <= 'Z') {
                sb.append((char) ('A' + (c - 'A' + 13) % 26));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Parse a UserAssist Count entry. {@code data} is the raw registry value;
     * the Win7+ layout puts run count at offset 4 and the last-run FILETIME at
     * offset 60. Returns an entry with best-effort fields (nulls / zero if the
     * blob is too small).
     */
    public static Entry parse(String encodedName, byte[] data) {
        String path = decodeName(encodedName);
        int runCount = 0;
        Instant lastRun = null;
        if (data != null && data.length >= 68) {
            runCount = u32(data, 4);
            long filetime = u64(data, 60);
            lastRun = fileTimeToInstant(filetime);
        }
        return new Entry(path, runCount, lastRun);
    }

    /** Windows FILETIME (100ns since 1601-01-01 UTC) to Instant, or null. */
    public static Instant fileTimeToInstant(long filetime) {
        if (filetime <= 0) {
            return null;
        }
        // 11644473600 seconds between 1601-01-01 and 1970-01-01
        long millis = filetime / 10_000L - 11_644_473_600_000L;
        if (millis < 0 || millis > 4_102_444_800_000L) { // sanity: before year 2100
            return null;
        }
        return Instant.ofEpochMilli(millis);
    }

    private static int u32(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8)
                | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }

    private static long u64(byte[] d, int o) {
        long lo = u32(d, o) & 0xFFFFFFFFL;
        long hi = u32(d, o + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }
}

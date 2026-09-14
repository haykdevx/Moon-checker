package ru.moon.checker.parse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Full Prefetch (.pf) parser: unwraps the Windows 8+ {@code MAM} container via
 * {@link Xpress} and reads the SCCA body.
 *
 * <p>The body is the valuable part that filename-only parsing misses:
 * <ul>
 *   <li><b>the filename strings array</b> — every file/DLL the program loaded
 *       during startup, so a CS2 process that loaded a cheat DLL is provable
 *       even after the DLL is deleted, and</li>
 *   <li><b>the run timestamps</b> — the last 8 executions (1 on Windows 7).</li>
 * </ul>
 *
 * Fully defensive: any malformed or truncated input yields {@code null} rather
 * than an exception.
 */
public final class PrefetchBody {

    /** Refuse absurd decompressed sizes (a .pf is normally well under 1 MB). */
    private static final int MAX_DECOMPRESSED = 32 * 1024 * 1024;
    private static final int FILE_INFO_OFFSET = 84;

    private PrefetchBody() {
    }

    public record Body(int version, String exeName, List<Instant> runTimes, List<String> loadedFiles) {
        /** Most recent run time, or null when none is recorded. */
        public Instant lastRun() {
            Instant best = null;
            for (Instant i : runTimes) {
                if (i != null && (best == null || i.isAfter(best))) {
                    best = i;
                }
            }
            return best;
        }
    }

    public static Body parse(byte[] raw) {
        try {
            byte[] scca = unwrap(raw);
            if (scca == null || scca.length < FILE_INFO_OFFSET + 48) {
                return null;
            }
            if (scca[4] != 'S' || scca[5] != 'C' || scca[6] != 'C' || scca[7] != 'A') {
                return null;
            }
            int version = u32(scca, 0);

            String exeName = utf16(scca, 16, 60);

            int fnOffset = u32(scca, FILE_INFO_OFFSET + 16);
            int fnSize = u32(scca, FILE_INFO_OFFSET + 20);
            List<String> loaded = readFilenames(scca, fnOffset, fnSize);

            List<Instant> times = readRunTimes(scca, version);

            return new Body(version, exeName, times, loaded);
        } catch (Exception e) { // includes Xpress.FormatException (unchecked)
            return null;
        }
    }

    /** Strip the MAM container (Win8+) if present, returning raw SCCA bytes. */
    static byte[] unwrap(byte[] raw) {
        if (raw == null || raw.length < 8) {
            return null;
        }
        if (raw[0] == 'M' && raw[1] == 'A' && raw[2] == 'M') {
            int size = u32(raw, 4);
            if (size <= 0 || size > MAX_DECOMPRESSED) {
                return null;
            }
            return Xpress.decompressHuffman(raw, 8, size);
        }
        return raw;
    }

    private static List<String> readFilenames(byte[] d, int offset, int size) {
        List<String> out = new ArrayList<>();
        if (offset <= 0 || size <= 0 || offset + size > d.length) {
            return out;
        }
        String block = new String(d, offset, size, StandardCharsets.UTF_16LE);
        for (String s : block.split("\0")) {
            String t = s.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    /**
     * Windows 8 and later store 8 FILETIMEs at file-info offset 44; Windows 7
     * (version 23) stores a single one at the same place.
     */
    private static List<Instant> readRunTimes(byte[] d, int version) {
        List<Instant> out = new ArrayList<>();
        int base = FILE_INFO_OFFSET + 44;
        int count = version >= 26 ? 8 : 1;
        for (int i = 0; i < count; i++) {
            int o = base + i * 8;
            if (o + 8 > d.length) {
                break;
            }
            Instant t = UserAssist.fileTimeToInstant(u64(d, o));
            if (t != null) {
                out.add(t);
            }
        }
        return out;
    }

    private static String utf16(byte[] d, int off, int maxBytes) {
        if (off < 0 || off + maxBytes > d.length) {
            return "";
        }
        String s = new String(d, off, maxBytes, StandardCharsets.UTF_16LE);
        int nul = s.indexOf('\0');
        return (nul >= 0 ? s.substring(0, nul) : s).trim();
    }

    private static int u32(byte[] d, int o) {
        if (o + 4 > d.length) {
            return 0;
        }
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8)
                | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }

    private static long u64(byte[] d, int o) {
        long lo = u32(d, o) & 0xFFFFFFFFL;
        long hi = u32(d, o + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }
}

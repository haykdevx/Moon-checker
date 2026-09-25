package ru.moon.checker.parse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Full Prefetch ({@code .pf}) body parser: the executable name, run count, up
 * to eight last-run times, every file the program loaded in its first seconds
 * (DLLs included) and the volumes involved.
 *
 * <p>Windows 10/11 store the body in a {@code MAM} container compressed with
 * LZXpress-Huffman ({@link XpressHuffman}); older systems store the {@code SCCA}
 * structure directly. Both are accepted. Supported SCCA versions: 17 (XP/2003),
 * 23 (Vista/7), 26 (8.1), 30 (10) and 31 (11), including both version-30 file
 * information layouts (run count at 0xD0 or 0xC8).
 *
 * <p>Defensive: any malformed input yields {@code null}; counts, offsets and
 * lengths from the file are bounds-checked and capped.
 */
public final class PrefetchBody {

    static final int MAM_SIGNATURE = 0x004D414D;   // "MAM" + format byte
    static final int FORMAT_XPRESS_HUFF = 4;
    static final int SCCA_SIGNATURE = 0x41434353;  // "SCCA"
    private static final int MAX_ENTRIES = 65_536;

    private PrefetchBody() {
    }

    /** A volume the program touched. */
    public record Volume(String devicePath, long serialNumber, Instant created) {
    }

    /**
     * Parsed Prefetch body.
     *
     * @param version     SCCA format version
     * @param exeName     executable name as recorded (upper case, at most 29 chars)
     * @param hash        prefetch hash, 8 upper-case hex digits (the part after '-' in the file name)
     * @param runCount    times the program ran
     * @param lastRuns    last run times, most recent first (1 for versions below 26, up to 8 otherwise)
     * @param loadedFiles every file referenced by the trace, e.g. {@code \VOLUME{..}\WINDOWS\SYSTEM32\NTDLL.DLL}
     * @param volumes     volumes the files live on
     */
    public record Info(int version, String exeName, String hash, int runCount,
                       List<Instant> lastRuns, List<String> loadedFiles, List<Volume> volumes) {
        public Instant lastRun() {
            return lastRuns.isEmpty() ? null : lastRuns.get(0);
        }
    }

    private static final Pattern VOLUME_PATH =
            Pattern.compile("^\\\\VOLUME\\{[0-9A-Fa-f]+-([0-9A-Fa-f]{8})}(\\\\.*)?$");

    /**
     * Rewrites {@code \VOLUME{01dd442b53987e73-ae53a35e}\USERS\X.DLL} to
     * {@code C:\USERS\X.DLL} when the serial ({@code ae53a35e}) belongs to a known
     * drive; other paths are returned unchanged.
     */
    public static String toDrivePath(String path, Map<Long, Character> serialToLetter) {
        if (path == null) {
            return null;
        }
        Matcher m = VOLUME_PATH.matcher(path);
        if (!m.matches()) {
            return path;
        }
        Character letter = serialToLetter.get(Long.parseLong(m.group(1), 16));
        if (letter == null) {
            return path;
        }
        return letter + ":" + (m.group(2) == null ? "\\" : m.group(2));
    }

    /** Parse a whole .pf file (compressed or not); null when it is not a valid Prefetch file. */
    public static Info parse(byte[] pf) {
        byte[] scca = uncompressed(pf);
        return scca == null ? null : parseScca(scca);
    }

    /** The SCCA bytes of a .pf file: decompressed MAM payload, or the file itself if not compressed. */
    static byte[] uncompressed(byte[] pf) {
        if (pf == null || pf.length < 8) {
            return null;
        }
        if (u32(pf, 4) == SCCA_SIGNATURE) {
            return pf;
        }
        int sig = u32(pf, 0);
        if ((sig & 0x00FFFFFF) != MAM_SIGNATURE || (sig >>> 24 & 0x0F) != FORMAT_XPRESS_HUFF) {
            return null;
        }
        boolean hasChecksum = (sig >>> 24 & 0x80) != 0;
        int dataStart = hasChecksum ? 12 : 8;
        long size = u32(pf, 4) & 0xFFFFFFFFL;
        if (size < 84 || size > XpressHuffman.MAX_OUTPUT || pf.length <= dataStart) {
            return null;
        }
        return XpressHuffman.decompress(pf, dataStart, pf.length - dataStart, (int) size);
    }

    static Info parseScca(byte[] d) {
        try {
            if (d.length < 156 || u32(d, 4) != SCCA_SIGNATURE) {
                return null;
            }
            int version = u32(d, 0);
            if (version != 17 && version != 23 && version != 26 && version != 30 && version != 31) {
                return null;
            }
            String exe = utf16z(d, 16, 60);
            String hash = String.format(Locale.ROOT, "%08X", u32(d, 76));

            int metricsOffset = u32(d, 84);
            int metricsCount = u32(d, 88);
            int stringsOffset = u32(d, 100);
            int stringsSize = u32(d, 104);
            int volumesOffset = u32(d, 108);
            int volumesCount = u32(d, 112);

            List<Instant> lastRuns = new ArrayList<>();
            int runCount;
            if (version == 17) {
                addTime(lastRuns, d, 120);
                runCount = u32(d, 144);
            } else if (version == 23) {
                addTime(lastRuns, d, 128);
                runCount = u32(d, 152);
            } else {
                for (int i = 0; i < 8; i++) {
                    addTime(lastRuns, d, 128 + i * 8);
                }
                // version 30 "variant 2" (Windows 10 1903+) and 31 shrank the file-information block by 8 bytes
                runCount = u32(d, metricsOffset == 0x128 ? 200 : 208);
            }

            List<String> files = loadedFiles(d, version, metricsOffset, metricsCount, stringsOffset, stringsSize);
            List<Volume> volumes = volumes(d, version, volumesOffset, volumesCount);
            return new Info(version, exe, hash, Math.max(0, runCount), List.copyOf(lastRuns),
                    List.copyOf(files), List.copyOf(volumes));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static List<String> loadedFiles(byte[] d, int version, int metricsOffset, int count,
                                            int stringsOffset, int stringsSize) {
        List<String> out = new ArrayList<>();
        if (!inside(d, stringsOffset, stringsSize) || count < 0 || count > MAX_ENTRIES) {
            return out;
        }
        int entrySize = version == 17 ? 20 : 32;
        int nameOffField = version == 17 ? 8 : 12;
        if (inside(d, metricsOffset, (long) count * entrySize)) {
            for (int i = 0; i < count; i++) {
                int e = metricsOffset + i * entrySize;
                int nameOff = u32(d, e + nameOffField);
                int nameChars = u32(d, e + nameOffField + 4);
                if (nameOff >= 0 && nameChars > 0 && nameChars < 32_768
                        && (long) nameOff + nameChars * 2L <= stringsSize) {
                    out.add(new String(d, stringsOffset + nameOff, nameChars * 2, StandardCharsets.UTF_16LE));
                }
            }
            if (!out.isEmpty()) {
                return out;
            }
        }
        // metrics unusable: fall back to splitting the NUL-separated string block
        String block = new String(d, stringsOffset, stringsSize & ~1, StandardCharsets.UTF_16LE);
        for (String s : block.split("\0")) {
            if (!s.isEmpty() && out.size() < MAX_ENTRIES) {
                out.add(s);
            }
        }
        return out;
    }

    private static List<Volume> volumes(byte[] d, int version, int offset, int count) {
        List<Volume> out = new ArrayList<>();
        int entrySize = version == 17 ? 40 : version == 30 || version == 31 ? 96 : 104;
        if (count <= 0 || count > 64 || !inside(d, offset, (long) count * entrySize)) {
            return out;
        }
        for (int i = 0; i < count; i++) {
            int e = offset + i * entrySize;
            int pathOff = u32(d, e);
            int pathChars = u32(d, e + 4);
            String path = null;
            if (pathChars > 0 && pathChars < 1024 && inside(d, offset + (long) pathOff, pathChars * 2L)) {
                path = new String(d, offset + pathOff, pathChars * 2, StandardCharsets.UTF_16LE);
            }
            Instant created = UserAssist.fileTimeToInstant(u64(d, e + 8));
            long serial = u32(d, e + 16) & 0xFFFFFFFFL;
            out.add(new Volume(path, serial, created));
        }
        return out;
    }

    private static void addTime(List<Instant> out, byte[] d, int off) {
        Instant t = UserAssist.fileTimeToInstant(u64(d, off));
        if (t != null) {
            out.add(t);
        }
    }

    private static boolean inside(byte[] d, long off, long len) {
        return off >= 0 && len >= 0 && off + len <= d.length;
    }

    private static String utf16z(byte[] d, int off, int maxChars) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxChars && off + i * 2 + 1 < d.length; i++) {
            char c = (char) ((d[off + i * 2] & 0xFF) | ((d[off + i * 2 + 1] & 0xFF) << 8));
            if (c == 0) {
                break;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static int u32(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8) | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }

    private static long u64(byte[] d, int o) {
        return (u32(d, o) & 0xFFFFFFFFL) | ((long) u32(d, o + 4) << 32);
    }
}

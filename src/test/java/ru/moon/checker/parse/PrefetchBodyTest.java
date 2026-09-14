package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/** Crafted (uncompressed) SCCA bodies; the MAM path is covered by XpressTest. */
class PrefetchBodyTest {

    private static final int FILE_INFO = 84;
    private static final int FN_OFFSET = 256;

    private static void putU32(byte[] d, int o, int v) {
        for (int i = 0; i < 4; i++) {
            d[o + i] = (byte) (v >>> (8 * i));
        }
    }

    private static void putU64(byte[] d, int o, long v) {
        for (int i = 0; i < 8; i++) {
            d[o + i] = (byte) (v >>> (8 * i));
        }
    }

    private static long fileTime(long epochMillis) {
        return (epochMillis + 11_644_473_600_000L) * 10_000L;
    }

    /** Build a version-30 SCCA with the given loaded-file list. */
    private static byte[] scca(int version, String exeName, long lastRunMillis, String... files) {
        StringBuilder sb = new StringBuilder();
        for (String f : files) {
            sb.append(f).append('\0');
        }
        byte[] names = sb.toString().getBytes(StandardCharsets.UTF_16LE);
        byte[] d = new byte[FN_OFFSET + names.length];

        putU32(d, 0, version);
        d[4] = 'S';
        d[5] = 'C';
        d[6] = 'C';
        d[7] = 'A';
        byte[] exe = exeName.getBytes(StandardCharsets.UTF_16LE);
        System.arraycopy(exe, 0, d, 16, Math.min(exe.length, 58));

        putU32(d, FILE_INFO + 16, FN_OFFSET);       // filename strings offset
        putU32(d, FILE_INFO + 20, names.length);    // filename strings size
        putU64(d, FILE_INFO + 44, fileTime(lastRunMillis)); // most recent run time
        System.arraycopy(names, 0, d, FN_OFFSET, names.length);
        return d;
    }

    @Test
    void parsesLoadedFilesAndRunTime() {
        byte[] pf = scca(30, "CS2.EXE", 1609459200000L,
                "\\DEVICE\\HARDDISKVOLUME3\\GAME\\CS2.EXE",
                "\\DEVICE\\HARDDISKVOLUME3\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                "\\DEVICE\\HARDDISKVOLUME3\\USERS\\P\\APPDATA\\LOCAL\\TEMP\\NIXWARE.DLL");

        PrefetchBody.Body body = PrefetchBody.parse(pf);
        assertNotNull(body);
        assertEquals(30, body.version());
        assertEquals("CS2.EXE", body.exeName());
        assertEquals(3, body.loadedFiles().size());
        assertTrue(body.loadedFiles().stream().anyMatch(f -> f.endsWith("NIXWARE.DLL")));
        assertEquals(Instant.parse("2021-01-01T00:00:00Z"), body.lastRun());
    }

    @Test
    void windows7SingleRunTime() {
        byte[] pf = scca(23, "LOADER.EXE", 1609459200000L, "\\DEVICE\\X\\LOADER.EXE");
        PrefetchBody.Body body = PrefetchBody.parse(pf);
        assertNotNull(body);
        assertEquals(1, body.runTimes().size());
        assertEquals("LOADER.EXE", body.exeName());
    }

    @Test
    void rejectsNonScca() {
        assertNull(PrefetchBody.parse(new byte[200]));
        assertNull(PrefetchBody.parse("not a prefetch file".getBytes(StandardCharsets.US_ASCII)));
        assertNull(PrefetchBody.parse(null));
    }

    @Test
    void unwrapPassesThroughUncompressed() {
        byte[] pf = scca(30, "A.EXE", 1609459200000L, "\\DEVICE\\X\\A.EXE");
        assertSame(pf, PrefetchBody.unwrap(pf));
    }

    @Test
    void rejectsAbsurdMamSize() {
        byte[] mam = new byte[64];
        mam[0] = 'M';
        mam[1] = 'A';
        mam[2] = 'M';
        mam[3] = 0x04;
        putU32(mam, 4, Integer.MAX_VALUE); // absurd decompressed size
        assertNull(PrefetchBody.unwrap(mam));
    }
}

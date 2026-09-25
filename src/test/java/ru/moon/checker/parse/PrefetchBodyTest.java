package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PrefetchBodyTest {

    static final Instant RUN1 = Instant.parse("2026-09-01T10:00:00Z");
    static final Instant RUN2 = Instant.parse("2026-08-30T21:15:30Z");
    static final List<String> FILES = List.of(
            "\\VOLUME{01dc2b1a3f5e7d90-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
            "\\VOLUME{01dc2b1a3f5e7d90-1a2b3c4d}\\USERS\\ИГРОК\\DOWNLOADS\\NIXWARE.DLL",
            "\\VOLUME{01dc2b1a3f5e7d90-1a2b3c4d}\\PROGRAM FILES (X86)\\STEAM\\CS2.EXE");

    static long filetime(Instant t) {
        return (t.toEpochMilli() + 11_644_473_600_000L) * 10_000L;
    }

    /**
     * Builds an SCCA structure the way Windows lays it out.
     *
     * @param version       17, 23, 26, 30 or 31
     * @param metricsOffset 0x130 (v26 / v30 variant 1), 0x128 (v30 variant 2 / v31), 0xF0 (v23), 0x9C (v17)
     */
    static byte[] scca(int version, int metricsOffset) {
        int entry = version == 17 ? 20 : 32;
        int volEntry = version == 17 ? 40 : version >= 30 ? 96 : 104;
        byte[] strings = String.join("\0", FILES).concat("\0").getBytes(StandardCharsets.UTF_16LE);
        int stringsOffset = metricsOffset + FILES.size() * entry;
        int volumesOffset = stringsOffset + strings.length;
        byte[] devicePath = "\\DEVICE\\HARDDISKVOLUME3".getBytes(StandardCharsets.UTF_16LE);
        int size = volumesOffset + volEntry + devicePath.length + 8;

        ByteBuffer b = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0, version).putInt(4, 0x41434353).putInt(12, size);
        byte[] exe = "CS2.EXE".getBytes(StandardCharsets.UTF_16LE);
        b.put(16, exe);
        b.putInt(76, 0x1A2B3C4D);
        b.putInt(84, metricsOffset).putInt(88, FILES.size());
        b.putInt(100, stringsOffset).putInt(104, strings.length);
        b.putInt(108, volumesOffset).putInt(112, 1).putInt(116, volEntry + devicePath.length);
        if (version == 17) {
            b.putLong(120, filetime(RUN1)).putInt(144, 5);
        } else if (version == 23) {
            b.putLong(128, filetime(RUN1)).putInt(152, 5);
        } else {
            b.putLong(128, filetime(RUN1)).putLong(136, filetime(RUN2));
            b.putInt(metricsOffset == 0x128 ? 200 : 208, 5);
        }
        int nameOff = 0;
        for (int i = 0; i < FILES.size(); i++) {
            int e = metricsOffset + i * entry;
            int field = version == 17 ? 8 : 12;
            b.putInt(e + field, nameOff).putInt(e + field + 4, FILES.get(i).length());
            nameOff += (FILES.get(i).length() + 1) * 2;
        }
        b.put(stringsOffset, strings);
        b.putInt(volumesOffset, volEntry).putInt(volumesOffset + 4, devicePath.length / 2);
        b.putLong(volumesOffset + 8, filetime(RUN2)).putInt(volumesOffset + 16, 0xDEADBEEF);
        b.put(volumesOffset + volEntry, devicePath);
        return b.array();
    }

    static byte[] mam(byte[] scca) {
        byte[] packed = XpressTestEncoder.compress(scca, true);
        ByteBuffer b = ByteBuffer.allocate(8 + packed.length).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0x044D414D).putInt(scca.length).put(packed);
        return b.array();
    }

    @Test
    void windows11CompressedPrefetch() {
        PrefetchBody.Info info = PrefetchBody.parse(mam(scca(31, 0x128)));
        assertNotNull(info);
        assertEquals(31, info.version());
        assertEquals("CS2.EXE", info.exeName());
        assertEquals("1A2B3C4D", info.hash());
        assertEquals(5, info.runCount());
        assertEquals(List.of(RUN1, RUN2), info.lastRuns());
        assertEquals(RUN1, info.lastRun());
        assertEquals(FILES, info.loadedFiles());
        assertEquals(1, info.volumes().size());
        assertEquals("\\DEVICE\\HARDDISKVOLUME3", info.volumes().get(0).devicePath());
        assertEquals(0xDEADBEEFL, info.volumes().get(0).serialNumber());
    }

    @Test
    void bothWindows10LayoutsReadTheRightRunCount() {
        assertEquals(5, PrefetchBody.parse(mam(scca(30, 0x130))).runCount());
        assertEquals(5, PrefetchBody.parse(mam(scca(30, 0x128))).runCount());
        assertEquals(5, PrefetchBody.parse(scca(26, 0x130)).runCount());
    }

    @Test
    void olderUncompressedVersions() {
        PrefetchBody.Info v23 = PrefetchBody.parse(scca(23, 0xF0));
        assertEquals(List.of(RUN1), v23.lastRuns());
        assertEquals(FILES, v23.loadedFiles());
        PrefetchBody.Info v17 = PrefetchBody.parse(scca(17, 0x9C));
        assertEquals(5, v17.runCount());
        assertEquals(FILES, v17.loadedFiles());
    }

    @Test
    void brokenMetricsFallBackToTheStringBlock() {
        byte[] d = scca(30, 0x128);
        ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN).putInt(84, 0x7FFF_FFF0); // metrics offset out of range
        assertEquals(FILES, PrefetchBody.parse(d).loadedFiles());
    }

    @Test
    void malformedInputYieldsNull() {
        assertNull(PrefetchBody.parse(null));
        assertNull(PrefetchBody.parse(new byte[10]));
        assertNull(PrefetchBody.parse("not a prefetch file at all, just text".getBytes()));
        byte[] unknownVersion = scca(30, 0x128);
        unknownVersion[0] = 99;
        assertNull(PrefetchBody.parse(unknownVersion));
        byte[] truncatedMam = mam(scca(31, 0x128));
        assertNull(PrefetchBody.parse(java.util.Arrays.copyOf(truncatedMam, 40)));
        byte[] hugeSize = mam(scca(31, 0x128));
        ByteBuffer.wrap(hugeSize).order(ByteOrder.LITTLE_ENDIAN).putInt(4, Integer.MAX_VALUE);
        assertNull(PrefetchBody.parse(hugeSize));
    }

    @Test
    void fuzzedStructuresNeverThrow() {
        java.util.Random r = new java.util.Random(9);
        byte[] base = scca(31, 0x128);
        for (int i = 0; i < 2000; i++) {
            byte[] d = base.clone();
            for (int k = 0; k < 6; k++) {
                d[84 + r.nextInt(d.length - 84)] = (byte) r.nextInt(256);
            }
            assertDoesNotThrow(() -> PrefetchBody.parse(d));
        }
    }
}

package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/** Decoder and parser checked against data produced by a real Windows 11 25H2 machine. */
class WindowsFixtureTest {

    static byte[] fixture(String name) throws Exception {
        try (InputStream in = WindowsFixtureTest.class.getResourceAsStream("/fixtures/windows11-25h2/" + name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    /** Same generator as the PowerShell capture script (LCG noise over UTF-16LE path words). */
    static byte[] windowsInput() {
        byte[] words = "\\VOLUME{01DC2B1A}\\WINDOWS\\SYSTEM32\\NTDLL.DLL|CS2.EXE|CLIENT.DLL|Проверка|"
                .getBytes(StandardCharsets.UTF_16LE);
        byte[] src = new byte[300_000];
        long seed = 12345;
        for (int i = 0; i < src.length; i++) {
            seed = (seed * 1103515245L + 12345L) & 0xFFFFFFFFL;
            src[i] = ((seed >>> 16) % 11) == 0 ? (byte) ((seed >>> 8) & 0xFF) : words[i % words.length];
        }
        return src;
    }

    @Test
    void decodesWhatRtlCompressBufferProduced() throws Exception {
        byte[] expected = windowsInput();
        assertArrayEquals(expected, XpressHuffman.decompress(fixture("xpress-fmt4.bin"), expected.length));
    }

    @Test
    void parsesRealWindows11Prefetch() throws Exception {
        PrefetchBody.Info cmd = PrefetchBody.parse(fixture("CMD.EXE-0BD30981.pf"));
        assertNotNull(cmd);
        assertEquals(31, cmd.version());
        assertEquals("CMD.EXE", cmd.exeName());
        assertEquals("0BD30981", cmd.hash(), "hash must match the file name");
        assertEquals(3, cmd.runCount());
        assertEquals(3, cmd.lastRuns().size());
        assertEquals(Instant.parse("2026-09-14T11:08:17.823Z"), cmd.lastRun());
        assertEquals(36, cmd.loadedFiles().size());
        assertTrue(cmd.loadedFiles().get(0).endsWith("\\WINDOWS\\SYSTEM32\\NTDLL.DLL"));
        assertEquals(2924716894L, cmd.volumes().get(0).serialNumber());

        PrefetchBody.Info ps = PrefetchBody.parse(fixture("POWERSHELL.EXE-CA1AE517.pf"));
        assertNotNull(ps);
        assertEquals("CA1AE517", ps.hash());
        assertEquals(10, ps.runCount());
        assertEquals(8, ps.lastRuns().size(), "Windows keeps the last 8 run times");
        assertEquals(203, ps.loadedFiles().size());
        assertTrue(ps.loadedFiles().stream().anyMatch(f -> f.endsWith("\\SYSTEM.MANAGEMENT.AUTOMATION.DLL")));
    }
}

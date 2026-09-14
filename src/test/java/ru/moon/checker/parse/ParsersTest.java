package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Byte-level tests for the forensic parsers, using crafted fixtures. */
class ParsersTest {

    // ---- BinStrings -------------------------------------------------------

    @Test
    void binStringsExtractsAsciiAndUtf16() {
        byte[] ascii = "xx\0dwEntityList\0yy".getBytes(StandardCharsets.US_ASCII);
        List<String> a = BinStrings.ascii(ascii, 4);
        assertTrue(a.contains("dwEntityList"));

        byte[] utf16 = "dwViewMatrix".getBytes(StandardCharsets.UTF_16LE);
        List<String> u = BinStrings.utf16le(utf16, 4);
        assertTrue(u.contains("dwViewMatrix"));
    }

    @Test
    void binStringsRespectsMinLength() {
        byte[] data = "ab\0abcdef".getBytes(StandardCharsets.US_ASCII);
        List<String> s = BinStrings.ascii(data, 4);
        assertFalse(s.contains("ab"));
        assertTrue(s.contains("abcdef"));
    }

    // ---- Prefetch ---------------------------------------------------------

    @Test
    void prefetchParsesExeAndHash() {
        Prefetch.Info info = Prefetch.fromFileName("NIXWARE.EXE-1A2B3C4D.pf");
        assertNotNull(info);
        assertEquals("NIXWARE.EXE", info.exeName());
        assertEquals("1A2B3C4D", info.hash());
        assertNull(Prefetch.fromFileName("notaprefetch.txt"));
    }

    // ---- Recycle Bin $I ---------------------------------------------------

    @Test
    void recycleBinParsesV2() {
        String path = "C:\\cheats\\loader.exe";
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        writeU64(b, 2);                 // version 2
        writeU64(b, 4096);              // file size
        writeU64(b, filetime(1600000000000L)); // deletion time
        writeU32(b, path.length() + 1); // name chars incl null
        b.writeBytes(path.getBytes(StandardCharsets.UTF_16LE));
        RecycleBin.Entry e = RecycleBin.parse(b.toByteArray());
        assertNotNull(e);
        assertEquals(path, e.originalPath());
        assertEquals(4096, e.fileSize());
        assertNotNull(e.deletedAt());
    }

    // ---- USN record -------------------------------------------------------

    @Test
    void usnParsesDeleteRecord() {
        String name = "nixware.dll";
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_16LE);
        int recordLen = 60 + nameBytes.length;
        byte[] buf = new byte[8 + recordLen];
        int base = 8; // leading cursor
        putU32(buf, base, recordLen);
        putU16(buf, base + 4, 2);      // major version
        putU64(buf, base + 8, 111);    // file ref
        putU64(buf, base + 16, 222);   // parent ref
        putU64(buf, base + 24, 333);   // usn
        putU64(buf, base + 32, filetime(1600000000000L));
        putU32(buf, base + 40, (int) Usn.REASON_FILE_DELETE);
        putU16(buf, base + 56, nameBytes.length);
        putU16(buf, base + 58, 60);
        System.arraycopy(nameBytes, 0, buf, base + 60, nameBytes.length);

        List<Usn.Record> recs = Usn.parseBuffer(buf, buf.length);
        assertEquals(1, recs.size());
        Usn.Record r = recs.get(0);
        assertEquals("nixware.dll", r.fileName());
        assertTrue(r.isDeleted());
        assertEquals(111, r.fileReference());
        assertEquals(222, r.parentReference());
    }

    // ---- LNK --------------------------------------------------------------

    @Test
    void lnkExtractsLocalTarget() {
        String target = "C:\\cheats\\loader.exe";
        byte[] targetBytes = target.getBytes(StandardCharsets.ISO_8859_1);
        int localBaseOff = 28;
        int suffixOff = localBaseOff + targetBytes.length + 1;
        int linkInfoSize = suffixOff + 1;

        byte[] lnk = new byte[76 + linkInfoSize];
        putU32(lnk, 0, 0x4C);          // HeaderSize
        putU32(lnk, 20, 0x02);         // flags: HasLinkInfo only
        int li = 76;
        putU32(lnk, li, linkInfoSize);
        putU32(lnk, li + 4, 0x1C);     // header size (< 0x24 -> ANSI)
        putU32(lnk, li + 8, 0x1);      // VolumeIDAndLocalBasePath
        putU32(lnk, li + 16, localBaseOff);
        putU32(lnk, li + 24, suffixOff);
        System.arraycopy(targetBytes, 0, lnk, li + localBaseOff, targetBytes.length);
        // suffix is an empty c-string (already 0)

        Lnk parsed = Lnk.parse(lnk);
        assertTrue(parsed.valid());
        assertEquals(target, parsed.targetPath());
    }

    // ---- ShellBag ---------------------------------------------------------

    @Test
    void shellBagFindsFolderName() {
        String folder = "cheats";
        byte[] name = folder.getBytes(StandardCharsets.UTF_16LE);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(new byte[8]);                 // filler
        b.writeBytes(new byte[]{0x04, 0x00, (byte) 0xEF, (byte) 0xBE}); // BEEF0004
        b.writeBytes(name);
        b.writeBytes(new byte[]{0, 0});            // terminator
        List<String> names = ShellBag.extractFolderNames(b.toByteArray());
        assertTrue(names.contains("cheats"), "expected 'cheats' in " + names);
    }

    // ---- PE ---------------------------------------------------------------

    @Test
    void peRejectsNonPe() {
        assertFalse(Pe.parse("not a pe file at all".getBytes()).isPe());
        assertFalse(Pe.parse(new byte[]{'M', 'Z'}).isPe());
        assertFalse(Pe.parse(new byte[10]).looksLikeInjector());
    }

    // ---- helpers ----------------------------------------------------------

    private static long filetime(long epochMillis) {
        return (epochMillis + 11_644_473_600_000L) * 10_000L;
    }

    private static void writeU32(ByteArrayOutputStream b, long v) {
        for (int i = 0; i < 4; i++) b.write((int) ((v >>> (8 * i)) & 0xFF));
    }

    private static void writeU64(ByteArrayOutputStream b, long v) {
        for (int i = 0; i < 8; i++) b.write((int) ((v >>> (8 * i)) & 0xFF));
    }

    private static void putU16(byte[] d, int o, int v) {
        d[o] = (byte) v;
        d[o + 1] = (byte) (v >>> 8);
    }

    private static void putU32(byte[] d, int o, int v) {
        for (int i = 0; i < 4; i++) d[o + i] = (byte) (v >>> (8 * i));
    }

    private static void putU64(byte[] d, int o, long v) {
        for (int i = 0; i < 8; i++) d[o + i] = (byte) (v >>> (8 * i));
    }
}

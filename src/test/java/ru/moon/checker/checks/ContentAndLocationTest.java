package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.core.TestResults;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;

import java.io.ByteArrayOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Review findings on the checker: locations were trusted by substring, content inspection
 * depended on the file extension (extensionless ELF files were never inspected), and walks
 * stopped at their limits without saying so. The fixtures here are harmless byte patterns:
 * they prove the plumbing, not that a real cheat would be detected.
 */
class ContentAndLocationTest {

    private static final SignatureDb DB = SignatureLoader.load(null).db();
    private static final Locations.Roots WIN = Locations.Roots.windows(Map.of("SystemRoot", "C:\\Windows",
            "ProgramFiles", "C:\\Program Files", "ProgramFiles(x86)", "C:\\Program Files (x86)",
            "ProgramData", "C:\\ProgramData", "SystemDrive", "C:"));

    // ---- locations --------------------------------------------------------------------------

    @Test
    void pathsAreNormalisedBeforeTheyAreCompared() {
        assertEquals("c:\\windows\\system32\\x.dll", Locations.normalize("\\\\?\\C:\\Windows\\.\\System32\\\\X.dll", true));
        assertEquals("c:\\windows\\x.dll", Locations.normalize("C:/Windows/System32/../x.dll", true));
        assertEquals("c:\\x.dll", Locations.normalize("C:\\..\\..\\x.dll", true), "never above the drive");
        assertEquals("\\\\server\\share\\x.exe", Locations.normalize("\\\\?\\UNC\\Server\\Share\\x.exe", true));
        assertNull(Locations.normalize("relative\\x.dll", true));
        assertEquals("/usr/lib/libc.so.6", Locations.normalize("/usr//lib/./x/../libc.so.6", false));
    }

    @Test
    void rootsMatchWholeFolderNamesOnly() {
        assertEquals(Locations.Kind.PROGRAM, kind("C:\\Program Files\\App\\app.exe"));
        assertEquals(Locations.Kind.OTHER, kind("C:\\Program Files Evil\\app.exe"), "a sibling sharing the prefix");
        assertEquals(Locations.Kind.OTHER, kind("C:\\WindowsApps2\\x.exe"));
        assertEquals(Locations.Kind.SYSTEM, kind("c:\\WINDOWS\\system32\\kernelbase.dll"));
    }

    @Test
    void anAllowedFragmentDeepInsideAUserFolderIsStillAUserFolder() {
        // review repro: substring "\steam\steamapps\common\" made this a trusted Steam file
        assertEquals(Locations.Kind.USER_WRITABLE, kind("C:\\Users\\p\\Downloads\\x\\steam\\steamapps\\common\\cheat.exe"));
        assertEquals(Locations.Kind.USER_WRITABLE, kind("C:\\Users\\p\\AppData\\Local\\Discord\\evil.dll"));
        assertEquals(Locations.Kind.USER_WRITABLE, kind("C:\\Users\\p\\Desktop\\Program Files\\x.exe"));
    }

    @Test
    void theMostSpecificRootWins() {
        assertEquals(Locations.Kind.USER_WRITABLE, kind("C:\\Windows\\Temp\\x.exe"));
        assertEquals(Locations.Kind.USER_WRITABLE, kind("C:\\Windows\\System32\\spool\\drivers\\color\\x.dll"));
        assertEquals(Locations.Kind.SYSTEM, kind("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x.dll"));
        assertEquals(Locations.Kind.USER_WRITABLE, kind("C:\\ProgramData\\Loader\\x.dll"));
        assertEquals(Locations.Kind.NETWORK, kind("\\\\nas\\games\\x.exe"));
        assertEquals(Locations.Kind.UNKNOWN, kind("x.exe"));
    }

    @Test
    void rootsComeFromTheMachineNotFromFixedLetters() {
        Locations.Roots d = Locations.Roots.windows(Map.of("SystemRoot", "D:\\Win", "SystemDrive", "D:"));
        assertEquals(Locations.Kind.SYSTEM, Locations.classify(Locations.normalize("D:\\Win\\System32\\x.dll", true), d));
        assertEquals(Locations.Kind.OTHER, Locations.classify(Locations.normalize("C:\\Windows\\System32\\x.dll", true), d),
                "C:\\Windows is just a folder on a PC whose Windows is on D:");
    }

    @Test
    void aLinkIntoAUserFolderIsJudgedByWhereItPoints(@TempDir Path tmp) throws Exception {
        Path prog = Files.createDirectories(tmp.resolve("prog"));
        Path user = Files.createDirectories(tmp.resolve("user"));
        Path payload = Files.writeString(user.resolve("payload.so"), "x");
        Path link;
        try {
            link = Files.createSymbolicLink(prog.resolve("lib.so"), payload);
        } catch (UnsupportedOperationException | java.io.IOException e) {
            assumeTrue(false, "symbolic links not available here");
            return;
        }
        Locations.Roots roots = Locations.Roots.of(false, Map.of(prog.toString(), Locations.Kind.PROGRAM,
                user.toString(), Locations.Kind.USER_WRITABLE));
        assertEquals(Locations.Kind.USER_WRITABLE, Locations.ofFile(link, roots));
        assertEquals(Locations.Kind.UNKNOWN, Locations.ofFile(prog.resolve("missing.so"), roots),
                "a protected location that cannot be confirmed is not trusted");
        Path mine = Files.writeString(prog.resolve("mine.so"), "x");
        assertEquals(Locations.Kind.UNKNOWN, Locations.ofFile(mine, roots),
                "Linux: a 'program folder' file owned by an ordinary user is not trusted");
    }

    @Test
    void realSystemFilesAreSystem() {
        Path ls = Path.of("/usr/bin/ls");
        assumeTrue(Files.isRegularFile(ls) && !ru.moon.checker.core.Platform.isWindows());
        assertEquals(Locations.Kind.SYSTEM, Locations.ofFile(ls, Locations.Roots.unix()));
    }

    private static Locations.Kind kind(String path) {
        return Locations.classify(Locations.normalize(path, true), WIN);
    }

    // ---- content formats ------------------------------------------------------------------------

    @Test
    void executablesAreRecognisedByContent(@TempDir Path tmp) throws Exception {
        assertEquals(FileInspection.Format.PE, FileInspection.format(Files.write(tmp.resolve("a"), pe(""))));
        assertEquals(FileInspection.Format.ELF, FileInspection.format(Files.write(tmp.resolve("b"), elf(""))));
        assertEquals(FileInspection.Format.MZ_MALFORMED, FileInspection.format(Files.write(tmp.resolve("c"),
                "MZ just text".getBytes(StandardCharsets.US_ASCII))));
        byte[] badElf = elf("");
        badElf[4] = 9; // no such ELF class
        assertEquals(FileInspection.Format.ELF_MALFORMED, FileInspection.format(Files.write(tmp.resolve("d"), badElf)));
        assertEquals(FileInspection.Format.ELF_MALFORMED, FileInspection.format(Files.write(tmp.resolve("e"),
                new byte[]{0x7F, 'E', 'L', 'F', 2})), "truncated header");
        byte[] mzFarPe = pe("");
        mzFarPe[0x3C] = (byte) 0xFF; mzFarPe[0x3D] = (byte) 0xFF; mzFarPe[0x3E] = 0x7F; // e_lfanew past the end
        assertEquals(FileInspection.Format.MZ_MALFORMED, FileInspection.format(Files.write(tmp.resolve("f"), mzFarPe)));
        assertEquals(FileInspection.Format.NONE, FileInspection.format(Files.writeString(tmp.resolve("g.txt"), "hello")));
        assertEquals(FileInspection.Format.UNREADABLE, FileInspection.format(tmp.resolve("missing")));
    }

    @Test
    void theSameProgramGetsTheSameFindingsWhateverItIsCalled(@TempDir Path tmp) throws Exception {
        // review repro: identical harmless ELF fixtures, a finding with ".so" and none without an extension
        byte[] fixture = elf("dwLocalPlayerPawn\0dwEntityList\0dwViewMatrix\0");
        List<String> reference = null;
        for (String name : new String[]{"tool", "libtool.so", "libtool.so.1", "tool.elf", "tool.bin"}) {
            Path f = Files.write(tmp.resolve(name), fixture);
            List<Finding> got = new ArrayList<>();
            assertEquals(FileInspection.Outcome.INSPECTED, FileInspection.inspect(f, ctx(got), "linuxfiles", Category.FILES), name);
            List<String> shape = got.stream().map(x -> x.severity() + " " + x.title()).sorted().toList();
            assertFalse(shape.isEmpty(), name + " produced no finding");
            if (reference == null) {
                reference = shape;
            }
            assertEquals(reference, shape, name);
        }
        assertTrue(reference.contains("HIGH Строки оффсетов CS2 в бинарнике / CS2 offset strings in binary"), reference.toString());
    }

    @Test
    void anAllowedFolderNameDeepInAScannedFolderDoesNotSilenceIt(@TempDir Path tmp) throws Exception {
        // review repro: the fixture stopped producing its finding under a nested ".../steam/steamapps/common/"
        Path nested = Files.createDirectories(tmp.resolve("x/.steam/steam/steamapps/common/usr/lib"));
        List<Finding> got = new ArrayList<>();
        FileInspection.inspect(Files.write(nested.resolve("tool"), elf("dwLocalPlayerPawn\0dwEntityList\0dwViewMatrix\0")),
                ctx(got), "linuxfiles", Category.FILES);
        assertTrue(got.stream().anyMatch(f -> f.severity() == Severity.HIGH), got.toString());
    }

    @Test
    void aProgramDisguisedAsAPictureIsReportedAndAnHonestNameIsNot(@TempDir Path tmp) throws Exception {
        List<Finding> png = new ArrayList<>();
        FileInspection.inspect(Files.write(tmp.resolve("screenshot.png"), pe("")), ctx(png), "files", Category.FILES);
        assertTrue(png.stream().anyMatch(f -> f.title().contains("disguised")), png.toString());
        List<Finding> exe = new ArrayList<>();
        FileInspection.inspect(Files.write(tmp.resolve("tool.exe"), pe("")), ctx(exe), "files", Category.FILES);
        assertTrue(exe.stream().noneMatch(f -> f.title().contains("disguised")), exe.toString());
        List<Finding> elfPng = new ArrayList<>();
        FileInspection.inspect(Files.write(tmp.resolve("cat.jpg"), elf("")), ctx(elfPng), "linuxfiles", Category.FILES);
        assertTrue(elfPng.stream().anyMatch(f -> f.title().contains("disguised") && f.detail().startsWith("ELF")));
    }

    @Test
    void limitsAndUnreadableFilesAreOutcomesNotSilence(@TempDir Path tmp) throws Exception {
        Path big = tmp.resolve("huge");
        Files.write(big, elf(""));
        try (RandomAccessFile raf = new RandomAccessFile(big.toFile(), "rw")) {
            raf.setLength(FileInspection.STRING_SCAN_MAX + 1);   // sparse: cheap to create
        }
        assertEquals(FileInspection.Outcome.TOO_LARGE, FileInspection.inspect(big, ctx(new ArrayList<>()), "x", Category.FILES));
        assertEquals(FileInspection.Outcome.EMPTY,
                FileInspection.inspect(Files.write(tmp.resolve("empty"), new byte[0]), ctx(new ArrayList<>()), "x", Category.FILES));
        assertEquals(FileInspection.Outcome.NOT_EXECUTABLE,
                FileInspection.inspect(Files.writeString(tmp.resolve("n.txt"), "notes"), ctx(new ArrayList<>()), "x", Category.FILES));
        Path locked = Files.write(tmp.resolve("locked"), elf(""));
        assumeTrue(locked.toFile().setReadable(false, false) && !Files.isReadable(locked), "running as root");
        assertEquals(FileInspection.Outcome.UNREADABLE, FileInspection.inspect(locked, ctx(new ArrayList<>()), "x", Category.FILES));
    }

    @Test
    void theIdentityGateNeverDropsAFindingForItsLocationAlone() {
        assertNull(FileInspection.gate(FileInspection.Identity.VERIFIED, Locations.Kind.USER_WRITABLE, Severity.HIGH),
                "a verified publisher is the only thing that silences a heuristic");
        var sys = FileInspection.gate(FileInspection.Identity.UNVERIFIED, Locations.Kind.SYSTEM, Severity.HIGH);
        assertEquals(Severity.LOW, sys.severity());
        assertEquals(EvidenceKind.CONTEXT, sys.kind(), "visible, but does not ask for review");
        var user = FileInspection.gate(FileInspection.Identity.UNVERIFIED, Locations.Kind.USER_WRITABLE, Severity.HIGH);
        assertEquals(Severity.HIGH, user.severity());
        var broken = FileInspection.gate(FileInspection.Identity.BROKEN, Locations.Kind.SYSTEM, Severity.LOW);
        assertEquals(Severity.MEDIUM, broken.severity(), "a modified signed file is looked at, even in System32");
        assertNull(broken.kind());
    }

    // ---- walks -------------------------------------------------------------------------------------

    @Test
    void aWalkSaysWhyItDidNotFinish(@TempDir Path tmp) throws Exception {
        for (int i = 0; i < 5; i++) {
            Files.writeString(tmp.resolve("f" + i), "x");
        }
        FileInspection.Walk capped = FileInspection.scan(tmp, 3, 8, null, f -> { }, null);
        assertTrue(capped.fileLimitHit());
        assertFalse(capped.complete());
        assertTrue(capped.shortfall().contains("file limit"));

        FileInspection.Walk late = FileInspection.scan(tmp, 100, 8, java.time.Instant.now().minusSeconds(1), f -> { }, null);
        assertTrue(late.timeUp());

        AtomicBoolean cancelled = new AtomicBoolean(true);
        ScanContext stopped = new ScanContext(DB, CheckId.generate(), TestResults.ENV, null, f -> { }, cancelled);
        assertTrue(FileInspection.scan(tmp, 100, 8, null, f -> { }, stopped).cancelled());

        FileInspection.Walk full = FileInspection.scan(tmp, 100, 8, null, f -> { }, null);
        assertTrue(full.complete());
        assertEquals(5, full.files());
        assertTrue(FileInspection.scan(tmp.resolve("nope"), 100, 8, null, f -> { }, null).rootMissing());
    }

    @Test
    void anUnreadableSubfolderMakesTheWalkIncomplete(@TempDir Path tmp) throws Exception {
        Path closed = Files.createDirectories(tmp.resolve("closed"));
        Files.writeString(closed.resolve("x"), "x");
        assumeTrue(closed.toFile().setReadable(false, false) && !Files.isReadable(closed), "running as root");
        try {
            FileInspection.Walk w = FileInspection.scan(tmp, 100, 8, null, f -> { }, null);
            assertEquals(1, w.deniedDirs());
            assertFalse(w.complete());
        } finally {
            closed.toFile().setReadable(true, false);
        }
    }

    @Test
    void linksAreNotFollowedAndDeclaredExclusionsAreSkipped(@TempDir Path tmp) throws Exception {
        Path lib = Files.createDirectories(tmp.resolve("steamapps/common/Game"));
        Files.writeString(lib.resolve("game.bin"), "x");
        Files.writeString(tmp.resolve("keep"), "x");
        try {
            Files.createSymbolicLink(tmp.resolve("loop"), tmp);
        } catch (UnsupportedOperationException | java.io.IOException e) {
            // no links here: the exclusion part still runs
        }
        List<Path> seen = new ArrayList<>();
        FileInspection.Walk w = FileInspection.scan(tmp, 100, 8, null, LinuxFileScanCheck::isExcluded, seen::add, null);
        assertEquals(List.of(tmp.resolve("keep")), seen);
        assertTrue(w.complete(), "a declared exclusion is not a shortfall");
    }

    // ---- fixtures ----------------------------------------------------------------------------------

    private static ScanContext ctx(List<Finding> out) {
        return new ScanContext(DB, CheckId.generate(), TestResults.ENV, null, out::add);
    }

    /** A minimal PE: MZ header whose e_lfanew points at "PE\0\0", then {@code tail}. */
    static byte[] pe(String tail) {
        byte[] b = new byte[0x80];
        b[0] = 'M';
        b[1] = 'Z';
        b[0x3C] = 0x40;
        b[0x40] = 'P';
        b[0x41] = 'E';
        return concat(b, tail);
    }

    /** A minimal 64-bit little-endian ELF identification and header, then {@code tail}. */
    static byte[] elf(String tail) {
        byte[] b = new byte[64];
        b[0] = 0x7F;
        b[1] = 'E';
        b[2] = 'L';
        b[3] = 'F';
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        return concat(b, tail);
    }

    private static byte[] concat(byte[] head, String tail) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(head);
        out.writeBytes(tail.getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }
}

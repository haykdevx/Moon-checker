package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.PrefetchBody;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExecutionTraceCheckTest {

    static final String VOL = "\\VOLUME{01dd442b53987e73-ae53a35e}";
    static final Instant LAST = Instant.parse("2026-09-12T19:40:00Z");
    static final SignatureDb DB = SignatureLoader.load(null).db();

    static List<Finding> correlate(String exe, List<String> loaded) {
        List<Finding> out = new ArrayList<>();
        ScanContext ctx = new ScanContext(DB, CheckId.generate(),
                new EnvironmentInfo("pc", "Windows 11", "u", true, "1", "h", "j"), ScanListener.NOOP, out::add);
        PrefetchBody.Info body = new PrefetchBody.Info(31, exe, "0BD30981", 4, List.of(LAST), loaded, List.of());
        ExecutionTraceCheck.correlateLoadedFiles(ctx, Path.of(exe + "-0BD30981.pf"), body,
                Map.of(0xAE53A35EL, 'C'));
        return out;
    }

    @Test
    void cheatDllInCs2TraceIsCritical() {
        List<Finding> f = correlate("CS2.EXE", List.of(
                VOL + "\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                VOL + "\\USERS\\ИГРОК\\APPDATA\\LOCAL\\TEMP\\NIXWARE.DLL",
                VOL + "\\USERS\\ИГРОК\\APPDATA\\LOCAL\\TEMP\\NIXWARE.DLL"));  // listed twice -> reported once
        assertEquals(1, f.size(), f.toString());
        assertEquals(Severity.CRITICAL, f.get(0).severity());
        assertEquals(Category.EXECUTION, f.get(0).category());
        assertEquals("C:\\USERS\\ИГРОК\\APPDATA\\LOCAL\\TEMP\\NIXWARE.DLL", f.get(0).evidence());
        assertEquals("C:\\USERS\\ИГРОК\\APPDATA\\LOCAL\\TEMP", f.get(0).openPath());
        assertEquals(LAST, f.get(0).when(), "timestamp must be the real last run, not the .pf mtime");
    }

    @Test
    void cheatFileInAnotherProgramsTraceUsesRuleSeverity() {
        var rule = DB.matchCheatName("nixware.dll").orElseThrow();
        List<Finding> f = correlate("LOADER.EXE", List.of(VOL + "\\DOWNLOADS\\NIXWARE.DLL"));
        assertEquals(1, f.size());
        assertEquals(rule.severity(), f.get(0).severity());
        assertTrue(f.get(0).detail().contains("loaded by LOADER.EXE"));
    }

    @Test
    void cleanTraceProducesNothing() {
        assertTrue(correlate("CS2.EXE", List.of(VOL + "\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
                VOL + "\\PROGRAM FILES (X86)\\STEAM\\STEAMAPPS\\COMMON\\COUNTER-STRIKE GLOBAL OFFENSIVE\\GAME\\BIN\\WIN64\\CS2.EXE"))
                .isEmpty());
    }

    @Test
    void volumePathsMapToDriveLetters() {
        Map<Long, Character> drives = Map.of(0xAE53A35EL, 'C', 0x12345678L, 'D');
        assertEquals("C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                PrefetchBody.toDrivePath(VOL + "\\WINDOWS\\SYSTEM32\\NTDLL.DLL", drives));
        assertEquals("D:\\", PrefetchBody.toDrivePath("\\VOLUME{01d0000000000000-12345678}", drives));
        // unknown serial or a non-volume path stays untouched
        assertEquals("\\VOLUME{01d0-99999999}\\X.DLL", PrefetchBody.toDrivePath("\\VOLUME{01d0-99999999}\\X.DLL", drives));
        assertEquals("\\DEVICE\\HARDDISKVOLUME2\\X.DLL", PrefetchBody.toDrivePath("\\DEVICE\\HARDDISKVOLUME2\\X.DLL", drives));
        assertNull(PrefetchBody.toDrivePath(null, drives));
    }

    @Test
    void onlyCounterStrikeExecutablesCountAsTheGame() {
        assertTrue(ExecutionTraceCheck.isGame("CS2.EXE"));
        assertTrue(ExecutionTraceCheck.isGame("csgo.exe"));
        assertFalse(ExecutionTraceCheck.isGame("CS2LAUNCHER.EXE"));
        assertFalse(ExecutionTraceCheck.isGame(null));
    }
}

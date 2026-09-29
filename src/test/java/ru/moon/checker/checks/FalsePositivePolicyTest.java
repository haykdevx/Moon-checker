package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Severity;
import ru.moon.checker.signatures.SignatureRule;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Software on ordinary gaming PCs that must not ask for a review, next to the real
 * positive that still must.
 */
class FalsePositivePolicyTest {

    private static final SignatureRule AFTERBURNER = new SignatureRule("rtcore64.sys", null, Severity.CRITICAL, "RTCore64");
    private static final SignatureRule MAPPER = new SignatureRule("kdmapper", null, Severity.CRITICAL, "kdmapper");

    private static boolean movesOutcome(Finding f) {
        return f.kind() == EvidenceKind.DETECTION || ((f.kind() == EvidenceKind.INDICATOR
                || f.kind() == EvidenceKind.CONCEALMENT) && f.severity().compareTo(Severity.MEDIUM) >= 0);
    }

    @Test
    void driverPlacesAreClassified() {
        assertEquals(DriverPlacement.Place.SYSTEM, DriverPlacement.of("\\SystemRoot\\System32\\drivers\\RTCore64.sys"));
        assertEquals(DriverPlacement.Place.SYSTEM, DriverPlacement.of("system32\\drivers\\gdrv.sys"));
        assertEquals(DriverPlacement.Place.SYSTEM,
                DriverPlacement.of("c:/windows/system32/driverstore/filerepository/asio.inf_amd64/asio64.sys"));
        assertEquals(DriverPlacement.Place.VENDOR,
                DriverPlacement.of("\\??\\C:\\Program Files (x86)\\MSI Afterburner\\RTCore64.sys"));
        assertEquals(DriverPlacement.Place.USER_WRITABLE,
                DriverPlacement.of("\\??\\C:\\Users\\Иван\\AppData\\Local\\Temp\\x7f3.sys"));
        assertEquals(DriverPlacement.Place.USER_WRITABLE, DriverPlacement.of("C:\\Users\\p\\Downloads\\gdrv.sys"));
        assertEquals(DriverPlacement.Place.USER_WRITABLE, DriverPlacement.of("C:\\Windows\\Temp\\iqvw64e.sys"));
        assertEquals(DriverPlacement.Place.USER_WRITABLE, DriverPlacement.of("C:\\rtcore64.sys"));
        assertEquals(DriverPlacement.Place.UNUSUAL, DriverPlacement.of("D:\\Games\\Genshin Impact\\mhyprot3.sys"));
    }

    @Test
    void afterburnerInstalledIsContextButDroppedByALoaderIsCritical() {
        Finding installed = DriverPlacement.finding(AFTERBURNER,
                "\\??\\C:\\Program Files (x86)\\MSI Afterburner\\RTCore64.sys", "kernel", "service");
        assertEquals(EvidenceKind.CONTEXT, installed.kind());
        assertFalse(movesOutcome(installed));
        Finding dropped = DriverPlacement.finding(AFTERBURNER, "C:\\Users\\p\\AppData\\Local\\Temp\\rtcore64.sys",
                "kernel", "service");
        assertEquals(Severity.CRITICAL, dropped.severity());
        assertTrue(movesOutcome(dropped));
        Finding unusual = DriverPlacement.finding(AFTERBURNER, "D:\\tools\\rtcore64.sys", "kernel", "service");
        assertEquals(Severity.MEDIUM, unusual.severity(), "somewhere odd asks for a look, no more");
    }

    @Test
    void aManualMapperIsNeverLegitimate() {
        Finding f = DriverPlacement.finding(MAPPER, "C:\\Windows\\System32\\drivers\\kdmapper.sys", "kernel", "x");
        assertEquals(Severity.CRITICAL, f.severity());
        assertTrue(movesOutcome(f));
    }

    @Test
    void defenderActivatorDetectionsAreContextGameHacksAreNot() {
        assertEquals(DefenderCheck.Weight.CONTEXT, DefenderCheck.weigh("hacktool:win32/autokms"));
        assertEquals(DefenderCheck.Weight.CONTEXT, DefenderCheck.weigh("hacktool:win32/keygen"));
        assertEquals(DefenderCheck.Weight.CONTEXT, DefenderCheck.weigh("hacktool:win64/kmspico!ml|c:\\kmspico\\x.exe"));
        assertEquals(DefenderCheck.Weight.IGNORE, DefenderCheck.weigh("trojan:win32/injector.a!mtb"),
                "a generic malware family is not a cheat loader");
        assertEquals(DefenderCheck.Weight.CHEAT_HIGH, DefenderCheck.weigh("hacktool:win64/gamehack.b"));
        assertEquals(DefenderCheck.Weight.CHEAT_HIGH, DefenderCheck.weigh("hacktool:win64/dllinjector"));
        assertEquals(DefenderCheck.Weight.CHEAT_HIGH, DefenderCheck.weigh("pua:win32/cheatengine"));
        assertEquals(DefenderCheck.Weight.CHEAT_MEDIUM, DefenderCheck.weigh("hacktool:win32/trainer"));
        assertEquals(DefenderCheck.Weight.IGNORE, DefenderCheck.weigh("trojan:win32/wacatac.b!ml"));
    }

    @Test
    void junctionsAreNotWalkedAndCloudFilesAreNotRead() {
        // C:\ProgramData\Application Data is a junction back to ProgramData (found on the first Windows run)
        assertTrue(FileInspection.isReparse(0x10 | 0x400), "directory + reparse point = junction");
        assertFalse(FileInspection.isReparse(0x10), "a plain directory");
        assertFalse(FileInspection.isReparse(-1), "unknown attributes: walk normally");
        assertTrue(FileInspection.isCloudOnly(0x20 | 0x400000), "OneDrive online-only file");
        assertTrue(FileInspection.isCloudOnly(0x1000), "offline file");
        assertFalse(FileInspection.isCloudOnly(0x20), "an ordinary local file");
    }

    @Test
    void launchOptionsAreMatchedWhole() {
        assertTrue(Cs2IntegrityCheck.hasOption("-novid -insecure +fps_max 0", "-insecure"));
        assertFalse(Cs2IntegrityCheck.hasOption("-novid -toolsmode", "-tools"));
        assertFalse(Cs2IntegrityCheck.hasOption("+exec c:\\configs\\-tools\\a.cfg", "-tools"));
    }

    @Test
    void relocatedUserFoldersAreFound() {
        assertEquals("C:\\Users\\Иван\\Downloads",
                FileScanCheck.expandEnv("%USERPROFILE%\\Downloads", java.util.Map.of("UserProfile", "C:\\Users\\Иван")));
        assertEquals("D:\\Загрузки", FileScanCheck.expandEnv("D:\\Загрузки", java.util.Map.of()));
        assertEquals("%OneDrive%\\Desktop", FileScanCheck.expandEnv("%OneDrive%\\Desktop", java.util.Map.of()),
                "an unknown variable is left alone (and the folder skipped)");
    }

    @Test
    void theFileCollectorStopsBeforeTheEnginesDeadline() {
        java.time.Instant now = java.time.Instant.parse("2026-09-29T10:00:00Z");
        assertEquals(now.plus(FileScanCheck.BUDGET), FileScanCheck.stopAt(now, null));
        assertEquals(now.plusSeconds(70), FileScanCheck.stopAt(now, now.plusSeconds(90)),
                "a 90 s self-test budget: stop 20 s early to report instead of being killed");
    }

    @Test
    void theFileCollectorFinishesInsideTheEnginesLimit() {
        assertTrue(FileScanCheck.BUDGET.compareTo(ru.moon.checker.core.ScanEngine.DEFAULT_MODULE_TIMEOUT
                .minusSeconds(30)) <= 0, "a big multi-drive PC must not end as a timed-out (incomplete) scan");
    }

    @Test
    void aFeatureUpdateIsNotAReinstall() {
        assertTrue(AntiForensicCheck.featureUpdate(new String[]{"MoSetup", "Source OS (Updated on 9/20/2026 10:12:03)"}));
        assertFalse(AntiForensicCheck.featureUpdate(new String[]{"MoSetup", "Status", "Pid"}));
        assertFalse(AntiForensicCheck.featureUpdate(new String[0]));
    }

    @Test
    void anInstalledCleanerIsContextRunningOneBeforeTheCheckIsNot() {
        Severity ccleaner = Severity.MEDIUM, sdelete = Severity.HIGH;
        assertEquals(Severity.LOW, AntiForensicCheck.cleanerSeverity(ccleaner, AntiForensicCheck.CleanerEvidence.INSTALLED));
        assertEquals(Severity.LOW, AntiForensicCheck.cleanerSeverity(ccleaner, AntiForensicCheck.CleanerEvidence.RAN_BEFORE));
        assertEquals(Severity.MEDIUM,
                AntiForensicCheck.cleanerSeverity(ccleaner, AntiForensicCheck.CleanerEvidence.RAN_RECENTLY));
        assertEquals(Severity.HIGH, AntiForensicCheck.cleanerSeverity(ccleaner, AntiForensicCheck.CleanerEvidence.RUNNING));
        assertEquals(Severity.MEDIUM, AntiForensicCheck.cleanerSeverity(sdelete, AntiForensicCheck.CleanerEvidence.RAN_BEFORE));
        assertEquals(Severity.HIGH, AntiForensicCheck.cleanerSeverity(sdelete, AntiForensicCheck.CleanerEvidence.RAN_RECENTLY));
    }
}

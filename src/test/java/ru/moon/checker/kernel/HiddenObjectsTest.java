package ru.moon.checker.kernel;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class HiddenObjectsTest {

    private static final List<String> REPORT = List.of(
            "MOONMON kernel report",
            "KPID 1 systemd",
            "KPID 4242 cs2",
            "KPID 9001 nixware_loader",
            "garbage line",
            "KPID notanumber x");

    @Test
    void parsesKernelPids() {
        Set<Integer> pids = HiddenObjects.parseKernelPids(REPORT);
        assertEquals(Set.of(1, 4242, 9001), pids);
        assertTrue(HiddenObjects.parseKernelPids(null).isEmpty());
    }

    @Test
    void findsProcessHiddenFromUserMode() {
        Set<Integer> kernel = HiddenObjects.parseKernelPids(REPORT);
        Set<Integer> visible = Set.of(1, 4242); // 9001 unlinked from /proc
        List<Integer> hidden = HiddenObjects.hiddenPids(kernel, visible);
        assertEquals(List.of(9001), hidden);
        assertEquals("nixware_loader", HiddenObjects.commOf(REPORT, 9001));
    }

    @Test
    void noHiddenProcessesWhenViewsAgree() {
        Set<Integer> kernel = Set.of(1, 2, 3);
        assertTrue(HiddenObjects.hiddenPids(kernel, Set.of(1, 2, 3)).isEmpty());
    }

    @Test
    void detectsModuleHiddenFromProcModules() {
        List<String> proc = List.of("nvidia", "btusb");
        List<String> sys = List.of("nvidia", "btusb", "rootkit_lkm");
        List<String> diff = HiddenObjects.moduleDisagreement(proc, sys);
        assertEquals(1, diff.size());
        assertTrue(diff.get(0).contains("rootkit_lkm"));
        assertTrue(diff.get(0).contains("missing from /proc/modules"));
    }

    @Test
    void dashUnderscoreNamingIsNormalised() {
        // /sys/module uses '_' where /proc/modules may print '-'
        assertTrue(HiddenObjects.moduleDisagreement(
                List.of("snd-hda-intel"), List.of("snd_hda_intel")).isEmpty());
    }

    @Test
    void parsesWeakBootOptions() {
        List<String> weak = HiddenObjects.weakBootOptions(
                "MININT -NOINTEGRITYCHECKS -TESTSIGNING -DEBUG");
        assertEquals(3, weak.size());
        assertTrue(weak.stream().anyMatch(s -> s.startsWith("TESTSIGNING")));
        assertTrue(weak.stream().anyMatch(s -> s.startsWith("NOINTEGRITYCHECKS")));
        assertTrue(HiddenObjects.weakBootOptions("NOEXECUTE=OPTIN").isEmpty());
        assertTrue(HiddenObjects.weakBootOptions(null).isEmpty());
    }

    @org.junit.jupiter.api.Test
    void windowsDriverPathsAreClassifiedInUserMode() {
        org.junit.jupiter.api.Assertions.assertTrue(ru.moon.checker.checks.KernelCheckAccess.system("\\SystemRoot\\system32\\drivers\\a.sys"));
        org.junit.jupiter.api.Assertions.assertTrue(ru.moon.checker.checks.KernelCheckAccess.system("\\??\\C:\\Windows\\System32\\b.sys"));
        org.junit.jupiter.api.Assertions.assertFalse(ru.moon.checker.checks.KernelCheckAccess.system("\\??\\C:\\Program Files\\EasyAntiCheat\\c.sys"));
        org.junit.jupiter.api.Assertions.assertFalse(ru.moon.checker.checks.KernelCheckAccess.system("\\??\\C:\\Users\\p\\AppData\\Local\\Temp\\d.sys"));
    }
}

package ru.moon.checker.kernel;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PostureTest {

    @Test
    void windowsSettingsBecomeOneReadableLine() {
        Posture.Windows w = new Posture.Windows(Posture.dword(1, true), Posture.dword(0, true), Posture.vbs(-1),
                Posture.dword(-1, true), true);
        assertEquals("Secure Boot: on; memory integrity (HVCI): off; VBS: not configured; "
                + "vulnerable-driver blocklist: Windows default; TPM 2.0: present", w.summary());
        assertFalse(w.blocklistDisabled(), "absent = Windows' default, not a deliberate change");
        Posture.Windows off = new Posture.Windows(Posture.dword(-1, true), Posture.dword(-1, true), Posture.vbs(2),
                Posture.dword(0, true), false);
        assertTrue(off.blocklistDisabled());
        assertTrue(off.summary().startsWith("Secure Boot: legacy BIOS"));
        assertTrue(off.summary().contains("VBS: on"));
    }

    @Test
    void linuxSysfsValuesAreParsed() {
        assertEquals(Posture.State.ON, Posture.efiSecureBoot(new byte[]{6, 0, 0, 0, 1}, true));
        assertEquals(Posture.State.OFF, Posture.efiSecureBoot(new byte[]{6, 0, 0, 0, 0}, true));
        assertEquals(Posture.State.UNKNOWN, Posture.efiSecureBoot(null, true));
        assertEquals(Posture.State.DEFAULT, Posture.efiSecureBoot(null, false));
        assertEquals("integrity", Posture.lockdown("none [integrity] confidentiality"));
        assertNull(Posture.lockdown(null));
        assertEquals(Posture.State.ON, Posture.yesNo("Y\n"));
        assertEquals(Posture.State.OFF, Posture.yesNo("N"));
        assertEquals(1, Posture.ptraceScope("1\n"));
        assertEquals(-1, Posture.ptraceScope("x"));
        String line = new Posture.Linux(Posture.State.OFF, "none", Posture.State.OFF, 0).summary();
        assertTrue(line.contains("ptrace scope: 0 (any process"));
    }

    @Test
    void bootSwitchesAreMatchedWhole() {
        assertTrue(HiddenObjects.weakBootOptions(" NOEXECUTE=OPTIN  NODEBUG").isEmpty(), "NODEBUG is not DEBUG");
        assertEquals(1, HiddenObjects.weakBootOptions(" DEBUG DEBUGPORT=COM1 BAUDRATE=115200").size());
        assertEquals(1, HiddenObjects.weakBootOptions(" SAFEBOOT:MINIMAL").size());
        assertEquals(1, HiddenObjects.weakBootOptions(" testsigning").size());
    }
}

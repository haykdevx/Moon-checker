package ru.moon.checker.win;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WinInfoTest {

    @Test
    void physicalHardwareIsNotAVm() {
        assertNull(WinInfo.matchVm("ASUSTeK COMPUTER INC.", "ROG STRIX B550-F", "American Megatrends Inc.", "2803"));
        // a Surface is made by Microsoft but is not a Hyper-V guest
        assertNull(WinInfo.matchVm("Microsoft Corporation", "Surface Pro 9", "Microsoft Corporation", "19.100"));
        // "xen" must be a word, not part of a model name
        assertNull(WinInfo.matchVm("Micro-Star International", "Xenith Board", "AMI", "1.0"));
        assertNull(WinInfo.matchVm(null, null, null, null));
    }

    @Test
    void hypervisorsAreRecognisedAcrossSeparateFields() {
        // Hyper-V splits the tell across manufacturer and product
        assertEquals("Hyper-V", WinInfo.matchVm("Microsoft Corporation", "Virtual Machine", "Microsoft Corporation", "Hyper-V UEFI"));
        assertEquals("VMware", WinInfo.matchVm("VMware, Inc.", "VMware20,1", "VMware, Inc.", "INTEL - 6040000"));
        assertEquals("VirtualBox", WinInfo.matchVm("innotek GmbH", "VirtualBox", "innotek GmbH", "VirtualBox"));
        assertEquals("QEMU", WinInfo.matchVm("QEMU", "Standard PC (Q35 + ICH9, 2009)", "EFI Development Kit II / OVMF", "0.0.0"));
        assertEquals("Xen", WinInfo.matchVm("Xen", "HVM domU", "Xen", "4.11"));
    }

    @Test
    void startOptionsDetectSigningRelaxations() {
        WinInfo.SigningState clean = WinInfo.parseStartOptions(" NOEXECUTE=OPTIN  FVEBOOT=2654208  NOVGA");
        assertFalse(clean.anyRelaxed());

        WinInfo.SigningState test = WinInfo.parseStartOptions(" TESTSIGNING  NOEXECUTE=OPTIN");
        assertTrue(test.testSigning());
        assertFalse(test.integrityChecksOff());

        WinInfo.SigningState nic = WinInfo.parseStartOptions("DISABLE_INTEGRITY_CHECKS NOEXECUTE=OPTIN");
        assertTrue(nic.integrityChecksOff());

        WinInfo.SigningState dbg = WinInfo.parseStartOptions(" DEBUG  DEBUGPORT=COM1  BAUDRATE=115200");
        assertTrue(dbg.kernelDebug());
        assertFalse(dbg.testSigning());
        // DEBUGPORT alone must not be read as DEBUG
        assertFalse(WinInfo.parseStartOptions("DEBUGPORT=COM1").kernelDebug());
    }
}

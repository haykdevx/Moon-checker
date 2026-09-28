package ru.moon.checker.kernel;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KernelReportTest {

    @Test
    void completeWindowsReport() {
        KernelReport r = KernelReport.parse(List.of("MOONMON 2 2", "DRIVER \\SystemRoot\\a.sys",
                "DRIVER \\??\\C:\\Program Files\\x\\b.sys", "END 2", ""));
        assertTrue(r.complete(), r.problem());
        assertEquals(2, r.records().size());
    }

    @Test
    void completeLinuxReportWithoutDeclaredCount() {
        KernelReport r = KernelReport.parse(List.of("MOONMON 2", "KPID 1 systemd", "KPID 42 bash", "END 2"));
        assertTrue(r.complete(), r.problem());
        assertEquals(List.of(1, 42), HiddenObjects.parseKernelPids(r.records()).stream().sorted().toList());
    }

    @Test
    void truncatedReportIsIncomplete() {
        KernelReport r = KernelReport.parse(List.of("MOONMON 2 3", "DRIVER \\SystemRoot\\a.sys"));
        assertFalse(r.complete());
        assertTrue(r.problem().contains("truncated"), r.problem());
        assertEquals(1, r.records().size(), "what did arrive is still usable as evidence");
    }

    @Test
    void countMismatchesAreIncomplete() {
        assertFalse(KernelReport.parse(List.of("MOONMON 2", "KPID 1 a", "END 2")).complete());
        assertFalse(KernelReport.parse(List.of("MOONMON 2 5", "DRIVER x", "END 1")).complete());
    }

    @Test
    void oldOrForeignProtocolsAreRejected() {
        assertFalse(KernelReport.parse(List.of("MOONMON 1", "DRIVER x")).complete());
        assertFalse(KernelReport.parse(List.of("MOONMON kernel report", "KPID 1 a")).complete());
        assertFalse(KernelReport.parse(List.of("DRIVER x")).complete());
        assertFalse(KernelReport.parse(List.of()).complete());
    }

    @Test
    void injectedOrStrayLinesAreRejected() {
        // a forged line after END, or anything that is not a record, breaks the framing
        assertFalse(KernelReport.parse(List.of("MOONMON 2", "KPID 1 a", "END 1", "KPID 666 hidden")).complete());
        assertFalse(KernelReport.parse(List.of("MOONMON 2", "KPID 1 a", "HIDDEN proc x", "END 1")).complete());
        assertFalse(KernelReport.parse(List.of("MOONMON 2", "END -1")).complete());
        assertFalse(KernelReport.parse(List.of("MOONMON 2", "END 0", "END 0")).complete());
    }
}

package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Severity;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression guard for the "executable disguised by extension" false positive:
 * Windows ships many legitimately-PE extensions (.cpl, .drv, .ocx, .ax, .tlb),
 * and flagging those floods the admin with noise.
 */
class FileInspectionTest {

    @Test
    void legitimatePeExtensionsAreNotDisguised() {
        for (String name : new String[]{"appwiz.cpl", "winex11.drv", "hhctrl.ocx",
                "ksproxy.ax", "stdole2.tlb", "msadp32.acm", "light.msstyles",
                "chcp.com", "client.dll", "cs2.exe", "driver.sys"}) {
            assertTrue(FileInspection.isBinaryName(name), name + " should count as binary");
            assertFalse(FileInspection.isNonExecutableName(name), name + " must not be 'disguised'");
        }
    }

    @Test
    void documentAndMediaExtensionsAreNonExecutable() {
        for (String name : new String[]{"screenshot.png", "config.txt", "notes.pdf",
                "song.mp3", "archive.zip", "clip.mp4", "data.json", "readme.md"}) {
            assertTrue(FileInspection.isNonExecutableName(name), name + " should be non-executable");
            assertFalse(FileInspection.isBinaryName(name), name + " is not a binary extension");
        }
    }

    @Test
    void unknownExtensionIsNeitherBinaryNorDisguised() {
        // still deep-scanned when the content is a PE, but never reported as disguised
        assertFalse(FileInspection.isBinaryName("payload.abc"));
        assertFalse(FileInspection.isNonExecutableName("payload.abc"));
        assertFalse(FileInspection.isBinaryName("windows.networking.connectivity"));
        assertFalse(FileInspection.isNonExecutableName("windows.networking.connectivity"));
    }

    @Test
    void oneGameFieldNameAloneDoesNotAskForReview() {
        assertEquals(Severity.LOW, FileInspection.offsetSeverity(1, false));
        assertEquals(Severity.MEDIUM, FileInspection.offsetSeverity(1, true));   // an offset-dump name
        assertEquals(Severity.MEDIUM, FileInspection.offsetSeverity(2, false));
        assertEquals(Severity.HIGH, FileInspection.offsetSeverity(3, false));
        assertEquals(Severity.HIGH, FileInspection.offsetSeverity(4, true));
    }

    @Test
    void suspiciousLocationsAreRecognised() {
        assertTrue(FileInspection.isSuspiciousLocation("c:\\users\\p\\appdata\\local\\temp\\x.exe"));
        assertTrue(FileInspection.isSuspiciousLocation("c:\\users\\public\\loader.exe"));
        assertFalse(FileInspection.isSuspiciousLocation("c:\\windows\\system32\\ntdll.dll"));
    }
}

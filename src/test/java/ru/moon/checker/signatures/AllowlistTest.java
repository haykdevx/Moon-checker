package ru.moon.checker.signatures;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The allowlist must suppress heuristics on trusted binaries while never
 * hiding an exact cheat-name or cheat-hash match.
 */
class AllowlistTest {

    private final SignatureDb db = SignatureLoader.load(null).db();

    @Test
    void bundledAllowlistCoversOsAndGamePaths() {
        assertTrue(db.isAllowedPath("c:\\windows\\system32\\kernelbase.dll"));
        assertTrue(db.isAllowedPath("c:\\program files (x86)\\steam\\steamapps\\common\\cs2\\game\\bin\\client.dll"));
        assertTrue(db.isAllowedPath("/usr/lib/x86_64-linux-gnu/libc.so.6"));
        assertTrue(db.isAllowedPath("/home/p/.steam/debian-installation/compatibilitytools.d/ge-proton8-32/files/taskmgr.exe"));
    }

    @Test
    void userWritableLocationsAreNotAllowlisted() {
        assertFalse(db.isAllowedPath("c:\\users\\p\\appdata\\local\\temp\\nixware.exe"));
        assertFalse(db.isAllowedPath("c:\\users\\p\\downloads\\loader.exe"));
        assertFalse(db.isAllowedPath("/home/p/downloads/loader"));
        assertFalse(db.isAllowedPath(null));
    }

    @Test
    void trustedSignersRecognised() {
        assertTrue(db.isAllowedSigner("cn=microsoft corporation, o=microsoft corporation, l=redmond"));
        assertTrue(db.isAllowedSigner("cn=valve corp., o=valve corp., l=bellevue"));
        assertFalse(db.isAllowedSigner("cn=some random publisher ltd"));
        assertFalse(db.isAllowedSigner(null));
    }

    @Test
    void hashAllowlistIsExactMatch() {
        SignatureDb custom = new SignatureDb("t", null, null, null, null, null, null, null,
                null, null, java.util.List.of("ABCDEF0123456789"));
        assertTrue(custom.isAllowedHash("abcdef0123456789"), "must be case-insensitive");
        assertFalse(custom.isAllowedHash("abcdef012345678a"));
        assertFalse(custom.isAllowedHash(null));
    }

    @Test
    void allowlistDoesNotCountAsDetectionRules() {
        // ruleCount() is shown to admins as "detections"; allowlists must not inflate it
        assertEquals(158, db.ruleCount());
    }

    @Test
    void cheatSignaturesStillMatchInsideTrustedPaths() {
        // a cheat dropped into a trusted directory is still caught by name
        assertTrue(db.matchCheatName("c:\\windows\\system32\\nixware.dll").isPresent());
    }
}

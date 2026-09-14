package ru.moon.checker.signatures;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Severity;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SignatureDbTest {

    @Test
    void bundledSignaturesLoad() {
        SignatureLoader.Result r = SignatureLoader.load(null);
        assertNotNull(r.db());
        assertTrue(r.db().ruleCount() > 50, "expected a populated bundled DB");
        assertEquals("bundled", r.origin());
    }

    @Test
    void matchingIsCaseInsensitiveSubstring() {
        SignatureDb db = SignatureLoader.load(null).db();
        assertTrue(db.matchCheatName("C:\\Users\\x\\NIXWARE_loader.exe").isPresent());
        assertTrue(db.matchCheatName("nixware.dll").isPresent());
        assertTrue(db.matchDomain("https://neverlose.cc/market").isPresent());
        assertTrue(db.matchDriver("iqvw64e.sys").isPresent());
        assertFalse(db.matchCheatName("explorer.exe").isPresent());
    }

    @Test
    void offsetStringMatchesAggregate() {
        SignatureDb db = SignatureLoader.load(null).db();
        assertFalse(db.allOffsetMatches("... dwEntityList ... m_iHealth ...").isEmpty());
        assertTrue(db.allOffsetMatches("nothing here").isEmpty());
    }

    @Test
    void severityDefaultsToMediumWhenMissing() {
        SignatureRule r = new SignatureRule("test", null, null, null);
        assertEquals(Severity.MEDIUM, r.severity());
        assertTrue(r.matches("this is a test string"));
    }

    @Test
    void nonexistentExternalFileFallsBackToBundled() {
        SignatureLoader.Result r = SignatureLoader.load(Path.of("/nonexistent-dir-xyz"));
        assertEquals("bundled", r.origin());
        assertTrue(r.db().ruleCount() > 0);
    }
}

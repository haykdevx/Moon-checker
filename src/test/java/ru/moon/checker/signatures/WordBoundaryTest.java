package ru.moon.checker.signatures;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Severity;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Word-boundary matching guards against the "midnightlib.json" class of false
 * positive, where a cheat name substring-matched an unrelated file.
 */
class WordBoundaryTest {

    private final SignatureDb db = SignatureLoader.load(null).db();

    @Test
    void doesNotMatchInsideALongerWord() {
        SignatureRule r = new SignatureRule("midnight", null, Severity.CRITICAL, "Midnight");
        assertFalse(r.matches("c:\\mods\\config\\midnightlib.json"));
        assertFalse(r.matches("midnightlibrary"));
        assertTrue(r.matches("c:\\cheats\\midnight.exe"));
        assertTrue(r.matches("midnight_loader.exe"));
        assertTrue(r.matches("Midnight Cheat".toLowerCase()));
    }

    @Test
    void substringRulesStillMatchInsideWords() {
        SignatureRule r = new SignatureRule("nixware", null, Severity.CRITICAL, "Nixware", true);
        assertTrue(r.matches("nixwareloader.exe"));
        assertTrue(r.matches("c:\\x\\nixware.dll"));
    }

    @Test
    void realWorldFalsePositiveIsGone() {
        // the exact file that was reported as a CRITICAL cheat on a dev machine
        assertTrue(db.matchCheatName("/home/u/downloads/mods/config/midnightlib.json").isEmpty(),
                "midnightlib.json must no longer match a cheat signature");
    }

    @Test
    void digitsDoNotBreakAMatch() {
        // version-numbered filenames must still be caught
        assertTrue(db.matchCheatName("cheatengine77.exe").isPresent());
        SignatureRule r = new SignatureRule("nixware", null, Severity.CRITICAL, "Nixware");
        assertTrue(r.matches("nixware2.dll"));
    }

    @Test
    void realCheatsStillDetected() {
        assertTrue(db.matchCheatName("c:\\users\\p\\downloads\\nixware.exe").isPresent());
        assertTrue(db.matchCheatName("midnight.exe").isPresent());
        assertTrue(db.matchCheatName("cheatengine77.exe").isPresent());
        assertTrue(db.matchDomain("https://neverlose.cc/market").isPresent());
        assertFalse(db.allOffsetMatches("... dwEntityList ...").isEmpty());
    }
}

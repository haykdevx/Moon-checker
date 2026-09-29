package ru.moon.checker.signatures;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Severity;

import java.util.List;

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
    void gameFieldNamesMatchWholeIdentifiersOnly() {
        // m_iHealthMax is a different field: it must not count as m_iHealth
        assertTrue(db.allOffsetMatches("m_iHealthMax").isEmpty());
        assertTrue(db.allOffsetMatches("Oldm_vecOrigin").isEmpty());
        assertEquals(1, db.allOffsetMatches("C_BaseEntity::m_iHealth").size());
        assertEquals(1, db.allOffsetMatches("\"m_vecOrigin\": 136").size());
        // offset-dump names still match inside longer identifiers
        assertEquals(1, db.allOffsetMatches("client_dll_dwEntityListOffset").size());
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

    @Test
    void anAmbiguousNameMatchesProgramsOnlyAndAsksForALookNotAVerdict() {
        // found on a real Linux run: midnight-jazz.md and primordials.js were reported as CRITICAL cheats
        SignatureDb db = SignatureLoader.load(null).db();
        assertTrue(db.matchCheatName("midnight-jazz.md").isEmpty());
        assertTrue(db.matchCheatName("primordials.js").isEmpty());
        assertTrue(db.matchCheatName("predatorsense.exe").isEmpty(), "word boundary: part of a longer word");
        assertTrue(db.matchCheatName("midnight commander - wikipedia").isEmpty());
        var exe = db.matchCheatName("midnight.exe");
        assertTrue(exe.isPresent());
        assertEquals(Severity.MEDIUM, exe.get().severity(), "ambiguous: capped");
        assertTrue(db.matchCheatName("midnight").isPresent(), "a bare process name");
        assertEquals(Severity.CRITICAL, db.matchCheatName("nixware_loader.exe").get().severity(),
                "a distinctive product name keeps its severity");
        assertEquals(Severity.CRITICAL, db.matchCheatName("nixware notes.txt").get().severity(),
                "and matches any name");
    }

    @Test
    void dualUseToolsAreContextAndEveryRuleSaysWhereItComesFrom() {
        SignatureDb db = SignatureLoader.load(null).db();
        assertEquals(Severity.INFO, db.matchCheatName("x64dbg.exe").get().severity());
        assertEquals("dual-use", db.matchCheatName("processhacker.exe").get().ruleClass());
        for (var list : List.of(db.cheatNames(), db.domains(), db.offsetStrings(), db.vulnerableDrivers(), db.cleaners(),
                db.macroTools())) {
            for (SignatureRule r : list) {
                assertNotNull(r.ruleClass(), r.pattern());
                assertNotNull(r.source(), r.pattern());
                assertTrue(List.of("reviewed", "provisional").contains(r.status()), r.pattern() + ": " + r.status());
            }
        }
        assertTrue(db.hashes().isEmpty(), "no hash without a classified sample (docs/rules-pipeline.md)");
    }
}

package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Severity;
import ru.moon.checker.signatures.SignatureLoader;

import static org.junit.jupiter.api.Assertions.*;

/** The collectors added after comparing with another server's checker: exclusions, DNS cache, uptime. */
class DnsAndExclusionsTest {

    @Test
    void exclusionsThatHideThingsAreConcealmentOthersAreContext() {
        var user = DefenderCheck.classifyExclusion("Path", "C:\\Users\\p\\AppData\\Local\\Temp\\x");
        assertEquals(EvidenceKind.CONCEALMENT, user.kind());
        assertEquals(Severity.MEDIUM, user.severity());
        assertEquals("defender:exclusion-drive", DefenderCheck.classifyExclusion("Path", "D:\\").rule());
        assertEquals(Severity.HIGH, DefenderCheck.classifyExclusion("Extension", ".exe").severity());
        assertEquals(Severity.HIGH, DefenderCheck.classifyExclusion("Extension", "dll").severity());
        var games = DefenderCheck.classifyExclusion("Path", "D:\\SteamLibrary\\steamapps\\common");
        assertEquals(EvidenceKind.CONTEXT, games.kind(), "a games library excluded for speed");
        assertEquals(EvidenceKind.CONTEXT, DefenderCheck.classifyExclusion("Path", "C:\\Program Files\\JetBrains").kind());
        assertEquals(EvidenceKind.CONTEXT, DefenderCheck.classifyExclusion("Extension", ".log").kind());
        assertEquals(EvidenceKind.CONTEXT, DefenderCheck.classifyExclusion("Process", "cs2.exe").kind());
    }

    @Test
    void theDnsCacheListingIsCleanedAndMatchedAgainstCheatSites() {
        var names = DnsCacheCheck.names("www.google.com\r\nWWW.Google.com\r\nlocalhost\r\n  \r\nwpad.\r\nneverlose.cc.\r\n");
        assertEquals(java.util.List.of("www.google.com", "neverlose.cc"), java.util.List.copyOf(names));
        var db = SignatureLoader.load(null).db();
        assertTrue(db.matchDomain("neverlose.cc").isPresent(), "a cheat domain from the rule set matches a bare host name");
        assertTrue(db.matchDomain("www.google.com").isEmpty());
    }

    @Test
    void aRecentRestartIsNotedAsContextOnly() {
        assertNotNull(EnvironmentCheck.recentRestartNote(3));
        assertTrue(EnvironmentCheck.recentRestartNote(3).contains("only in memory"));
        assertNull(EnvironmentCheck.recentRestartNote(240));
    }
}

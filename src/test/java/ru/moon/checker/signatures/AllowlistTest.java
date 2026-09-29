package ru.moon.checker.signatures;

import org.junit.jupiter.api.Test;
import ru.moon.checker.win.Authenticode;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What may silence a heuristic finding: a verified publisher (valid signature, pinned root,
 * exact vendor name) or an approved hash. Locations are not on this list any more (review
 * finding: substring path fragments let {@code Downloads\x\steam\steamapps\common\…} count as
 * Steam) — see LocationsTest for how locations are classified now.
 */
class AllowlistTest {

    private final SignatureDb db = SignatureLoader.load(null).db();
    private static final String MS_ROOT_2010 = "3B1EFD3A66EA28B16697394703A72CA340A05BD5";

    @Test
    void aVerifiedVendorNeedsAValidSignatureAPinnedRootAndTheExactName() {
        List<String> ms = Authenticode.names("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US");
        assertTrue(db.isTrustedIdentity(true, MS_ROOT_2010, ms));
        assertFalse(db.isTrustedIdentity(false, MS_ROOT_2010, ms), "status not Valid");
        assertFalse(db.isTrustedIdentity(true, "00".repeat(20), ms),
                "a root the player added to their own store is not pinned");
        assertFalse(db.isTrustedIdentity(true, "", ms));
        List<String> valve = Authenticode.names("CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US");
        assertTrue(db.isTrustedIdentity(true, "0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43", valve));
    }

    @Test
    void aSignerNameContainingAVendorIsNotThatVendor() {
        for (String dn : new String[]{"CN=Not Microsoft Corporation Ltd, O=Evil",
                "CN=Microsoft Corporation Fan Club, O=Microsoft Corporation Fan Club",
                "CN=valve corp. cheats, O=x", "CN=random publisher ltd"}) {
            assertFalse(db.isTrustedIdentity(true, MS_ROOT_2010, Authenticode.names(dn)), dn);
        }
    }

    @Test
    void distinguishedNamesAreParsedWithQuotesAndCommas() {
        assertEquals(List.of("advanced micro devices, inc", "advanced micro devices, inc"),
                Authenticode.names("CN=\"Advanced Micro Devices, Inc.\", O=\"Advanced Micro Devices, Inc.\", C=US"));
        assertTrue(db.isTrustedIdentity(true, MS_ROOT_2010,
                Authenticode.names("CN=\"Advanced Micro Devices, Inc.\", O=\"Advanced Micro Devices, Inc.\", C=US")));
        assertEquals(List.of(), Authenticode.names(""));
    }

    @Test
    void everyPinnedRootSaysWhereItsThumbprintCameFrom() {
        assertFalse(db.trustedRoots().isEmpty());
        for (SignatureDb.TrustedRoot r : db.trustedRoots()) {
            assertTrue(r.sha1().matches("[0-9A-F]{40}"), r.toString());
            assertNotNull(r.source(), r.name());
            assertFalse(r.source().isBlank(), r.name());
        }
    }

    @Test
    void powershellLinesAreParsed() {
        var r = Authenticode.parseLine("3\tValid\tabcd\tCN=Valve Corp., O=Valve Corp.");
        assertEquals("Valid", r.status());
        assertEquals("ABCD", r.rootSha1());
        assertEquals(List.of("valve corp", "valve corp"), r.signerNames());
        assertTrue(Authenticode.parseLine("3\tHashMismatch\t\t").broken());
        assertNull(Authenticode.parseLine("WARNING: something"));
    }

    @Test
    void hashAllowlistIsExactMatch() {
        SignatureDb custom = new SignatureDb("t", null, null, null, null, null, null, null,
                null, List.of("ABCDEF0123456789"), null);
        assertTrue(custom.isAllowedHash("abcdef0123456789"), "must be case-insensitive");
        assertFalse(custom.isAllowedHash("abcdef012345678a"));
        assertFalse(custom.isAllowedHash(null));
    }

    @Test
    void allowlistDoesNotCountAsDetectionRules() {
        // ruleCount() is shown to admins as "detections"; allowlists and pinned roots must not inflate it
        assertEquals(158, db.ruleCount());
    }

    @Test
    void cheatSignaturesStillMatchInsideSystemFolders() {
        // a cheat dropped into a system directory is still caught by name
        assertTrue(db.matchCheatName("c:\\windows\\system32\\nixware.dll").isPresent());
    }
}

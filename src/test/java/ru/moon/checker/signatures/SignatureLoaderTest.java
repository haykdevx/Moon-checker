package ru.moon.checker.signatures;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Rule overrides next to the checker are accepted only when signed and not older than the bundled rules. */
class SignatureLoaderTest {

    private static final String NEWER = "{\"version\":\"2099.01.01\",\"cheatNames\":[{\"pattern\":\"moon-test-artifact\","
            + "\"severity\":\"HIGH\",\"note\":\"synthetic test rule\",\"substring\":true}]}";

    private static KeyPair keyPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static void write(Path dir, String rules, KeyPair signer) throws Exception {
        byte[] bytes = rules.getBytes(StandardCharsets.UTF_8);
        Files.write(dir.resolve(SignatureLoader.OVERRIDE_FILE), bytes);
        if (signer != null) {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(signer.getPrivate());
            s.update(bytes);
            Files.writeString(dir.resolve(SignatureLoader.SIGNATURE_FILE), Base64.getEncoder().encodeToString(s.sign()));
        }
    }

    @Test
    void signedNewerOverrideIsUsed(@TempDir Path dir) throws Exception {
        KeyPair k = keyPair();
        write(dir, NEWER, k);
        SignatureLoader.Result r = SignatureLoader.load(dir, List.of(k.getPublic()));
        assertEquals("signed-override", r.origin());
        assertEquals("2099.01.01", r.db().version());
        assertEquals(1, r.provenance().count());
        assertEquals(64, r.provenance().digest().length());
        assertNull(r.error());
    }

    @Test
    void unsignedOverrideIsIgnoredAndNoted(@TempDir Path dir) throws Exception {
        write(dir, "{\"version\":\"2099.01.01\"}", null); // an empty rule set would blank out every scan
        SignatureLoader.Result r = SignatureLoader.load(dir, List.of(keyPair().getPublic()));
        assertEquals("bundled", r.origin());
        assertTrue(r.db().ruleCount() > 0, "bundled rules stay in force");
        assertTrue(r.provenance().note().contains("unsigned"), r.provenance().note());
    }

    @Test
    void wrongKeyOrTamperedFileIsIgnored(@TempDir Path dir) throws Exception {
        KeyPair signer = keyPair();
        write(dir, NEWER, signer);
        assertEquals("bundled", SignatureLoader.load(dir, List.of(keyPair().getPublic())).origin(), "wrong key");

        Files.writeString(dir.resolve(SignatureLoader.OVERRIDE_FILE), NEWER.replace("HIGH", "LOW"));
        SignatureLoader.Result r = SignatureLoader.load(dir, List.of(signer.getPublic()));
        assertEquals("bundled", r.origin(), "edited after signing");
        assertTrue(r.provenance().note().contains("invalid signature"), r.provenance().note());
    }

    @Test
    void olderSignedOverrideIsADowngradeAndIgnored(@TempDir Path dir) throws Exception {
        KeyPair k = keyPair();
        write(dir, NEWER.replace("2099.01.01", "2000.01.01"), k);
        SignatureLoader.Result r = SignatureLoader.load(dir, List.of(k.getPublic()));
        assertEquals("bundled", r.origin());
        assertTrue(r.provenance().note().contains("older"), r.provenance().note());
    }

    @Test
    void shippedKeyListParses() {
        List<PublicKey> keys = SignatureLoader.trustedKeys();
        assertFalse(keys.isEmpty(), "rules-keys.txt must hold at least one Ed25519 key");
        assertEquals("EdDSA", keys.get(0).getAlgorithm());
    }

    @Test
    void versionOrdering() {
        assertTrue(SignatureLoader.compareVersions("2026.09.14-cs2", "2026.9.13b") > 0);
        assertTrue(SignatureLoader.compareVersions("2026.09.14", "2026.10.01") < 0);
        assertEquals(0, SignatureLoader.compareVersions("1.2.3", "1.2.3"));
    }

    @Test
    void aNewerRuleFormatIsRefusedUntilTheCheckerIsUpdated(@TempDir Path dir) throws Exception {
        KeyPair k = keyPair();
        write(dir, NEWER.replace("{\"version\"", "{\"format\":" + (SignatureLoader.FORMAT + 1) + ",\"version\""), k);
        SignatureLoader.Result r = SignatureLoader.load(dir, List.of(k.getPublic()));
        assertEquals("bundled", r.origin());
        assertTrue(r.provenance().note().contains("format"), r.provenance().note());
    }

    @Test
    void aSignedEmptyRuleSetIsRefused(@TempDir Path dir) throws Exception {
        KeyPair k = keyPair();
        write(dir, "{\"version\":\"2099.01.01\",\"cheatNames\":[]}", k);
        SignatureLoader.Result r = SignatureLoader.load(dir, List.of(k.getPublic()));
        assertEquals("bundled", r.origin());
        assertTrue(r.db().ruleCount() > 0);
        assertTrue(r.provenance().note().contains("no rules"), r.provenance().note());
    }

    @Test
    void anInterruptedUpdateIsIgnoredAndTheNextCompleteOneIsUsed(@TempDir Path dir) throws Exception {
        KeyPair k = keyPair();
        write(dir, NEWER, k);                                           // a complete, signed update
        byte[] full = Files.readAllBytes(dir.resolve(SignatureLoader.OVERRIDE_FILE));
        Files.write(dir.resolve(SignatureLoader.OVERRIDE_FILE), java.util.Arrays.copyOf(full, full.length / 2));
        SignatureLoader.Result cut = SignatureLoader.load(dir, List.of(k.getPublic()));
        assertEquals("bundled", cut.origin(), "a cut-off download fails the signature");
        String newerStill = NEWER.replace("2099.01.01", "2099.02.01");
        Files.writeString(dir.resolve(SignatureLoader.OVERRIDE_FILE), newerStill);   // new file, old signature
        assertEquals("bundled", SignatureLoader.load(dir, List.of(k.getPublic())).origin());
        write(dir, newerStill, k);                                      // recovery: the next complete pair
        SignatureLoader.Result ok = SignatureLoader.load(dir, List.of(k.getPublic()));
        assertEquals("signed-override", ok.origin());
        assertEquals("2099.02.01", ok.db().version());
    }

    @Test
    void withdrawnRulesStayInTheFileButAreNotUsed(@TempDir Path dir) throws Exception {
        KeyPair k = keyPair();
        write(dir, "{\"version\":\"2099.01.01\",\"cheatNames\":[{\"pattern\":\"moon-test-artifact\",\"severity\":\"HIGH\","
                + "\"substring\":true},{\"pattern\":\"legit-tool\",\"severity\":\"HIGH\",\"status\":\"withdrawn\"}]}", k);
        SignatureDb db = SignatureLoader.load(dir, List.of(k.getPublic())).db();
        assertEquals(1, db.ruleCount());
        assertTrue(db.matchCheatName("legit-tool.exe").isEmpty());
        assertTrue(db.matchCheatName("moon-test-artifact.exe").isPresent());
    }
}

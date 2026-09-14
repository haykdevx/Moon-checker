package ru.moon.checker.signatures;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The full signature set. Deserialised from {@code signatures.json}. Each list
 * targets a different kind of artefact; see {@link SignatureRule}.
 *
 * <ul>
 *   <li>{@code cheatNames} — matched against file/process/window-title names</li>
 *   <li>{@code domains} — matched against browser history URLs</li>
 *   <li>{@code hashes} — exact sha-256 of binaries found on disk</li>
 *   <li>{@code offsetStrings} — CS2 netvar/offset names embedded in binaries
 *       (catches private / self-compiled externals)</li>
 *   <li>{@code vulnerableDrivers} — BYOVD / manual-mapper driver names</li>
 *   <li>{@code cleaners} — anti-forensic / cleaner tools</li>
 *   <li>{@code macroTools} — mouse-macro software and script engines</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignatureDb(
        String version,
        List<SignatureRule> cheatNames,
        List<SignatureRule> domains,
        List<SignatureRule> hashes,
        List<SignatureRule> offsetStrings,
        List<SignatureRule> vulnerableDrivers,
        List<SignatureRule> cleaners,
        List<SignatureRule> macroTools,
        List<String> allowPaths,
        List<String> allowSigners,
        List<String> allowHashes
) {
    public SignatureDb {
        version = version == null ? "unknown" : version;
        cheatNames = nullToEmpty(cheatNames);
        domains = nullToEmpty(domains);
        hashes = nullToEmpty(hashes);
        offsetStrings = nullToEmpty(offsetStrings);
        vulnerableDrivers = nullToEmpty(vulnerableDrivers);
        cleaners = nullToEmpty(cleaners);
        macroTools = nullToEmpty(macroTools);
        allowPaths = lowerAll(allowPaths);
        allowSigners = lowerAll(allowSigners);
        allowHashes = lowerAll(allowHashes);
    }

    private static List<String> lowerAll(List<String> in) {
        if (in == null) {
            return List.of();
        }
        List<String> out = new ArrayList<>(in.size());
        for (String s : in) {
            if (s != null && !s.isBlank()) {
                out.add(s.toLowerCase(Locale.ROOT));
            }
        }
        return List.copyOf(out);
    }

    private static List<SignatureRule> nullToEmpty(List<SignatureRule> in) {
        return in == null ? List.of() : List.copyOf(in);
    }

    public static SignatureDb empty() {
        return new SignatureDb("empty", null, null, null, null, null, null, null, null, null, null);
    }

    // ---- allowlist (false-positive suppression) --------------------------

    /**
     * True when the path lives in a trusted location (OS directories, Steam,
     * Proton/Wine, vendor installs). Heuristic findings — offset strings,
     * injection imports, entropy, disguised extension — are suppressed for
     * these, because legitimate system and game binaries trip them. Exact
     * cheat-name and hash matches are NEVER suppressed.
     */
    public boolean isAllowedPath(String pathLower) {
        if (pathLower == null) {
            return false;
        }
        for (String p : allowPaths) {
            if (pathLower.contains(p)) {
                return true;
            }
        }
        return false;
    }

    /** True when a code-signing subject is a trusted vendor. */
    public boolean isAllowedSigner(String signerLower) {
        if (signerLower == null) {
            return false;
        }
        for (String s : allowSigners) {
            if (signerLower.contains(s)) {
                return true;
            }
        }
        return false;
    }

    /** True when this exact file hash is explicitly known-good. */
    public boolean isAllowedHash(String sha256Lower) {
        return sha256Lower != null && allowHashes.contains(sha256Lower);
    }

    /** Total rule count across every list — shown in the UI/report footer. */
    public int ruleCount() {
        return cheatNames.size() + domains.size() + hashes.size() + offsetStrings.size()
                + vulnerableDrivers.size() + cleaners.size() + macroTools.size();
    }

    // ---- matching helpers -------------------------------------------------

    public Optional<SignatureRule> matchCheatName(String name) {
        return firstMatch(cheatNames, name);
    }

    public Optional<SignatureRule> matchDomain(String url) {
        return firstMatch(domains, url);
    }

    public Optional<SignatureRule> matchOffsetString(String s) {
        return firstMatch(offsetStrings, s);
    }

    public Optional<SignatureRule> matchDriver(String name) {
        return firstMatch(vulnerableDrivers, name);
    }

    public Optional<SignatureRule> matchCleaner(String name) {
        return firstMatch(cleaners, name);
    }

    public Optional<SignatureRule> matchMacroTool(String name) {
        return firstMatch(macroTools, name);
    }

    public Optional<SignatureRule> matchHash(String sha256Lower) {
        if (sha256Lower == null) {
            return Optional.empty();
        }
        for (SignatureRule r : hashes) {
            if (r.matchesHash(sha256Lower)) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    /** Every offset-string rule that appears in the given text, de-duplicated. */
    public List<SignatureRule> allOffsetMatches(String s) {
        if (s == null) {
            return List.of();
        }
        String lower = s.toLowerCase(Locale.ROOT);
        List<SignatureRule> hits = new ArrayList<>();
        for (SignatureRule r : offsetStrings) {
            if (r.matches(lower)) {
                hits.add(r);
            }
        }
        return hits;
    }

    private static Optional<SignatureRule> firstMatch(List<SignatureRule> rules, String haystack) {
        if (haystack == null || haystack.isEmpty()) {
            return Optional.empty();
        }
        String lower = haystack.toLowerCase(Locale.ROOT);
        for (SignatureRule r : rules) {
            if (r.matches(lower)) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }
}

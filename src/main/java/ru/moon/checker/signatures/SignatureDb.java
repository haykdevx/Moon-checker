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
        List<String> allowSigners,
        List<String> allowHashes,
        List<TrustedRoot> trustedRoots
) {
    /**
     * A certificate root a vendor's code-signing chain may end in, pinned by SHA-1 thumbprint.
     * A root the player installed into their own Windows store is not on this list.
     *
     * @param source where the thumbprint was taken from (it is not typed in from memory)
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record TrustedRoot(String sha1, String name, String source) {
    }

    public SignatureDb {
        version = version == null ? "unknown" : version;
        cheatNames = nullToEmpty(cheatNames);
        domains = nullToEmpty(domains);
        hashes = nullToEmpty(hashes);
        offsetStrings = nullToEmpty(offsetStrings);
        vulnerableDrivers = nullToEmpty(vulnerableDrivers);
        cleaners = nullToEmpty(cleaners);
        macroTools = nullToEmpty(macroTools);
        allowSigners = allowSigners == null ? List.of() : allowSigners.stream()
                .filter(s -> s != null && !s.isBlank()).map(SignatureDb::normalizeName).toList();
        allowHashes = lowerAll(allowHashes);
        trustedRoots = trustedRoots == null ? List.of() : trustedRoots.stream()
                .filter(r -> r != null && r.sha1() != null && r.sha1().matches("(?i)[0-9a-f]{40}"))
                .map(r -> new TrustedRoot(r.sha1().toUpperCase(Locale.ROOT), r.name(), r.source())).toList();
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

    /** "Valve Corp." → "valve corp" (same rule as the signer names read from a certificate). */
    static String normalizeName(String v) {
        String s = v == null ? "" : v.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1).trim();
        }
        return s;
    }

    // ---- allowlist (false-positive suppression) --------------------------

    /**
     * Whether a file's signature is an identity this rule set vouches for: Windows says the
     * signature is valid, its chain ends in a pinned root, and the signer's CN or O equals an
     * allowed vendor name exactly (after trimming case, spaces and trailing dots). A substring
     * is not enough: "Not Microsoft Corporation Ltd" is not "Microsoft Corporation".
     *
     * <p>This only ever decides whether a heuristic finding needs a reviewer; exact cheat-name
     * and hash matches are reported regardless.
     */
    public boolean isTrustedIdentity(boolean valid, String rootSha1, List<String> signerNames) {
        if (!valid || rootSha1 == null || signerNames == null) {
            return false;
        }
        boolean pinned = trustedRoots.stream().anyMatch(r -> r.sha1().equalsIgnoreCase(rootSha1));
        return pinned && signerNames.stream().map(SignatureDb::normalizeName).anyMatch(allowSigners::contains);
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

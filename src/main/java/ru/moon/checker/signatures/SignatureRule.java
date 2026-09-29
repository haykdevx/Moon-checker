package ru.moon.checker.signatures;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import ru.moon.checker.core.Severity;

import java.util.Locale;

/**
 * A single detection rule from {@code signatures.json}.
 *
 * <p>Either {@code pattern} (matched against names, paths, domains, offset
 * strings, driver names...) or {@code sha256} (an exact file-hash match) is
 * used, depending on the list the rule lives in.
 *
 * <p>Matching is <b>word-boundary</b> by default: the pattern must not be
 * flanked by letters or digits. Without this, short or common patterns produce
 * bad false positives — {@code midnight} matched {@code midnightlib.json}, an
 * unrelated Minecraft mod config, and reported it as a cheat. Set
 * {@code "substring": true} on a rule whose name is distinctive enough that
 * matching inside a longer word is desirable (e.g. {@code nixwareloader.exe}).
 *
 * @param pattern   text to look for (nullable for hash rules)
 * @param sha256    lower-case hex sha-256 (nullable for pattern rules)
 * @param severity  severity to assign when this rule matches (defaults MEDIUM)
 * @param note      human explanation shown to the admin
 * @param substring match anywhere, skipping the word-boundary requirement
 * @param ruleClass what the rule is about: cheat-product, cheat-generic, bypass-tool, injector,
 *                  offset-tool, dual-use, cheat-site, offset-name, vulnerable-driver, cleaner,
 *                  macro-tool, known-hash (JSON "class")
 * @param ambiguous the name is also an ordinary word or a legitimate product ("predator",
 *                  "gamesense", "midnight"): it matches only program or archive names and never
 *                  counts above MEDIUM (see SignatureDb#matchCheatName)
 * @param status    reviewed | provisional | withdrawn — withdrawn rules are kept in the file for
 *                  the record and never loaded
 * @param source    where the rule comes from (provenance), stated plainly
 * @param since     rules version that added it
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignatureRule(String pattern, String sha256, Severity severity, String note,
                            boolean substring,
                            @com.fasterxml.jackson.annotation.JsonProperty("class") String ruleClass,
                            boolean ambiguous, String status, String source, String since) {

    public SignatureRule {
        if (severity == null) {
            severity = Severity.MEDIUM;
        }
        if (pattern != null) {
            pattern = pattern.toLowerCase(Locale.ROOT);
        }
        if (sha256 != null) {
            sha256 = sha256.trim().toLowerCase(Locale.ROOT);
        }
    }

    /** Convenience for tests / programmatic rules (word-boundary matching). */
    public SignatureRule(String pattern, String sha256, Severity severity, String note) {
        this(pattern, sha256, severity, note, false);
    }

    public SignatureRule(String pattern, String sha256, Severity severity, String note, boolean substring) {
        this(pattern, sha256, severity, note, substring, null, false, null, null, null);
    }

    public boolean withdrawn() {
        return "withdrawn".equalsIgnoreCase(status);
    }

    /** The same rule with its severity lowered to at most {@code cap}. */
    public SignatureRule cappedAt(Severity cap) {
        return severity.rank() <= cap.rank() ? this
                : new SignatureRule(pattern, sha256, cap, note, substring, ruleClass, ambiguous, status, source, since);
    }

    public boolean matches(String haystackLower) {
        if (pattern == null || pattern.isEmpty() || haystackLower == null) {
            return false;
        }
        if (substring) {
            return haystackLower.contains(pattern);
        }
        int from = 0;
        while (true) {
            int i = haystackLower.indexOf(pattern, from);
            if (i < 0) {
                return false;
            }
            int end = i + pattern.length();
            boolean leftOk = i == 0 || !isWordChar(haystackLower.charAt(i - 1));
            boolean rightOk = end >= haystackLower.length() || !isWordChar(haystackLower.charAt(end));
            if (leftOk && rightOk) {
                return true;
            }
            from = i + 1;
        }
    }

    /**
     * Only letters break a match. Digits are allowed to flank it so
     * version-numbered filenames like {@code CheatEngine77.exe} or
     * {@code nixware2.dll} are still detected, while {@code midnightlib.json}
     * is not.
     */
    private static boolean isWordChar(char c) {
        return Character.isLetter(c);
    }

    public boolean matchesHash(String hashLower) {
        return sha256 != null && !sha256.isEmpty() && sha256.equals(hashLower);
    }

    public String label() {
        if (note != null && !note.isBlank()) {
            return note;
        }
        return pattern != null ? pattern : sha256;
    }
}

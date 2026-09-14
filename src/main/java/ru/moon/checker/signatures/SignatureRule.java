package ru.moon.checker.signatures;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import ru.moon.checker.core.Severity;

import java.util.Locale;

/**
 * A single detection rule from {@code signatures.json}.
 *
 * <p>Either {@code pattern} (a case-insensitive substring matched against
 * names, paths, domains, offset strings, driver names...) or {@code sha256}
 * (an exact file-hash match) is used, depending on the list the rule lives in.
 *
 * @param pattern  substring to look for (nullable for hash rules)
 * @param sha256   lower-case hex sha-256 (nullable for pattern rules)
 * @param severity severity to assign when this rule matches (defaults MEDIUM)
 * @param note     human explanation shown to the admin
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignatureRule(String pattern, String sha256, Severity severity, String note) {

    public SignatureRule {
        if (severity == null) {
            severity = Severity.MEDIUM;
        }
        if (pattern != null) {
            // store lowercase for fast case-insensitive matching
            pattern = pattern.toLowerCase(Locale.ROOT);
        }
        if (sha256 != null) {
            sha256 = sha256.trim().toLowerCase(Locale.ROOT);
        }
    }

    public boolean matches(String haystackLower) {
        return pattern != null && !pattern.isEmpty() && haystackLower.contains(pattern);
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

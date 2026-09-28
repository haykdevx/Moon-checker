package ru.moon.checker.core;

/**
 * What the evidence supports — never a probability. Derived by
 * {@link VerdictEngine} from evidence kinds and scan coverage.
 *
 * <p>Precedence (first that applies): {@link #VALIDATED_DETECTION},
 * {@link #REVIEW_REQUIRED}, {@link #UNSUPPORTED_CONFIGURATION},
 * {@link #INCOMPLETE_SCAN}, {@link #NO_EVIDENCE}. Missing telemetry therefore
 * never reads as {@link #NO_EVIDENCE}.
 */
public enum Verdict {
    /** A known cheat artefact was identified exactly (hash of a classified sample). */
    VALIDATED_DETECTION("#ff5a5a", "verdict.validated"),
    /** Indicators or concealment that a human must weigh. Not a cheating verdict. */
    REVIEW_REQUIRED("#f6b949", "verdict.review"),
    /** The platform is outside what the checker supports; results cannot be relied on. */
    UNSUPPORTED_CONFIGURATION("#b6b6c6", "verdict.unsupported"),
    /** Required collectors failed, timed out or lacked privileges. */
    INCOMPLETE_SCAN("#9aa0ff", "verdict.incomplete"),
    /** Every required collector completed and found nothing to review. Not proof of innocence. */
    NO_EVIDENCE("#37d67a", "verdict.none");

    private final String color;
    private final String key;

    Verdict(String color, String key) {
        this.color = color;
        this.key = key;
    }

    /** Hex color used by the UI and HTML report. */
    public String color() {
        return color;
    }

    /** i18n key of the localised label. */
    public String key() {
        return key;
    }
}

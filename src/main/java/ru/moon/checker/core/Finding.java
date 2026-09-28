package ru.moon.checker.core;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;

/**
 * One piece of evidence produced by a {@link CheckModule}. Immutable; build
 * via {@link #builder(Category, Severity, String)}.
 *
 * @param module    id of the module that produced it (stable key)
 * @param category  logical grouping
 * @param severity  how strongly the reviewer should look at it (ordering only;
 *                  severities are never added up)
 * @param kind      what it is evidence of — drives the verdict
 * @param ruleId    stable identifier of the rule that produced it
 * @param title     short human summary (already localised)
 * @param detail    longer explanation / matched rule, may be null
 * @param evidence  the concrete artefact: a file path, registry value, url...
 * @param source    where it was found (e.g. "Prefetch", "USN journal")
 * @param when      timestamp associated with the artefact, may be null
 * @param openPath  filesystem path the UI can reveal in Explorer, may be null
 */
public record Finding(
        String module,
        Category category,
        Severity severity,
        EvidenceKind kind,
        String ruleId,
        String title,
        String detail,
        String evidence,
        String source,
        Instant when,
        String openPath
) {
    public Finding {
        Objects.requireNonNull(module, "module");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(title, "title");
    }

    public static Builder builder(Category category, Severity severity, String title) {
        return new Builder(category, severity, title);
    }

    /**
     * The kind a finding gets when its module does not say: concealment for the
     * anti-forensic category, context for INFO, otherwise an indicator. A
     * {@link EvidenceKind#DETECTION} is never assumed — a module must claim it.
     */
    static EvidenceKind defaultKind(Category category, Severity severity) {
        if (category == Category.ANTIFORENSIC) {
            return EvidenceKind.CONCEALMENT;
        }
        return severity == Severity.INFO ? EvidenceKind.CONTEXT : EvidenceKind.INDICATOR;
    }

    /** "module:english-title-slug" — stable enough to key rule documentation and tests. */
    static String defaultRuleId(String module, String title) {
        String english = title.contains(" / ") ? title.substring(title.lastIndexOf(" / ") + 3) : title;
        String slug = english.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
        if (slug.length() > 48) {
            slug = slug.substring(0, 48).replaceAll("-$", "");
        }
        return (module.isEmpty() ? "unknown" : module) + ":" + (slug.isEmpty() ? "finding" : slug);
    }

    public static final class Builder {
        private String module = "";
        private final Category category;
        private final Severity severity;
        private final String title;
        private EvidenceKind kind;
        private String ruleId;
        private String detail;
        private String evidence;
        private String source;
        private Instant when;
        private String openPath;

        private Builder(Category category, Severity severity, String title) {
            this.category = category;
            this.severity = severity;
            this.title = title;
        }

        public Builder module(String v) { this.module = v; return this; }
        public Builder kind(EvidenceKind v) { this.kind = v; return this; }
        public Builder rule(String v) { this.ruleId = v; return this; }
        public Builder detail(String v) { this.detail = v; return this; }
        public Builder evidence(String v) { this.evidence = v; return this; }
        public Builder source(String v) { this.source = v; return this; }
        public Builder when(Instant v) { this.when = v; return this; }
        public Builder openPath(String v) { this.openPath = v; return this; }

        public Finding build() {
            EvidenceKind k = kind != null ? kind : defaultKind(category, severity);
            String r = ruleId != null ? ruleId : defaultRuleId(module, title);
            return new Finding(module, category, severity, k, r, title, detail, evidence, source, when, openPath);
        }
    }
}

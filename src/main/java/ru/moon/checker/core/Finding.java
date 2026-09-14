package ru.moon.checker.core;

import java.time.Instant;
import java.util.Objects;

/**
 * One piece of evidence produced by a {@link CheckModule}. Immutable; build
 * via {@link #builder(Category, Severity, String)}.
 *
 * @param module    id of the module that produced it (stable key)
 * @param category  logical grouping
 * @param severity  how damning this evidence is
 * @param title     short human summary (already localised)
 * @param detail    longer explanation / matched rule, may be null
 * @param evidence  the concrete artefact: a file path, registry value, url...
 * @param source    where it was found (e.g. "Prefetch", "USN journal")
 * @param when      timestamp associated with the artefact, may be null
 * @param openPath  filesystem path the UI can reveal in Explorer, may be null
 * @param weight    contribution to the score (defaults to severity weight)
 */
public record Finding(
        String module,
        Category category,
        Severity severity,
        String title,
        String detail,
        String evidence,
        String source,
        Instant when,
        String openPath,
        int weight
) {
    public Finding {
        Objects.requireNonNull(module, "module");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(title, "title");
    }

    public static Builder builder(Category category, Severity severity, String title) {
        return new Builder(category, severity, title);
    }

    public static final class Builder {
        private String module = "";
        private final Category category;
        private final Severity severity;
        private final String title;
        private String detail;
        private String evidence;
        private String source;
        private Instant when;
        private String openPath;
        private int weight = -1;

        private Builder(Category category, Severity severity, String title) {
            this.category = category;
            this.severity = severity;
            this.title = title;
        }

        public Builder module(String v) { this.module = v; return this; }
        public Builder detail(String v) { this.detail = v; return this; }
        public Builder evidence(String v) { this.evidence = v; return this; }
        public Builder source(String v) { this.source = v; return this; }
        public Builder when(Instant v) { this.when = v; return this; }
        public Builder openPath(String v) { this.openPath = v; return this; }
        public Builder weight(int v) { this.weight = v; return this; }

        public Finding build() {
            int w = weight >= 0 ? weight : severity.weight();
            return new Finding(module, category, severity, title, detail,
                    evidence, source, when, openPath, w);
        }
    }
}

package ru.moon.checker.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Turns a flat list of findings into something an admin can act on in seconds.
 *
 * <p>A single cheat typically produces evidence in five different modules — the
 * file on disk, the Prefetch entry, the AmCache record, the Run key and the
 * loaded driver. Presented as five unrelated rows that reads as noise; grouped
 * under one subject it reads as a case. This class also explains how the score
 * was reached and orders timestamped findings into a timeline.
 *
 * <p>Pure functions, no I/O — fully unit-tested.
 */
public final class Analysis {

    private Analysis() {
    }

    /** Correlated evidence about one subject (usually one cheat). */
    public record Group(String subject, Severity topSeverity, EvidenceKind topKind,
                        List<Finding> findings, Set<String> modules) {
        public int count() {
            return findings.size();
        }
    }

    /**
     * The subject a finding is about — normally the signature rule's label,
     * which modules put at the start of {@code detail}. Falls back to the title.
     */
    public static String subjectOf(Finding f) {
        String d = f.detail();
        if (d != null && !d.isBlank()) {
            String s = d;
            for (String sep : new String[]{" — ", "  (", "  [", " -> ", ", "}) {
                int i = s.indexOf(sep);
                if (i > 0) {
                    s = s.substring(0, i);
                }
            }
            s = s.trim();
            if (looksLikeSubject(s)) {
                return s;
            }
        }
        return f.title();
    }

    /**
     * Modules put the signature label first in {@code detail} ("Nixware CS2
     * cheat"), but some details are descriptions instead ({@code Stream
     * "payload" (204800 bytes)}, {@code 4 match(es): dwEntityList},
     * {@code login=smurf_alt}). Those are not subjects — grouping by them
     * produces nonsense cards, so fall back to the finding's title.
     */
    private static boolean looksLikeSubject(String s) {
        if (s.isEmpty() || s.length() > 60) {
            return false;
        }
        if (Character.isDigit(s.charAt(0))) {
            return false;
        }
        for (String bad : new String[]{"\"", "=", ":", "/", "\\", "(", ")", "bytes", "match("}) {
            if (s.contains(bad)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Group findings by subject, merging subjects where one is a prefix of the
     * other ("Nixware" and "Nixware CS2 cheat" are the same case). Ordered by
     * severity, then by how many traces support it, so the strongest case is first.
     */
    public static List<Group> group(List<Finding> findings) {
        Map<String, List<Finding>> bySubject = new LinkedHashMap<>();
        for (Finding f : findings) {
            bySubject.computeIfAbsent(subjectOf(f), k -> new ArrayList<>()).add(f);
        }
        mergePrefixes(bySubject);

        List<Group> groups = new ArrayList<>();
        for (var e : bySubject.entrySet()) {
            Severity top = Severity.INFO;
            EvidenceKind kind = EvidenceKind.CONTEXT;
            Set<String> modules = new LinkedHashSet<>();
            for (Finding f : e.getValue()) {
                if (f.severity().rank() > top.rank()) {
                    top = f.severity();
                }
                if (f.kind().ordinal() < kind.ordinal()) {
                    kind = f.kind(); // DETECTION < INDICATOR < CONCEALMENT < CONFIGURATION < CONTEXT
                }
                modules.add(f.module());
            }
            groups.add(new Group(e.getKey(), top, kind, List.copyOf(e.getValue()), modules));
        }
        groups.sort(Comparator
                .comparingInt((Group g) -> g.topSeverity().rank()).reversed()
                .thenComparing(Comparator.comparingInt(Group::count).reversed()));
        return groups;
    }

    /** Fold "Nixware" into "Nixware CS2 cheat" (keep the longer, more specific name). */
    private static void mergePrefixes(Map<String, List<Finding>> bySubject) {
        List<String> keys = new ArrayList<>(bySubject.keySet());
        keys.sort(Comparator.comparingInt(String::length)); // shortest first
        for (int i = 0; i < keys.size(); i++) {
            String shortKey = keys.get(i);
            if (!bySubject.containsKey(shortKey)) {
                continue;
            }
            for (int j = keys.size() - 1; j > i; j--) {
                String longKey = keys.get(j);
                if (longKey.equals(shortKey) || !bySubject.containsKey(longKey)) {
                    continue;
                }
                if (longKey.toLowerCase(Locale.ROOT).startsWith(shortKey.toLowerCase(Locale.ROOT))) {
                    bySubject.get(longKey).addAll(bySubject.remove(shortKey));
                    break;
                }
            }
        }
    }

    /** Findings that carry a timestamp, most recent first. */
    public static List<Finding> timeline(List<Finding> findings) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) {
            if (f.when() != null) {
                out.add(f);
            }
        }
        out.sort(Comparator.comparing(Finding::when).reversed());
        return out;
    }

    /**
     * Why the verdict is what it is, in plain language: the engine's reasons with
     * the evidence ids they cite, then what was covered and how far to trust it.
     */
    public static String explain(ScanResult r) {
        Assessment a = r.assessment();
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.t(a.outcome().key())).append(" — ").append(I18n.t(a.outcome().key() + ".help"));
        for (Assessment.Reason reason : a.reasons()) {
            sb.append("\n  • ").append(reason.text());
            if (!reason.evidence().isEmpty()) {
                sb.append("  [").append(String.join(", ",
                        reason.evidence().stream().map(i -> "E" + i).toList())).append(']');
            }
        }
        Coverage c = a.coverage();
        sb.append("\n\n").append(I18n.t("coverage.summary", c.completed(), c.required().size(),
                c.elevated() ? I18n.t("header.admin.yes") : I18n.t("header.admin.no")));
        sb.append("\n").append(I18n.t("assurance.summary", I18n.t("assurance." + a.assurance().level().name())));
        for (Assurance.Note n : a.assurance().reasons()) {
            sb.append("\n  – ").append(n.text());
        }
        return sb.toString();
    }
}

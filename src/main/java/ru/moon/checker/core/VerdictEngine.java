package ru.moon.checker.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Derives the {@link Assessment} from evidence kinds and coverage. Deliberately
 * rule-based: there is no score, no weights and no probability.
 *
 * <ul>
 *   <li>{@link Verdict#VALIDATED_DETECTION} needs at least one
 *       {@link EvidenceKind#DETECTION} (exact identity of a classified sample).</li>
 *   <li>{@link Verdict#REVIEW_REQUIRED}: indicators or concealment of MEDIUM or
 *       higher severity. Findings about the same subject are one reason, however
 *       many collectors saw them — correlated traces of one cause are not
 *       independent proof.</li>
 *   <li>{@link EvidenceKind#CONFIGURATION} never changes the outcome; it lowers
 *       the {@link Assurance} instead.</li>
 *   <li>Without evidence, an unsupported platform or an incomplete inspection is
 *       reported as such — never as {@link Verdict#NO_EVIDENCE}.</li>
 * </ul>
 */
public final class VerdictEngine {

    private VerdictEngine() {
    }

    public static Assessment assess(List<Finding> findings, Coverage coverage, EnvironmentInfo env) {
        List<Assessment.Reason> reasons = new ArrayList<>();
        Map<String, List<Integer>> detections = bySubject(findings, f -> f.kind() == EvidenceKind.DETECTION);
        Map<String, List<Integer>> review = bySubject(findings, f ->
                (f.kind() == EvidenceKind.INDICATOR || f.kind() == EvidenceKind.CONCEALMENT)
                        && f.severity().rank() >= Severity.MEDIUM.rank());

        Verdict outcome;
        if (!detections.isEmpty()) {
            outcome = Verdict.VALIDATED_DETECTION;
            detections.forEach((subject, ids) -> reasons.add(new Assessment.Reason("detection.exact",
                    "Known cheat artefact identified by exact hash: " + subject, ids)));
            review.forEach((subject, ids) -> reasons.add(reviewReason(findings, subject, ids)));
        } else if (!review.isEmpty()) {
            outcome = Verdict.REVIEW_REQUIRED;
            review.forEach((subject, ids) -> reasons.add(reviewReason(findings, subject, ids)));
        } else if (!coverage.platformSupported()) {
            outcome = Verdict.UNSUPPORTED_CONFIGURATION;
            reasons.add(new Assessment.Reason("platform.unsupported", coverage.platformNote(), List.of()));
        } else if (!coverage.complete()) {
            outcome = Verdict.INCOMPLETE_SCAN;
        } else {
            outcome = Verdict.NO_EVIDENCE;
            reasons.add(new Assessment.Reason("coverage.complete", "All " + coverage.required().size()
                    + " required collectors completed and nothing needs review. This is not proof that the"
                    + " PC is clean: it covers only what these collectors can see.", List.of()));
        }
        if (!coverage.complete()) {
            reasons.addAll(coverageReasons(coverage));
        }
        return new Assessment(outcome, reasons, coverage, assurance(findings, coverage, env));
    }

    private static Assessment.Reason reviewReason(List<Finding> findings, String subject, List<Integer> ids) {
        boolean concealment = ids.stream().allMatch(i -> findings.get(i - 1).kind() == EvidenceKind.CONCEALMENT);
        long collectors = ids.stream().map(i -> findings.get(i - 1).module()).distinct().count();
        String text = (concealment ? "Signs of removed or hidden evidence: " : "Indicator needs review: ") + subject
                + (collectors > 1 ? " (seen by " + collectors + " collectors — one subject, counted once)" : "");
        return new Assessment.Reason(concealment ? "review.concealment" : "review.indicator", text, ids);
    }

    private static List<Assessment.Reason> coverageReasons(Coverage coverage) {
        List<Assessment.Reason> out = new ArrayList<>();
        if (!coverage.elevated()) {
            out.add(new Assessment.Reason("coverage.privileges",
                    "The checker ran without administrator/root rights, so protected locations were not inspected.",
                    List.of()));
        }
        if (!coverage.rulesOk()) {
            out.add(new Assessment.Reason("coverage.rules", "No trusted detection rules were available ("
                    + coverage.rules().origin() + ", " + coverage.rules().count() + " rules), so collectors had"
                    + " nothing to match against.", List.of()));
        }
        List<String> missing = coverage.missing();
        if (!missing.isEmpty()) {
            StringBuilder sb = new StringBuilder("Required collectors did not complete: ");
            for (int i = 0; i < missing.size(); i++) {
                String id = missing.get(i);
                sb.append(i > 0 ? ", " : "").append(id).append(" (")
                        .append(coverage.modules().getOrDefault(id, ModuleStatus.PENDING));
                String err = coverage.errors().get(id);
                if (err != null) {
                    sb.append(": ").append(err);
                }
                sb.append(')');
            }
            out.add(new Assessment.Reason("coverage.missing", sb.toString(), List.of()));
        }
        return out;
    }

    static Assurance assurance(List<Finding> findings, Coverage coverage, EnvironmentInfo env) {
        List<Assurance.Note> notes = new ArrayList<>();
        Assurance.Level level = Assurance.Level.STANDARD;
        if (!coverage.platformSupported()) {
            notes.add(new Assurance.Note("platform.unsupported", coverage.platformNote()));
            level = Assurance.Level.LOW;
        }
        if (!coverage.elevated()) {
            notes.add(new Assurance.Note("privileges.missing", "Not elevated: collectors saw a partial view."));
            level = Assurance.Level.LOW;
        }
        RulesProvenance rules = coverage.rules();
        if (!rules.trusted()) {
            notes.add(new Assurance.Note("rules.untrusted", "Detection rules did not come from the build or a signed"
                    + " update (" + rules.origin() + ")."));
            level = Assurance.Level.LOW;
        } else if (rules.note() != null) {
            notes.add(new Assurance.Note("rules.override-ignored", "Someone placed a rule file next to the checker: "
                    + rules.note() + "."));
            level = min(level, Assurance.Level.REDUCED);
        }
        String hash = env.selfHash();
        if (hash == null || hash.isBlank() || hash.equals("dev-run") || hash.equals("unknown")) {
            notes.add(new Assurance.Note("build.unidentified",
                    "The checker could not hash its own program file (development or unpacked build)."));
            level = min(level, Assurance.Level.REDUCED);
        }
        for (Finding f : findings) {
            if (f.kind() == EvidenceKind.CONFIGURATION) {
                notes.add(new Assurance.Note("config." + f.ruleId(), f.title()));
                level = min(level, Assurance.Level.REDUCED);
            }
        }
        return new Assurance(level, notes);
    }

    private static Assurance.Level min(Assurance.Level a, Assurance.Level b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    /** Subject → 1-based evidence indexes, in finding order. */
    private static Map<String, List<Integer>> bySubject(List<Finding> findings, Predicate<Finding> keep) {
        Map<String, List<Integer>> out = new LinkedHashMap<>();
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            if (keep.test(f)) {
                out.computeIfAbsent(Analysis.subjectOf(f), k -> new ArrayList<>()).add(i + 1);
            }
        }
        return out;
    }
}

package ru.moon.checker.core;

import java.util.List;

/**
 * The conclusion of a scan, kept apart from the evidence it rests on.
 *
 * @param outcome   what the evidence supports
 * @param reasons   why, each pointing at the evidence ids it relies on
 * @param coverage  what was inspected
 * @param assurance how far the report itself can be trusted
 */
public record Assessment(Verdict outcome, List<Reason> reasons, Coverage coverage, Assurance assurance) {

    /**
     * One step of the reasoning.
     *
     * @param code     stable code (e.g. {@code detection.hash}, {@code coverage.missing})
     * @param text     human explanation
     * @param evidence 1-based evidence indexes (E1, E2...) this reason relies on
     */
    public record Reason(String code, String text, List<Integer> evidence) {
        public Reason {
            evidence = List.copyOf(evidence);
        }
    }

    public Assessment {
        reasons = List.copyOf(reasons);
    }
}

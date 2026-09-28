package ru.moon.checker.core;

/**
 * How urgently a reviewer should look at a finding. Used for ordering and
 * display only — severities are never added up or turned into a score; the
 * verdict comes from {@link EvidenceKind} and coverage (see {@link VerdictEngine}).
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** Rank used for sorting most-severe first. */
    public int rank() {
        return ordinal();
    }
}

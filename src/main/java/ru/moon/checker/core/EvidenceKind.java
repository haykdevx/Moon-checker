package ru.moon.checker.core;

/**
 * What a finding is evidence of. The verdict is derived from the kind, never
 * from adding severities together (see {@link VerdictEngine}).
 */
public enum EvidenceKind {
    /**
     * Exact identity of a known cheat artefact — a SHA-256 equal to a sample a
     * maintainer classified. The only kind that can produce
     * {@link Verdict#VALIDATED_DETECTION}.
     */
    DETECTION,
    /**
     * A heuristic or name-based match (process/window/file names, domains,
     * loaded modules, suspicious locations). Spoofable and has legitimate
     * lookalikes, so at most it asks for a human review.
     */
    INDICATOR,
    /** Signs that evidence was removed or hidden (journal reset, logs cleared). */
    CONCEALMENT,
    /**
     * A security or platform setting (test signing, weak boot options, VM).
     * Lowers the collector assurance; never a cheating verdict on its own.
     */
    CONFIGURATION,
    /** Background for the reviewer (accounts on the PC, VAC history). */
    CONTEXT
}

package ru.moon.checker.core;

/**
 * Severity of a single finding. Weight feeds the aggregate score; a CRITICAL
 * finding forces a CHEAT verdict on its own (see {@link ScoreCalculator}).
 */
public enum Severity {
    INFO(0),
    LOW(5),
    MEDIUM(12),
    HIGH(30),
    CRITICAL(100);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }

    /** Rank used for sorting most-severe first. */
    public int rank() {
        return ordinal();
    }
}

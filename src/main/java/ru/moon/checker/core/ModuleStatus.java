package ru.moon.checker.core;

/** Outcome of running a single {@link CheckModule}. */
public enum ModuleStatus {
    /** Completed normally. */
    OK("status.ok"),
    /** Not applicable on this platform / preconditions not met. */
    SKIPPED("status.skipped"),
    /** Threw an exception; partial or no results. */
    ERROR("status.error"),
    /** Exceeded its time budget and was stopped. */
    TIMEOUT("status.timeout"),
    /** Not started yet (UI initial state). */
    PENDING("status.pending"),
    /** Currently running (UI state). */
    RUNNING("status.running");

    private final String key;

    ModuleStatus(String key) {
        this.key = key;
    }

    public String key() {
        return key;
    }
}

package ru.moon.checker.core;

/**
 * A single inspection unit (files, prefetch, browser history, drivers...).
 * Modules are stateless with respect to each other and run concurrently, so
 * an implementation must only touch its own resources and emit findings
 * through the {@link ScanContext}.
 */
public interface CheckModule {

    /** Stable identifier, also used as the {@link Finding#module()} value. */
    String id();

    /** Localised display name (via {@link I18n}). */
    String displayName();

    Category category();

    /**
     * Perform the check. Should be resilient: catch its own recoverable errors,
     * check {@link ScanContext#isCancelled()} inside long loops, and never
     * throw for a merely-empty result. Throwing marks the module ERROR.
     */
    void run(ScanContext ctx) throws Exception;

    /**
     * If true the engine skips the module on non-Windows hosts (marking it
     * SKIPPED) instead of running it. Almost every module is Windows-only.
     */
    default boolean windowsOnly() {
        return true;
    }
}

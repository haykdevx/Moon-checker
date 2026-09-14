package ru.moon.checker.core;

/**
 * Overall outcome shown to the admin. The player only ever sees a neutral
 * "check complete" screen; the verdict and score are for the admin watching
 * the Discord screen share.
 */
public enum Verdict {
    CLEAN("#37d67a"),
    SUSPICIOUS("#f6b949"),
    CHEAT("#ff5a5a"),
    /** A scan that could not complete (not run as admin, crashed module...). */
    INCONCLUSIVE("#b6b6b6");

    private final String color;

    Verdict(String color) {
        this.color = color;
    }

    /** Hex color used by the UI and HTML report. */
    public String color() {
        return color;
    }
}

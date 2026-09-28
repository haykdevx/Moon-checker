package ru.moon.checker.core;

import java.time.Instant;

/**
 * The player's consent to this inspection, recorded in the evidence bundle.
 *
 * @param textVersion version of the notice the player was shown ({@link #TEXT_VERSION})
 * @param acceptedAt  when Start was pressed (or the operator ran the CLI)
 * @param channel     {@code gui}, {@code cli}, or {@code none} when not recorded
 */
public record Consent(String textVersion, Instant acceptedAt, String channel) {

    /** Bump whenever the start-screen notice (start.privacy*, start.intro) changes meaning. */
    public static final String TEXT_VERSION = "2026-09-28";

    public static Consent gui() {
        return new Consent(TEXT_VERSION, Instant.now(), "gui");
    }

    public static Consent cli() {
        return new Consent(TEXT_VERSION, Instant.now(), "cli");
    }

    public static Consent none() {
        return new Consent("", null, "none");
    }
}

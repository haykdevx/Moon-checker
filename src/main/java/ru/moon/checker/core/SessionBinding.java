package ru.moon.checker.core;

/**
 * Which panel check a report is made for (upload protocol 3). The panel issues a random,
 * single-use upload value when the code is entered; it goes into the evidence together with
 * the panel's session id, is covered by the report's hash and verification code, and the
 * panel accepts exactly one report carrying it.
 *
 * <p>What this establishes: the report was produced — or edited — for this check after the
 * code was entered, and an unmodified report from another check cannot be delivered here.
 * What it does not: that an unmodified checker produced it. The value travels through the
 * player's PC like everything else (docs/report-assurance.md).
 */
public record SessionBinding(String panelSessionId, String uploadNonce, int protocol) {

    /** The upload protocol this checker speaks. */
    public static final int PROTOCOL = 3;
}

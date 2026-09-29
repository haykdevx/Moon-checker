package ru.moon.checker.net;

/**
 * A claimed check session: the result of entering the admin's code.
 *
 * @param sessionId        server id of the check
 * @param token            per-session bearer secret (never logged)
 * @param adminAlias       the admin's public alias, shown to the player
 * @param adminName        display name (may equal the alias)
 * @param playerName       the name the admin entered for this player
 * @param heartbeatSeconds how often the checker should report progress
 * @param statusUrl        the player's private page for this check (may be empty)
 * @param uploadProtocol   the upload protocol the panel expects (3: the report carries a binding)
 * @param uploadNonce      single-use value to put into the report (never logged; empty before protocol 3)
 */
public record SessionLink(String sessionId, String token, String adminAlias, String adminName,
                          String playerName, int heartbeatSeconds, String statusUrl,
                          int uploadProtocol, String uploadNonce) {

    /** What goes into the evidence so the panel accepts it for this check only; null if the panel wants none. */
    public ru.moon.checker.core.SessionBinding binding() {
        return uploadNonce == null || uploadNonce.isBlank() ? null
                : new ru.moon.checker.core.SessionBinding(sessionId, uploadNonce, uploadProtocol);
    }

    @Override
    public String toString() {
        return "SessionLink[" + sessionId + ", admin=" + adminAlias + "]"; // keep the token out of logs
    }
}

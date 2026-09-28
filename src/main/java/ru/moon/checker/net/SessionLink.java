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
 */
public record SessionLink(String sessionId, String token, String adminAlias, String adminName,
                          String playerName, int heartbeatSeconds, String statusUrl) {

    @Override
    public String toString() {
        return "SessionLink[" + sessionId + ", admin=" + adminAlias + "]"; // keep the token out of logs
    }
}

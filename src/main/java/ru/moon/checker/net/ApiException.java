package ru.moon.checker.net;

import ru.moon.checker.core.I18n;

/**
 * A failed call to the Moon panel.
 *
 * @see #code() the server's error code ({@code invalid_code}, {@code code_expired}...) or
 *      {@code network} / {@code server} / {@code protocol} for local classifications
 */
public final class ApiException extends Exception {

    private final int status;
    private final String code;
    private final String serverMessage;
    private final String download;
    private final String verificationCode;

    public ApiException(int status, String code, String serverMessage, String download, String verificationCode) {
        super(code + " (" + status + "): " + serverMessage);
        this.status = status;
        this.code = code;
        this.serverMessage = serverMessage;
        this.download = download;
        this.verificationCode = verificationCode;
    }

    public static ApiException network(Throwable cause) {
        String why = cause.getClass().getSimpleName()
                + (cause.getMessage() != null ? ": " + cause.getMessage() : "");
        ApiException e = new ApiException(0, "network", why, null, null);
        e.initCause(cause);
        return e;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    /** For a 409 "already delivered": the code the server computed for the stored report. */
    public String verificationCode() {
        return verificationCode;
    }

    /** Worth retrying automatically: connection problems, 5xx, 429. */
    public boolean retryable() {
        return status == 0 || status == 429 || status >= 500;
    }

    /** Message for the player, localised where we know the error code. */
    public String describe(String host) {
        String key = "net.err." + code;
        String text = I18n.t(key, download != null ? download : host);
        if (!text.equals(key)) {
            return text;
        }
        if (status >= 500) {
            return I18n.t("net.err.server", status);
        }
        return serverMessage != null && !serverMessage.isBlank() ? serverMessage : code;
    }
}

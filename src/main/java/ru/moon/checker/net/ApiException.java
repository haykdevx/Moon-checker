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
        ApiException e = new ApiException(0, classify(cause), why, null, null);
        e.initCause(cause);
        return e;
    }

    /**
     * What went wrong on the way to the panel, so the player gets a message that
     * says what to do: {@code dns} (no internet / name not resolved), {@code timeout},
     * {@code tls} (certificate — often antivirus HTTPS scanning or a wrong PC clock),
     * {@code proxy}, {@code unreachable} (refused / no route), else {@code network}.
     */
    static String classify(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause() == c ? null : c.getCause()) {
            String msg = String.valueOf(c.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (c instanceof java.nio.channels.UnresolvedAddressException
                    || c instanceof java.net.UnknownHostException) {
                return "dns";
            }
            if (c instanceof java.net.http.HttpTimeoutException || c instanceof java.net.SocketTimeoutException) {
                return "timeout";
            }
            if (c instanceof javax.net.ssl.SSLException
                    || c instanceof java.security.cert.CertificateException) {
                return "tls";
            }
            if (msg.contains("proxy") || msg.contains("tunnel") || msg.contains("407")) {
                return "proxy";
            }
            if (c instanceof java.net.ConnectException || c instanceof java.net.NoRouteToHostException) {
                // HttpClient wraps an unresolved name in a bare ConnectException: look deeper first
                String deeper = c.getCause() != null && c.getCause() != c ? classify(c.getCause()) : "network";
                return deeper.equals("network") ? "unreachable" : deeper;
            }
        }
        return "network";
    }

    /**
     * A non-JSON answer: a captive portal (hotel / café Wi-Fi login page, or a
     * provider's block page) answers with HTML or a redirect instead of the panel;
     * a proxy asks for credentials with 407.
     */
    static String classifyHttp(int status, byte[] body) {
        if (status == 407) {
            return "proxy";
        }
        if (status >= 300 && status < 400) {
            return "captive";
        }
        String head = body == null ? "" : new String(body, 0, Math.min(body.length, 512),
                java.nio.charset.StandardCharsets.ISO_8859_1).toLowerCase(java.util.Locale.ROOT).strip();
        if (status >= 200 && status < 300 && (head.startsWith("<") || head.contains("<html"))) {
            return "captive";
        }
        return status >= 500 ? "server" : "protocol";
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

    /** Worth retrying automatically: connection problems (not certificates), 5xx, 429. */
    public boolean retryable() {
        return (status == 0 && !"tls".equals(code)) || status == 429 || status >= 500;
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

package ru.moon.checker.net;

import java.io.InputStream;
import java.io.Reader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Properties;

/**
 * Where results are sent. Resolution order: {@code --server URL}, then
 * {@code moon.properties} next to the exe, then the bundled
 * {@code moon-client.properties}. {@code --offline} (or an empty URL) turns the
 * link off and the checker works standalone, exactly like before.
 *
 * <p>Evidence is personal data, so plain {@code http://} is only accepted for
 * loopback addresses (local testing); everything else must be HTTPS.
 *
 * @param base   panel root, e.g. {@code https://moon.example.org}; null when offline
 * @param origin where the URL came from (for logs / diagnostics)
 * @param error  why a configured URL was rejected, or null
 */
public record ServerConfig(URI base, String origin, String error) {

    public static final String KEY = "server.url";
    public static final String OVERRIDE_FILE = "moon.properties";
    private static final String BUNDLED = "/moon-client.properties";

    public static ServerConfig offline(String why) {
        return new ServerConfig(null, why, null);
    }

    public boolean online() {
        return base != null;
    }

    /** Human-readable host for messages ("moon.example.org"). */
    public String host() {
        return base == null ? "-" : base.getHost();
    }

    public static ServerConfig resolve(String cliUrl, boolean offline, Path exeDir) {
        if (offline) {
            return offline("--offline");
        }
        if (cliUrl != null) {
            return parse(cliUrl, "--server");
        }
        if (exeDir != null) {
            Path file = exeDir.resolve(OVERRIDE_FILE);
            if (Files.isRegularFile(file)) {
                try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    Properties p = new Properties();
                    p.load(r);
                    if (p.containsKey(KEY)) {
                        return parse(p.getProperty(KEY), file.toString());
                    }
                } catch (Exception e) {
                    return new ServerConfig(null, file.toString(), "unreadable: " + e.getMessage());
                }
            }
        }
        try (InputStream in = ServerConfig.class.getResourceAsStream(BUNDLED)) {
            if (in != null) {
                Properties p = new Properties();
                p.load(new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
                return parse(p.getProperty(KEY, ""), "bundled");
            }
        } catch (Exception ignored) {
            // fall through to offline
        }
        return offline("not configured");
    }

    static ServerConfig parse(String raw, String origin) {
        String v = raw == null ? "" : raw.trim();
        if (v.isEmpty()) {
            return offline(origin + " (empty)");
        }
        try {
            URI u = URI.create(v.endsWith("/") ? v.substring(0, v.length() - 1) : v);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            String host = u.getHost();
            if (host == null || u.getUserInfo() != null || u.getQuery() != null || u.getFragment() != null) {
                return new ServerConfig(null, origin, "not a valid server URL: " + v);
            }
            boolean loopback = host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]");
            if (!scheme.equals("https") && !(scheme.equals("http") && loopback)) {
                return new ServerConfig(null, origin, "server URL must use https: " + v);
            }
            return new ServerConfig(u, origin, null);
        } catch (IllegalArgumentException e) {
            return new ServerConfig(null, origin, "not a valid server URL: " + v);
        }
    }
}

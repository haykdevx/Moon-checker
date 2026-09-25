package ru.moon.checker.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads visited-URL history from Chromium-family and Firefox SQLite databases.
 * Only used to match URLs against the cheat-domain signature list; the checker
 * never exports or displays a player's full browsing history — only the
 * matching entries become findings.
 *
 * <p>Databases are read from a private {@link #snapshot snapshot} (the file plus
 * its {@code -wal}/{@code -journal} siblings): a running browser may hold locks
 * on the live file, and Firefox keeps its most recent visits in
 * {@code places.sqlite-wal} until a checkpoint. Only when a snapshot cannot be
 * taken is the live file opened, in {@code immutable} mode so nothing in the
 * player's profile is ever written.
 */
public final class BrowserHistory {

    private BrowserHistory() {
    }

    public record Visit(String url, String title, Instant lastVisit) {
    }

    public record Download(String targetPath, String url, Instant when) {
    }

    private static final long WIN_EPOCH_DELTA_MS = 11_644_473_600_000L;
    private static final String[] SIBLINGS = {"-wal", "-journal"};

    @FunctionalInterface
    private interface Row<T> {
        T map(ResultSet rs) throws SQLException;
    }

    /**
     * JDBC URL for a database file. The path is emitted as a percent-encoded
     * {@code file:} URI: concatenating a raw path breaks on {@code #}, {@code ?}
     * or {@code %} in a profile folder, and SQLite then silently opens nothing.
     *
     * @param live true for a file owned by a running browser: opened read-only and
     *             immutable (no locks, no {@code -shm} created, WAL ignored)
     */
    public static String jdbcUrl(Path db, boolean live) {
        String uri = db.toAbsolutePath().toUri().toASCIIString();
        return "jdbc:sqlite:" + uri + (live ? "?mode=ro&immutable=1" : "");
    }

    /**
     * Copies {@code db} and its write-ahead / rollback journals into
     * {@code dir} under {@code name}. Returns the copy, or null when the file
     * cannot be copied (locked by a browser, unreadable profile). Current Edge on
     * Windows 11 does not lock {@code History}; copying works while it runs.
     */
    public static Path snapshot(Path db, Path dir, String name) {
        try {
            Path copy = dir.resolve(name);
            Files.copy(db, copy, StandardCopyOption.REPLACE_EXISTING);
            for (String suffix : SIBLINGS) {
                Path side = db.resolveSibling(db.getFileName() + suffix);
                if (Files.isRegularFile(side)) {
                    Files.copy(side, dir.resolve(name + suffix), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            return copy;
        } catch (Exception e) {
            return null;
        }
    }

    /** Chromium "History": urls(url,title,last_visit_time micros since 1601). */
    public static List<Visit> readChromium(Path db) {
        return readChromium(db, false);
    }

    public static List<Visit> readChromium(Path db, boolean live) {
        return query(db, live, "SELECT url, title, last_visit_time FROM urls",
                rs -> new Visit(rs.getString(1), rs.getString(2), chromiumTime(rs.getLong(3))));
    }

    /** Firefox "places.sqlite": moz_places(url,title,last_visit_date micros since 1970). */
    public static List<Visit> readFirefox(Path db) {
        return readFirefox(db, false);
    }

    public static List<Visit> readFirefox(Path db, boolean live) {
        return query(db, live, "SELECT url, title, last_visit_date FROM moz_places", rs -> {
            long t = rs.getLong(3);
            return new Visit(rs.getString(1), rs.getString(2), t > 0 ? Instant.ofEpochMilli(t / 1000) : null);
        });
    }

    /** Chromium "History": downloads(current_path, tab_url, start_time). */
    public static List<Download> readChromiumDownloads(Path db) {
        return readChromiumDownloads(db, false);
    }

    public static List<Download> readChromiumDownloads(Path db, boolean live) {
        return query(db, live, "SELECT current_path, tab_url, start_time FROM downloads",
                rs -> new Download(rs.getString(1), rs.getString(2), chromiumTime(rs.getLong(3))));
    }

    /** Firefox "places.sqlite": bookmarked URLs (moz_bookmarks + moz_places). */
    public static List<String> readFirefoxBookmarkUrls(Path db) {
        return readFirefoxBookmarkUrls(db, false);
    }

    public static List<String> readFirefoxBookmarkUrls(Path db, boolean live) {
        return query(db, live,
                "SELECT p.url FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.type = 1",
                rs -> rs.getString(1));
    }

    /** Chromium "Bookmarks" JSON: every bookmarked URL. */
    public static List<String> readChromiumBookmarkUrls(Path bookmarksJson) {
        List<String> out = new ArrayList<>();
        try {
            if (!Files.isRegularFile(bookmarksJson)) {
                return out;
            }
            JsonNode root = new ObjectMapper().readTree(bookmarksJson.toFile());
            JsonNode roots = root.get("roots");
            if (roots != null) {
                roots.forEach(node -> collectBookmarkUrls(node, out));
            }
        } catch (Exception e) {
            // ignore
        }
        return out;
    }

    private static void collectBookmarkUrls(JsonNode node, List<String> out) {
        if (node == null) {
            return;
        }
        JsonNode url = node.get("url");
        if (url != null && url.isTextual()) {
            out.add(url.asText());
        }
        JsonNode children = node.get("children");
        if (children != null && children.isArray()) {
            children.forEach(child -> collectBookmarkUrls(child, out));
        }
    }

    private static <T> List<T> query(Path db, boolean live, String sql, Row<T> row) {
        List<T> out = new ArrayList<>();
        if (db == null || !Files.isRegularFile(db)) {
            return out; // never let the driver create an empty database
        }
        try (Connection c = DriverManager.getConnection(jdbcUrl(db, live));
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                out.add(row.map(rs));
            }
        } catch (Exception e) {
            // locked / corrupt / table absent (not this browser's schema)
        }
        return out;
    }

    private static Instant chromiumTime(long micros1601) {
        return micros1601 > 0 ? Instant.ofEpochMilli(micros1601 / 1000 - WIN_EPOCH_DELTA_MS) : null;
    }
}

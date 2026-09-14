package ru.moon.checker.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads visited-URL history from Chromium-family and Firefox SQLite databases.
 * Only used to match URLs against the cheat-domain signature list; the checker
 * never exports or displays a player's full browsing history — only the
 * matching entries become findings.
 */
public final class BrowserHistory {

    private BrowserHistory() {
    }

    public record Visit(String url, String title, Instant lastVisit) {
    }

    private static final long WIN_EPOCH_DELTA_MS = 11_644_473_600_000L;

    /** Chromium "History": urls(url,title,last_visit_time micros since 1601). */
    public static List<Visit> readChromium(Path db) {
        List<Visit> out = new ArrayList<>();
        String url = "jdbc:sqlite:file:" + db.toAbsolutePath() + "?mode=ro&immutable=1";
        try (Connection c = DriverManager.getConnection(url);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT url, title, last_visit_time FROM urls")) {
            while (rs.next()) {
                long t = rs.getLong(3);
                Instant when = t > 0 ? Instant.ofEpochMilli(t / 1000 - WIN_EPOCH_DELTA_MS) : null;
                out.add(new Visit(rs.getString(1), rs.getString(2), when));
            }
        } catch (Exception e) {
            // locked / missing / not a chromium db — caller tries other formats
        }
        return out;
    }

    /** Firefox "places.sqlite": moz_places(url,title,last_visit_date micros since 1970). */
    public static List<Visit> readFirefox(Path db) {
        List<Visit> out = new ArrayList<>();
        String url = "jdbc:sqlite:file:" + db.toAbsolutePath() + "?mode=ro&immutable=1";
        try (Connection c = DriverManager.getConnection(url);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT url, title, last_visit_date FROM moz_places")) {
            while (rs.next()) {
                long t = rs.getLong(3);
                Instant when = t > 0 ? Instant.ofEpochMilli(t / 1000) : null;
                out.add(new Visit(rs.getString(1), rs.getString(2), when));
            }
        } catch (Exception e) {
            // ignore
        }
        return out;
    }

    public record Download(String targetPath, String url, Instant when) {
    }

    /** Chromium "History": downloads(current_path, tab_url, start_time). */
    public static List<Download> readChromiumDownloads(Path db) {
        List<Download> out = new ArrayList<>();
        String url = "jdbc:sqlite:file:" + db.toAbsolutePath() + "?mode=ro&immutable=1";
        try (Connection c = DriverManager.getConnection(url);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT current_path, tab_url, start_time FROM downloads")) {
            while (rs.next()) {
                long t = rs.getLong(3);
                Instant when = t > 0 ? Instant.ofEpochMilli(t / 1000 - WIN_EPOCH_DELTA_MS) : null;
                out.add(new Download(rs.getString(1), rs.getString(2), when));
            }
        } catch (Exception e) {
            // table/db absent — ignore
        }
        return out;
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

    /** Firefox "places.sqlite": bookmarked URLs (moz_bookmarks + moz_places). */
    public static List<String> readFirefoxBookmarkUrls(Path db) {
        List<String> out = new ArrayList<>();
        String url = "jdbc:sqlite:file:" + db.toAbsolutePath() + "?mode=ro&immutable=1";
        try (Connection c = DriverManager.getConnection(url);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT p.url FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.type = 1")) {
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        } catch (Exception e) {
            // ignore
        }
        return out;
    }
}

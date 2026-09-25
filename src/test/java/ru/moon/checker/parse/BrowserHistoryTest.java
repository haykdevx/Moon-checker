package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BrowserHistoryTest {

    @Test
    void profilePathWithUriMetacharactersIsReadable(@TempDir Path tmp) throws Exception {
        // a raw "file:" + path URL truncates at '#' and decodes "%41" -> reads nothing
        Path dir = Files.createDirectories(tmp.resolve("Игрок #1 %41").resolve("User Data"));
        Path db = dir.resolve("History");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement st = c.createStatement()) {
            st.execute("CREATE TABLE urls (id INTEGER, url TEXT, title TEXT, last_visit_time INTEGER)");
            st.execute("INSERT INTO urls VALUES (1,'https://neverlose.cc','x',0)");
        }
        assertEquals(1, BrowserHistory.readChromium(db, true).size());
        assertEquals(1, BrowserHistory.readChromium(db, false).size());
        assertTrue(BrowserHistory.jdbcUrl(db, true).contains("%23"), "'#' must be percent-encoded");
    }

    @Test
    void snapshotIncludesUncheckpointedWalVisits(@TempDir Path tmp) throws Exception {
        Path profile = Files.createDirectories(tmp.resolve("ff"));
        Path places = profile.resolve("places.sqlite");
        // the "browser" keeps the database open, so the visit lives only in -wal
        try (Connection browser = DriverManager.getConnection("jdbc:sqlite:" + places);
             Statement st = browser.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA wal_autocheckpoint=0");
            st.execute("CREATE TABLE moz_places (id INTEGER, url TEXT, title TEXT, last_visit_date INTEGER)");
            st.execute("INSERT INTO moz_places VALUES (1,'https://nixware.cc','Nixware',0)");
            assertTrue(Files.size(profile.resolve("places.sqlite-wal")) > 0);

            Path snapDir = Files.createDirectories(tmp.resolve("snap"));
            Path snap = BrowserHistory.snapshot(places, snapDir, "h0");
            assertNotNull(snap);
            assertTrue(Files.isRegularFile(snapDir.resolve("h0-wal")));
            assertEquals(1, BrowserHistory.readFirefox(snap).size(), "WAL content must be visible");
        }
    }

    @Test
    void missingDatabaseIsNotCreated(@TempDir Path tmp) {
        Path db = tmp.resolve("History");
        assertTrue(BrowserHistory.readChromium(db).isEmpty());
        assertFalse(Files.exists(db), "reader must not create files in a player's profile");
        assertNull(BrowserHistory.snapshot(db, tmp, "x"));
    }

    @Test
    void readsChromiumUrlsTable() throws Exception {
        Path db = Files.createTempFile("moon-chromium", ".db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement st = c.createStatement()) {
            st.execute("CREATE TABLE urls (id INTEGER, url TEXT, title TEXT, last_visit_time INTEGER)");
            // 2021-01-01 in chromium micros since 1601
            long t = (1609459200000L + 11_644_473_600_000L) * 1000L;
            st.execute("INSERT INTO urls VALUES (1,'https://neverlose.cc/market','Neverlose'," + t + ")");
            st.execute("INSERT INTO urls VALUES (2,'https://google.com','Google',0)");
        }
        List<BrowserHistory.Visit> visits = BrowserHistory.readChromium(db);
        assertEquals(2, visits.size());
        assertTrue(visits.stream().anyMatch(v -> v.url().contains("neverlose.cc")));
        BrowserHistory.Visit neverlose = visits.stream()
                .filter(v -> v.url().contains("neverlose")).findFirst().orElseThrow();
        assertNotNull(neverlose.lastVisit());
        Files.deleteIfExists(db);
    }

    @Test
    void readsChromiumDownloads() throws Exception {
        Path db = Files.createTempFile("moon-dl", ".db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement st = c.createStatement()) {
            st.execute("CREATE TABLE downloads (id INTEGER, current_path TEXT, tab_url TEXT, start_time INTEGER)");
            long t = (1609459200000L + 11_644_473_600_000L) * 1000L;
            st.execute("INSERT INTO downloads VALUES (1,'C:\\Users\\p\\Downloads\\nixware.exe','https://nixware.cc/dl'," + t + ")");
        }
        var dls = BrowserHistory.readChromiumDownloads(db);
        assertEquals(1, dls.size());
        assertTrue(dls.get(0).targetPath().endsWith("nixware.exe"));
        assertEquals("https://nixware.cc/dl", dls.get(0).url());
        Files.deleteIfExists(db);
    }

    @Test
    void readsChromiumBookmarks() throws Exception {
        Path json = Files.createTempFile("moon-bm", ".json");
        Files.writeString(json, """
                {"roots":{"bookmark_bar":{"children":[
                  {"type":"url","name":"cheat","url":"https://neverlose.cc/market"},
                  {"type":"folder","children":[{"type":"url","name":"x","url":"https://example.com"}]}
                ]}}}
                """);
        var urls = BrowserHistory.readChromiumBookmarkUrls(json);
        assertTrue(urls.stream().anyMatch(u -> u.contains("neverlose.cc")));
        assertTrue(urls.stream().anyMatch(u -> u.contains("example.com")));
        Files.deleteIfExists(json);
    }

    @Test
    void readsFirefoxBookmarks() throws Exception {
        Path db = Files.createTempFile("moon-ffbm", ".db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement st = c.createStatement()) {
            st.execute("CREATE TABLE moz_places (id INTEGER, url TEXT)");
            st.execute("CREATE TABLE moz_bookmarks (id INTEGER, type INTEGER, fk INTEGER)");
            st.execute("INSERT INTO moz_places VALUES (10,'https://skeet.cc')");
            st.execute("INSERT INTO moz_bookmarks VALUES (1,1,10)");
        }
        var urls = BrowserHistory.readFirefoxBookmarkUrls(db);
        assertEquals(1, urls.size());
        assertTrue(urls.get(0).contains("skeet.cc"));
        Files.deleteIfExists(db);
    }

    @Test
    void readsFirefoxPlacesTable() throws Exception {
        Path db = Files.createTempFile("moon-firefox", ".db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement st = c.createStatement()) {
            st.execute("CREATE TABLE moz_places (id INTEGER, url TEXT, title TEXT, last_visit_date INTEGER)");
            long micros = 1609459200000L * 1000L; // micros since 1970
            st.execute("INSERT INTO moz_places VALUES (1,'https://nixware.cc','Nixware'," + micros + ")");
        }
        List<BrowserHistory.Visit> visits = BrowserHistory.readFirefox(db);
        assertEquals(1, visits.size());
        assertTrue(visits.get(0).url().contains("nixware.cc"));
        assertNotNull(visits.get(0).lastVisit());
        Files.deleteIfExists(db);
    }
}

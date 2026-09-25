package ru.moon.checker.net;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ServerConfigTest {

    @Test
    void httpsIsAcceptedAndTrailingSlashDropped() {
        ServerConfig c = ServerConfig.parse("https://moon.example.org/", "test");
        assertTrue(c.online());
        assertEquals("https://moon.example.org", c.base().toString());
        assertEquals("moon.example.org", c.host());
    }

    @Test
    void plainHttpOnlyForLoopback() {
        assertTrue(ServerConfig.parse("http://127.0.0.1:8000", "t").online());
        assertTrue(ServerConfig.parse("http://localhost:8000", "t").online());
        ServerConfig remote = ServerConfig.parse("http://moon.example.org", "t");
        assertFalse(remote.online());
        assertNotNull(remote.error());
    }

    @Test
    void junkIsRejected() {
        for (String bad : new String[]{"ftp://x", "https://user:pw@x.org", "not a url", "https://x.org/?a=1"}) {
            ServerConfig c = ServerConfig.parse(bad, "t");
            assertFalse(c.online(), bad);
            assertNotNull(c.error(), bad);
        }
        assertNull(ServerConfig.parse("  ", "t").error()); // empty just means offline
    }

    @Test
    void resolutionOrder(@TempDir Path dir) throws Exception {
        assertFalse(ServerConfig.resolve("https://cli.example.org", true, dir).online(), "--offline wins");
        assertEquals("cli.example.org", ServerConfig.resolve("https://cli.example.org", false, dir).host());

        Files.writeString(dir.resolve("moon.properties"), "server.url=https://file.example.org\n");
        assertEquals("file.example.org", ServerConfig.resolve(null, false, dir).host());

        Files.writeString(dir.resolve("moon.properties"), "server.url=\n");
        assertFalse(ServerConfig.resolve(null, false, dir).online(), "an empty override disables the link");
    }

    @Test
    void bundledDefaultIsHttps() {
        ServerConfig c = ServerConfig.resolve(null, false, null);
        assertTrue(c.online(), "bundled moon-client.properties should point at the panel");
        assertEquals("https", c.base().getScheme());
    }
}

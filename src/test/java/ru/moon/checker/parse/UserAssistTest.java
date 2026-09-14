package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class UserAssistTest {

    @Test
    void rot13RoundTrips() {
        String plain = "C:\\Users\\Player\\Downloads\\loader.exe";
        String encoded = UserAssist.decodeName(plain); // ROT13 is symmetric
        assertNotEquals(plain, encoded);
        assertEquals(plain, UserAssist.decodeName(encoded));
    }

    @Test
    void decodesKnownRot13() {
        // "nixware" ROT13 -> "avkjner"
        assertEquals("nixware", UserAssist.decodeName("avkjner"));
    }

    @Test
    void parsesRunCountAndFileTime() {
        byte[] data = new byte[68];
        // run count = 7 at offset 4 (LE)
        data[4] = 7;
        // FILETIME for 2021-01-01T00:00:00Z at offset 60
        long filetime = (1609459200000L + 11_644_473_600_000L) * 10_000L;
        for (int i = 0; i < 8; i++) {
            data[60 + i] = (byte) (filetime >>> (8 * i));
        }
        UserAssist.Entry e = UserAssist.parse("avkjner", data);
        assertEquals("nixware", e.path());
        assertEquals(7, e.runCount());
        assertEquals(Instant.parse("2021-01-01T00:00:00Z"), e.lastRun());
    }

    @Test
    void fileTimeZeroIsNull() {
        assertNull(UserAssist.fileTimeToInstant(0));
    }
}

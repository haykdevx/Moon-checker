package ru.moon.checker.win;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AlternateStreamsTest {

    @Test
    void cleanNameStripsColonsAndDataSuffix() {
        assertEquals("cheat", AlternateStreams.cleanName(":cheat:$DATA"));
        assertEquals("", AlternateStreams.cleanName("::$DATA"));
        assertEquals("Zone.Identifier", AlternateStreams.cleanName(":Zone.Identifier:$DATA"));
        assertNull(AlternateStreams.cleanName(null));
    }
}

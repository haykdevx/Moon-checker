package ru.moon.checker.linux;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LinuxInfoTest {

    @Test
    void decodesOutOfTreeTaintBit() {
        String d = LinuxInfo.taintDescription(1L << 12);
        assertTrue(d.contains("out-of-tree"), d);
    }

    @Test
    void decodesUnsignedTaintBit() {
        String d = LinuxInfo.taintDescription(1L << 13);
        assertTrue(d.contains("unsigned"), d);
    }

    @Test
    void decodesForceLoadedBit() {
        String d = LinuxInfo.taintDescription(1L << 1);
        assertTrue(d.toLowerCase().contains("force"), d);
    }

    @Test
    void cleanTaintHasNoFlags() {
        assertEquals("flags=0", LinuxInfo.taintDescription(0));
    }
}

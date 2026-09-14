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
    void sysModulesIgnoresBuiltInModules() throws Exception {
        // built-in modules have a /sys/module dir but no initstate file, and
        // never appear in /proc/modules — counting them floods the hidden-module
        // check with false positives (131 on a stock Ubuntu kernel).
        java.nio.file.Path root = java.nio.file.Files.createTempDirectory("sysmod");
        java.nio.file.Path loadable = java.nio.file.Files.createDirectory(root.resolve("nvidia"));
        java.nio.file.Files.writeString(loadable.resolve("initstate"), "live\n");
        java.nio.file.Files.createDirectory(root.resolve("acpi")); // built-in, no initstate

        var mods = LinuxInfo.sysModules(root);
        assertEquals(java.util.List.of("nvidia"), mods);
    }

    @Test
    void cleanTaintHasNoFlags() {
        assertEquals("flags=0", LinuxInfo.taintDescription(0));
    }
}

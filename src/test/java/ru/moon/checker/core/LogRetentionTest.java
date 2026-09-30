package ru.moon.checker.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;

class LogRetentionTest {

    @Test
    void oldLogFilesAreDeletedAndOtherFilesAreLeftAlone(@TempDir Path dir) throws Exception {
        String old = "moon-" + LocalDate.now().minusDays(20).format(DateTimeFormatter.BASIC_ISO_DATE) + ".log";
        String recent = "moon-" + LocalDate.now().minusDays(2).format(DateTimeFormatter.BASIC_ISO_DATE) + ".log";
        Files.writeString(dir.resolve(old), "x");
        Files.writeString(dir.resolve(recent), "x");
        Files.writeString(dir.resolve("notes.txt"), "not ours");
        assertEquals(1, Log.pruneOld(dir, Log.KEEP_DAYS));
        assertFalse(Files.exists(dir.resolve(old)));
        assertTrue(Files.exists(dir.resolve(recent)));
        assertTrue(Files.exists(dir.resolve("notes.txt")));
    }
}

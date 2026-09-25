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

    @Test
    void metadataStreamsAreBenignOnlyAtMetadataSize() {
        assertTrue(AlternateStreams.isBenign(new AlternateStreams.Stream("Zone.Identifier", 120)));
        assertTrue(AlternateStreams.isBenign(new AlternateStreams.Stream("SmartScreen", 7)));
        // seen 28x on a clean Windows 11 25H2 install (xml_file*.xml in %TEMP%)
        assertTrue(AlternateStreams.isBenign(new AlternateStreams.Stream("StreamedFileState", 32)));
        assertTrue(AlternateStreams.isBenign(new AlternateStreams.Stream("com.dropbox.attributes", 400)));
        // a 300 KB "Zone.Identifier" is a payload wearing a benign name
        assertFalse(AlternateStreams.isBenign(new AlternateStreams.Stream("Zone.Identifier", 300_000)));
        assertFalse(AlternateStreams.isBenign(new AlternateStreams.Stream("hidden", 5)));
    }
}

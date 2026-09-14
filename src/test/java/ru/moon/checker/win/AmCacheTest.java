package ru.moon.checker.win;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AmCacheTest {

    private static final String SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    @Test
    void stripsFileIdPrefix() {
        assertEquals(SHA1, AmCache.normalizeFileId("0000" + SHA1));
    }

    @Test
    void acceptsBareSha1() {
        assertEquals(SHA1, AmCache.normalizeFileId(SHA1.toUpperCase()));
    }

    @Test
    void rejectsGarbage() {
        assertNull(AmCache.normalizeFileId("not-a-hash"));
        assertNull(AmCache.normalizeFileId(null));
        assertNull(AmCache.normalizeFileId("0000short"));
    }
}

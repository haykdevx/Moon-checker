package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EntropyTest {

    @Test
    void uniformBytesAreLowEntropy() {
        byte[] zeros = new byte[4096];
        assertEquals(0.0, Entropy.shannon(zeros), 1e-9);
    }

    @Test
    void allByteValuesAreMaxEntropy() {
        byte[] data = new byte[256 * 32];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }
        assertTrue(Entropy.shannon(data) > 7.99, "expected ~8.0, got " + Entropy.shannon(data));
    }

    @Test
    void textIsMidEntropyBelowPackedThreshold() {
        byte[] text = "the quick brown fox jumps over the lazy dog ".repeat(50)
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        double e = Entropy.shannon(text);
        assertTrue(e > 3.0 && e < 5.0, "english text entropy was " + e);
    }
}

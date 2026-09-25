package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class XpressHuffmanTest {

    @Test
    void literalOnlyRoundTrip() {
        byte[] data = XpressTestEncoder.sample(5000, 1);
        byte[] packed = XpressTestEncoder.compress(data, false);
        assertArrayEquals(data, XpressHuffman.decompress(packed, data.length));
    }

    @Test
    void matchesAcrossSeveralBlocksRoundTrip() {
        // > 2 blocks of 65536 bytes, with short, long (extra byte) and very long (16-bit) matches
        byte[] data = XpressTestEncoder.sample(200_000, 7);
        Arrays.fill(data, 70_000, 71_000, (byte) 'A');   // run -> overlapping copy with offset 1
        System.arraycopy(data, 1000, data, 150_000, 40_000);
        byte[] packed = XpressTestEncoder.compress(data, true);
        assertTrue(packed.length < data.length / 2, "matches should compress: " + packed.length);
        assertArrayEquals(data, XpressHuffman.decompress(packed, data.length));
    }

    @Test
    void emptyOutputNeedsNoInput() {
        assertArrayEquals(new byte[0], XpressHuffman.decompress(new byte[0], 0));
    }

    @Test
    void malformedInputYieldsNullNeverThrows() {
        byte[] data = XpressTestEncoder.sample(20_000, 3);
        byte[] packed = XpressTestEncoder.compress(data, true);

        // truncated stream
        assertNull(XpressHuffman.decompress(Arrays.copyOf(packed, 300), data.length));
        // incomplete Huffman table (all lengths zero)
        byte[] badTable = packed.clone();
        Arrays.fill(badTable, 0, 256, (byte) 0);
        assertNull(XpressHuffman.decompress(badTable, data.length));
        // over-subscribed table (every symbol length 1)
        byte[] overfull = packed.clone();
        Arrays.fill(overfull, 0, 256, (byte) 0x11);
        assertNull(XpressHuffman.decompress(overfull, data.length));
        // hostile sizes / arguments
        assertNull(XpressHuffman.decompress(packed, -1));
        assertNull(XpressHuffman.decompress(packed, Integer.MAX_VALUE));
        assertNull(XpressHuffman.decompress(null, 10));
        assertNull(XpressHuffman.decompress(packed, 10, packed.length, 100));
    }

    @Test
    void randomGarbageNeverThrows() {
        java.util.Random r = new java.util.Random(42);
        for (int i = 0; i < 300; i++) {
            byte[] junk = new byte[r.nextInt(2000)];
            r.nextBytes(junk);
            assertDoesNotThrow(() -> XpressHuffman.decompress(junk, r.nextInt(100_000)));
        }
    }
}

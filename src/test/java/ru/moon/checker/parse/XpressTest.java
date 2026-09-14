package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Hand-crafted LZXPRESS-Huffman streams. The 256-byte header holds 512 four-bit
 * code lengths (low nibble = even symbol, high nibble = odd symbol); the
 * bitstream is consumed MSB-first from 16-bit little-endian words.
 */
class XpressTest {

    /** Set the 4-bit code length for a symbol in the 256-byte table. */
    private static void setLength(byte[] table, int symbol, int bitLength) {
        int idx = symbol / 2;
        if (symbol % 2 == 0) {
            table[idx] |= (byte) (bitLength & 0x0F);
        } else {
            table[idx] |= (byte) ((bitLength & 0x0F) << 4);
        }
    }

    private static byte[] stream(byte[] table, int... words) {
        byte[] out = new byte[256 + words.length * 2];
        System.arraycopy(table, 0, out, 0, 256);
        int p = 256;
        for (int w : words) {
            out[p++] = (byte) (w & 0xFF);
            out[p++] = (byte) ((w >>> 8) & 0xFF);
        }
        return out;
    }

    @Test
    void decodesLiteralsAlternating() {
        byte[] table = new byte[256];
        setLength(table, 'A', 1); // canonical: first 1-bit code  -> prefix 0
        setLength(table, 'B', 1); // second 1-bit code            -> prefix 1
        // bits 0,1,0,1 => A B A B, MSB-first in the first 16-bit word
        byte[] in = stream(table, 0x5000, 0x0000);
        byte[] out = Xpress.decompressHuffman(in, 0, 4);
        assertEquals("ABAB", new String(out, StandardCharsets.US_ASCII));
    }

    @Test
    void decodesLz77Match() {
        byte[] table = new byte[256];
        setLength(table, 'A', 1);   // prefix 0 -> literal 'A'
        setLength(table, 256, 1);   // prefix 1 -> match: len=(0&15)+3=3, offsetBits=0 -> offset 1
        // bits 0,1 => 'A' then copy 3 bytes from distance 1 => "AAAA"
        byte[] in = stream(table, 0x4000, 0x0000);
        byte[] out = Xpress.decompressHuffman(in, 0, 4);
        assertEquals("AAAA", new String(out, StandardCharsets.US_ASCII));
    }

    @Test
    void buildsCanonicalTableInSymbolOrder() {
        int[] lengths = new int[512];
        lengths['A'] = 1;
        lengths['B'] = 1;
        int[] table = Xpress.buildDecodingTable(lengths);
        assertEquals('A', table[0]);
        assertEquals('A', table[(1 << 14) - 1]);
        assertEquals('B', table[1 << 14]);
        assertEquals('B', table[(1 << 15) - 1]);
    }

    @Test
    void rejectsGarbage() {
        assertThrows(Xpress.FormatException.class,
                () -> Xpress.decompressHuffman(new byte[10], 0, 16));
        // table with no valid codes => first symbol has length 0
        assertThrows(Xpress.FormatException.class,
                () -> Xpress.decompressHuffman(new byte[300], 0, 4));
    }

    @Test
    void oversubscribedTableIsRejected() {
        int[] lengths = new int[512];
        for (int i = 0; i < 512; i++) {
            lengths[i] = 1; // 512 one-bit codes cannot fit
        }
        assertThrows(Xpress.FormatException.class, () -> Xpress.buildDecodingTable(lengths));
    }
}

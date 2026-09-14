package ru.moon.checker.parse;

/**
 * LZXPRESS-Huffman decompressor (MS-XCA §2.2), pure Java.
 *
 * <p>Windows 8+ stores Prefetch bodies inside a {@code MAM} container compressed
 * with this algorithm, which is why filename-only Prefetch parsing misses the
 * richest evidence. Decompressing it here — without calling
 * {@code RtlDecompressBufferEx} — keeps the parser testable off-Windows.
 *
 * <p>Format: a 256-byte header holding 512 four-bit Huffman code lengths,
 * followed by a bitstream of canonical Huffman symbols. Symbols 0-255 are
 * literals; 256-511 encode an LZ77 (length, offset) match.
 */
public final class Xpress {

    private static final int SYMBOLS = 512;
    private static final int TABLE_BITS = 15;
    private static final int TABLE_SIZE = 1 << TABLE_BITS;

    private Xpress() {
    }

    /** Thrown for malformed input; callers treat it as "unparseable". */
    public static final class FormatException extends RuntimeException {
        FormatException(String m) {
            super(m);
        }
    }

    /**
     * Decompress {@code outSize} bytes starting at {@code inOff}.
     *
     * @throws FormatException on a corrupt stream
     */
    public static byte[] decompressHuffman(byte[] in, int inOff, int outSize) {
        if (in == null || outSize < 0 || inOff < 0 || inOff + 256 > in.length) {
            throw new FormatException("input too small for Huffman table");
        }
        byte[] out = new byte[outSize];
        int[] codeLengths = new int[SYMBOLS];
        for (int i = 0; i < 256; i++) {
            int b = in[inOff + i] & 0xFF;
            codeLengths[2 * i] = b & 0x0F;
            codeLengths[2 * i + 1] = b >>> 4;
        }
        int[] table = buildDecodingTable(codeLengths);

        int pos = inOff + 256;
        long nextBits = readU16(in, pos);
        pos += 2;
        nextBits = (nextBits << 16) & 0xFFFFFFFFL;
        nextBits |= readU16(in, pos);
        pos += 2;
        int extraBits = 16;
        int outPos = 0;

        while (outPos < outSize) {
            int next15 = (int) ((nextBits >>> (32 - TABLE_BITS)) & (TABLE_SIZE - 1));
            int symbol = table[next15];
            int length = codeLengths[symbol];
            if (length == 0) {
                throw new FormatException("invalid Huffman symbol at output " + outPos);
            }
            nextBits = (nextBits << length) & 0xFFFFFFFFL;
            extraBits -= length;
            if (extraBits < 0) {
                nextBits |= ((long) readU16(in, pos)) << (-extraBits);
                nextBits &= 0xFFFFFFFFL;
                pos += 2;
                extraBits += 16;
            }

            if (symbol < 256) {
                out[outPos++] = (byte) symbol;
                continue;
            }

            int s = symbol - 256;
            int matchLength = s & 15;
            int offsetBits = s >>> 4;
            if (matchLength == 15) {
                matchLength = readU8(in, pos);
                pos += 1;
                if (matchLength == 255) {
                    matchLength = readU16(in, pos);
                    pos += 2;
                    if (matchLength < 15) {
                        throw new FormatException("bad extended match length");
                    }
                    matchLength -= 15;
                }
                matchLength += 15;
            }
            matchLength += 3;

            // offsetBits == 0 shifts a 32-bit value right by 32 -> 0, which is correct
            int matchOffset = (int) (nextBits >>> (32 - offsetBits));
            matchOffset += (1 << offsetBits);
            nextBits = (nextBits << offsetBits) & 0xFFFFFFFFL;
            extraBits -= offsetBits;
            if (extraBits < 0) {
                nextBits |= ((long) readU16(in, pos)) << (-extraBits);
                nextBits &= 0xFFFFFFFFL;
                pos += 2;
                extraBits += 16;
            }
            if (matchOffset > outPos) {
                throw new FormatException("match offset before start of output");
            }
            for (int i = 0; i < matchLength && outPos < outSize; i++) {
                out[outPos] = out[outPos - matchOffset];
                outPos++;
            }
        }
        return out;
    }

    /** Canonical Huffman: 15-bit prefix -> symbol. */
    static int[] buildDecodingTable(int[] codeLengths) {
        int[] table = new int[TABLE_SIZE];
        int entry = 0;
        for (int bitLength = 1; bitLength <= TABLE_BITS; bitLength++) {
            for (int symbol = 0; symbol < SYMBOLS; symbol++) {
                if (codeLengths[symbol] != bitLength) {
                    continue;
                }
                int count = 1 << (TABLE_BITS - bitLength);
                if (entry + count > TABLE_SIZE) {
                    throw new FormatException("over-subscribed Huffman table");
                }
                for (int i = 0; i < count; i++) {
                    table[entry++] = symbol;
                }
            }
        }
        return table;
    }

    private static int readU8(byte[] d, int o) {
        if (o < 0 || o >= d.length) {
            throw new FormatException("read past end of compressed data");
        }
        return d[o] & 0xFF;
    }

    private static int readU16(byte[] d, int o) {
        if (o < 0 || o + 1 >= d.length) {
            throw new FormatException("read past end of compressed data");
        }
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8);
    }
}

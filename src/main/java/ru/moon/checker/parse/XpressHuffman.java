package ru.moon.checker.parse;

/**
 * Pure-Java LZXpress-Huffman decompressor ([MS-XCA] §2.2.4), the algorithm
 * behind {@code COMPRESSION_FORMAT_XPRESS_HUFF} and Windows 10/11 compressed
 * Prefetch files. Works on any host, so the Prefetch parser is unit-testable
 * on Linux and does not depend on {@code ntdll!RtlDecompressBufferEx}.
 *
 * <p>Stream layout: consecutive blocks, each a 256-byte table of 512 4-bit
 * Huffman code lengths followed by a bit stream (16-bit little-endian words,
 * MSB first) that decodes to at most 65536 output bytes. Symbols below 256 are
 * literals; the rest encode a match (low nibble = length, high nibble = number
 * of offset bits).
 *
 * <p>Defensive: malformed input yields {@code null}, never an exception, and the
 * output size is bounded by the caller-supplied expected size.
 */
public final class XpressHuffman {

    /** Refuse absurd sizes from a hostile header (Prefetch bodies are a few MB). */
    public static final int MAX_OUTPUT = 64 * 1024 * 1024;

    private static final int SYMBOLS = 512;
    private static final int TABLE_BITS = 15;
    private static final int BLOCK_OUTPUT = 65536;

    private XpressHuffman() {
    }

    /** Decompress {@code in} to exactly {@code outputSize} bytes, or null if invalid. */
    public static byte[] decompress(byte[] in, int outputSize) {
        return in == null ? null : decompress(in, 0, in.length, outputSize);
    }

    public static byte[] decompress(byte[] in, int offset, int length, int outputSize) {
        if (in == null || offset < 0 || length < 0 || offset + length > in.length
                || outputSize < 0 || outputSize > MAX_OUTPUT) {
            return null;
        }
        try {
            return new Decoder(in, offset, offset + length, outputSize).run();
        } catch (RuntimeException e) {
            return null; // bounds/format violation surfaced as an index error
        }
    }

    private static final class Decoder {
        private final byte[] in;
        private final int end;
        private final byte[] out;
        private final short[] table = new short[1 << TABLE_BITS];
        private final byte[] lengths = new byte[SYMBOLS];
        private int pos;
        private int outPos;
        private long bits;     // up to 32 pending bits, MSB-aligned in the low 32 bits
        private int extra;     // bits available beyond the 16-bit lookahead

        Decoder(byte[] in, int start, int end, int outputSize) {
            this.in = in;
            this.pos = start;
            this.end = end;
            this.out = new byte[outputSize];
        }

        byte[] run() {
            while (outPos < out.length) {
                if (pos + 256 > end || !buildTable()) {
                    return null;
                }
                pos += 256;
                bits = ((long) read16() << 16) | read16();
                extra = 16;
                int blockEnd = Math.min(out.length, outPos + BLOCK_OUTPUT);
                while (outPos < blockEnd) {
                    int symbol = table[(int) (bits >>> (32 - TABLE_BITS)) & 0x7FFF];
                    consume(lengths[symbol]);
                    if (symbol < 256) {
                        out[outPos++] = (byte) symbol;
                        continue;
                    }
                    symbol -= 256;
                    int matchLength = symbol & 0xF;
                    int offsetBits = symbol >>> 4;
                    if (matchLength == 15) {
                        matchLength = readByte();
                        if (matchLength == 255) {
                            matchLength = read16();
                            if (matchLength == 0) {
                                matchLength = read32();
                            }
                            if (matchLength < 15) {
                                return null;
                            }
                            matchLength -= 15;
                        }
                        matchLength += 15;
                    }
                    matchLength += 3;
                    long matchOffset = offsetBits == 0 ? 1
                            : ((bits >>> (32 - offsetBits)) & ((1L << offsetBits) - 1)) + (1L << offsetBits);
                    consume(offsetBits);
                    if (matchOffset > outPos || matchLength < 0) {
                        return null;
                    }
                    int from = outPos - (int) matchOffset;
                    int n = Math.min(matchLength, out.length - outPos);
                    for (int i = 0; i < n; i++) {
                        out[outPos++] = out[from + i]; // byte-wise: overlapping copies repeat
                    }
                }
            }
            return out;
        }

        /** Canonical Huffman table: symbols in order of (bit length, symbol value). */
        private boolean buildTable() {
            for (int i = 0; i < SYMBOLS; i++) {
                lengths[i] = (byte) ((in[pos + (i >> 1)] >> ((i & 1) * 4)) & 0xF);
            }
            int entry = 0;
            for (int bitLength = 1; bitLength <= TABLE_BITS; bitLength++) {
                for (int symbol = 0; symbol < SYMBOLS; symbol++) {
                    if (lengths[symbol] != bitLength) {
                        continue;
                    }
                    int count = 1 << (TABLE_BITS - bitLength);
                    if (entry + count > table.length) {
                        return false;
                    }
                    java.util.Arrays.fill(table, entry, entry + count, (short) symbol);
                    entry += count;
                }
            }
            return entry == table.length;
        }

        private void consume(int n) {
            bits = (bits << n) & 0xFFFFFFFFL;
            extra -= n;
            if (extra < 0) {
                bits |= ((long) read16() << (-extra)) & 0xFFFFFFFFL;
                extra += 16;
            }
        }

        private int read16() {
            if (pos + 2 > end) {
                pos += 2; // past the end reads as zeros; a real overrun fails the size check
                if (pos > end + 8) {
                    throw new IndexOutOfBoundsException("input exhausted");
                }
                return 0;
            }
            int v = (in[pos] & 0xFF) | ((in[pos + 1] & 0xFF) << 8);
            pos += 2;
            return v;
        }

        private int readByte() {
            if (pos >= end) {
                throw new IndexOutOfBoundsException("input exhausted");
            }
            return in[pos++] & 0xFF;
        }

        private int read32() {
            if (pos + 4 > end) {
                throw new IndexOutOfBoundsException("input exhausted");
            }
            int v = (in[pos] & 0xFF) | ((in[pos + 1] & 0xFF) << 8)
                    | ((in[pos + 2] & 0xFF) << 16) | ((in[pos + 3] & 0xFF) << 24);
            pos += 4;
            return v;
        }
    }
}

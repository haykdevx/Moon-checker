package ru.moon.checker.parse;

import java.util.ArrayList;
import java.util.List;

/**
 * Extracts printable strings from a byte buffer (both single-byte ASCII and
 * UTF-16LE, which Windows binaries use heavily). Used to find CS2 offset /
 * netvar names and cheat identifiers embedded in executables — this is what
 * lets the checker flag private or self-compiled externals that no hash or
 * filename rule would catch.
 */
public final class BinStrings {

    private BinStrings() {
    }

    /** ASCII printable strings of at least {@code minLen} characters. */
    public static List<String> ascii(byte[] data, int minLen) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c < 0x7F) {
                cur.append((char) c);
            } else {
                flush(out, cur, minLen);
            }
        }
        flush(out, cur, minLen);
        return out;
    }

    /** UTF-16LE printable strings of at least {@code minLen} characters. */
    public static List<String> utf16le(byte[] data, int minLen) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i + 1 < data.length; i += 2) {
            int lo = data[i] & 0xFF;
            int hi = data[i + 1] & 0xFF;
            if (hi == 0 && lo >= 0x20 && lo < 0x7F) {
                cur.append((char) lo);
            } else {
                flush(out, cur, minLen);
            }
        }
        flush(out, cur, minLen);
        return out;
    }

    /** ASCII + UTF-16LE strings combined. */
    public static List<String> all(byte[] data, int minLen) {
        List<String> out = ascii(data, minLen);
        out.addAll(utf16le(data, minLen));
        return out;
    }

    private static void flush(List<String> out, StringBuilder cur, int minLen) {
        if (cur.length() >= minLen) {
            out.add(cur.toString());
        }
        cur.setLength(0);
    }
}

package ru.moon.checker.parse;

/**
 * Shannon entropy of a byte buffer (0..8 bits/byte). Cheat binaries are very
 * often packed/encrypted to evade signatures; a code section with entropy near
 * 8.0 is a strong "obfuscated / packed" signal when combined with a suspicious
 * location.
 */
public final class Entropy {

    private Entropy() {
    }

    /** Entropy in bits per byte, 0.0 for empty input. */
    public static double shannon(byte[] data, int offset, int length) {
        if (data == null || length <= 0) {
            return 0.0;
        }
        int end = Math.min(data.length, offset + length);
        long[] counts = new long[256];
        long total = 0;
        for (int i = Math.max(0, offset); i < end; i++) {
            counts[data[i] & 0xFF]++;
            total++;
        }
        if (total == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (long c : counts) {
            if (c == 0) {
                continue;
            }
            double p = (double) c / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    public static double shannon(byte[] data) {
        return shannon(data, 0, data == null ? 0 : data.length);
    }
}

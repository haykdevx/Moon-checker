package ru.moon.checker.parse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Parser for Recycle Bin {@code $I} index files (Windows Vista and later),
 * found under {@code C:\$Recycle.Bin\<SID>\}. Each $I file records the original
 * path, size and deletion time of a deleted item — so a cheat that was
 * "deleted" (but only moved to the bin) is still visible here.
 */
public final class RecycleBin {

    private RecycleBin() {
    }

    public record Entry(String originalPath, long fileSize, Instant deletedAt) {
    }

    public static Entry parse(byte[] d) {
        try {
            if (d == null || d.length < 24) {
                return null;
            }
            long version = u64(d, 0);
            long fileSize = u64(d, 8);
            Instant deletedAt = UserAssist.fileTimeToInstant(u64(d, 16));
            String path;
            if (version >= 2 && d.length >= 28) {
                int nameChars = u32(d, 24); // includes trailing null
                int bytes = Math.max(0, (nameChars - 1) * 2);
                if (28 + bytes > d.length) {
                    bytes = Math.max(0, d.length - 28);
                }
                path = new String(d, 28, bytes, StandardCharsets.UTF_16LE);
            } else {
                // version 1: fixed 260-wchar (520-byte) null-terminated path at offset 24
                int max = Math.min(520, d.length - 24);
                String raw = new String(d, 24, max, StandardCharsets.UTF_16LE);
                int nul = raw.indexOf('\0');
                path = nul >= 0 ? raw.substring(0, nul) : raw;
            }
            return new Entry(path, fileSize, deletedAt);
        } catch (Exception e) {
            return null;
        }
    }

    private static int u32(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8)
                | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }

    private static long u64(byte[] d, int o) {
        long lo = u32(d, o) & 0xFFFFFFFFL;
        long hi = u32(d, o + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }
}

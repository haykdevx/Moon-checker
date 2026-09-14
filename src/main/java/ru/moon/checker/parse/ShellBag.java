package ru.moon.checker.parse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Extracts folder names from ShellBag {@code ITEMIDLIST} blobs
 * (HKCU\...\Shell\BagMRU). ShellBags record every folder a user has browsed in
 * Explorer, <em>including folders that have since been deleted</em> — so a
 * "cheats" or "loader" folder that no longer exists on disk is still provable.
 *
 * <p>Modern shell items carry the long folder name in a {@code 0xBEEF0004}
 * extension block as a UTF-16LE string. This parser locates those blocks and
 * reads the names; it is deliberately tolerant of the several block-versions
 * Windows has shipped.
 */
public final class ShellBag {

    private ShellBag() {
    }

    private static final byte[] BEEF0004 = {0x04, 0x00, (byte) 0xEF, (byte) 0xBE};

    /** All plausible folder names found in a single shell-item value. */
    public static List<String> extractFolderNames(byte[] value) {
        Set<String> names = new LinkedHashSet<>();
        if (value == null || value.length < 8) {
            return new ArrayList<>(names);
        }
        for (int i = 0; i + 4 <= value.length; i++) {
            if (value[i] == BEEF0004[0] && value[i + 1] == BEEF0004[1]
                    && value[i + 2] == BEEF0004[2] && value[i + 3] == BEEF0004[3]) {
                String name = readUnicodeNameAfter(value, i + 4);
                if (isPlausibleName(name)) {
                    names.add(name);
                }
            }
        }
        return new ArrayList<>(names);
    }

    /**
     * Scan forward from {@code start} for the first aligned UTF-16LE run of at
     * least two characters and return it (up to the terminating double null).
     */
    private static String readUnicodeNameAfter(byte[] d, int start) {
        for (int base = start; base + 4 <= d.length; base += 2) {
            if (isUtf16Char(d, base) && isUtf16Char(d, base + 2)) {
                int end = base;
                StringBuilder sb = new StringBuilder();
                while (end + 1 < d.length && !(d[end] == 0 && d[end + 1] == 0)) {
                    if (!isUtf16Char(d, end)) {
                        break;
                    }
                    end += 2;
                }
                if (end > base) {
                    sb.append(new String(d, base, end - base, StandardCharsets.UTF_16LE));
                    return sb.toString();
                }
            }
        }
        return null;
    }

    private static boolean isUtf16Char(byte[] d, int o) {
        if (o + 1 >= d.length) {
            return false;
        }
        int lo = d[o] & 0xFF;
        int hi = d[o + 1] & 0xFF;
        // printable BMP range, excluding control chars; allow common latin/cyrillic
        return hi <= 0x04 && (lo >= 0x20 || (hi > 0 && lo >= 0x00)) && !(hi == 0 && lo < 0x20);
    }

    private static boolean isPlausibleName(String s) {
        if (s == null || s.length() < 2 || s.length() > 260) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (Character.isLetterOrDigit(s.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}

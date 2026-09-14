package ru.moon.checker.parse;

import java.nio.charset.StandardCharsets;

/**
 * Parser for Windows Shell Link (.lnk) files, as found in
 * {@code AppData\Roaming\Microsoft\Windows\Recent}. Recent shortcuts reveal
 * files a user opened even after the originals are deleted — a common way to
 * catch a cheat loader that was run then removed.
 *
 * <p>Extracts the resolved local target (LinkInfo LocalBasePath +
 * CommonPathSuffix), plus the relative path and command-line arguments from
 * the StringData block. Defensive: any malformed field yields nulls.
 */
public final class Lnk {

    private static final int HAS_LINK_TARGET_IDLIST = 0x01;
    private static final int HAS_LINK_INFO = 0x02;
    private static final int HAS_NAME = 0x04;
    private static final int HAS_RELATIVE_PATH = 0x08;
    private static final int HAS_WORKING_DIR = 0x10;
    private static final int HAS_ARGUMENTS = 0x20;
    private static final int HAS_ICON_LOCATION = 0x40;
    private static final int IS_UNICODE = 0x80;

    private final String localBasePath;
    private final String commonPathSuffix;
    private final String relativePath;
    private final String workingDir;
    private final String arguments;
    private final boolean valid;

    private Lnk(String localBasePath, String commonPathSuffix, String relativePath,
                String workingDir, String arguments, boolean valid) {
        this.localBasePath = localBasePath;
        this.commonPathSuffix = commonPathSuffix;
        this.relativePath = relativePath;
        this.workingDir = workingDir;
        this.arguments = arguments;
        this.valid = valid;
    }

    public boolean valid() {
        return valid;
    }

    public String relativePath() {
        return relativePath;
    }

    public String workingDir() {
        return workingDir;
    }

    public String arguments() {
        return arguments;
    }

    public String localBasePath() {
        return localBasePath;
    }

    /** Best resolved target path, or null if none could be read. */
    public String targetPath() {
        if (localBasePath != null && !localBasePath.isEmpty()) {
            String suffix = commonPathSuffix == null ? "" : commonPathSuffix;
            return localBasePath + suffix;
        }
        return null;
    }

    public static Lnk parse(byte[] d) {
        Lnk fail = new Lnk(null, null, null, null, null, false);
        try {
            if (d == null || d.length < 76) {
                return fail;
            }
            if (u32(d, 0) != 0x4C) {
                return fail; // HeaderSize must be 0x4C
            }
            int flags = u32(d, 20);
            int pos = 76;

            if ((flags & HAS_LINK_TARGET_IDLIST) != 0) {
                if (pos + 2 > d.length) {
                    return fail;
                }
                int idListSize = u16(d, pos);
                pos += 2 + idListSize;
            }

            String localBase = null;
            String suffix = null;
            if ((flags & HAS_LINK_INFO) != 0) {
                int linkInfoStart = pos;
                if (linkInfoStart + 28 > d.length) {
                    return fail;
                }
                int linkInfoSize = u32(d, linkInfoStart);
                int headerSize = u32(d, linkInfoStart + 4);
                int linkInfoFlags = u32(d, linkInfoStart + 8);
                int localBasePathOffset = u32(d, linkInfoStart + 16);
                int commonPathSuffixOffset = u32(d, linkInfoStart + 24);

                if ((linkInfoFlags & 0x1) != 0) { // VolumeIDAndLocalBasePath present
                    if (headerSize >= 0x24) {
                        int localBasePathOffsetUnicode = u32(d, linkInfoStart + 28);
                        localBase = cstringUtf16(d, linkInfoStart + localBasePathOffsetUnicode);
                        if (localBase == null) {
                            localBase = cstringAnsi(d, linkInfoStart + localBasePathOffset);
                        }
                    } else {
                        localBase = cstringAnsi(d, linkInfoStart + localBasePathOffset);
                    }
                    suffix = cstringAnsi(d, linkInfoStart + commonPathSuffixOffset);
                }
                pos = linkInfoStart + linkInfoSize;
            }

            // StringData block (each: 2-byte char count, then chars)
            boolean unicode = (flags & IS_UNICODE) != 0;
            String name = null, rel = null, work = null, args = null;
            if ((flags & HAS_NAME) != 0) {
                String[] r = readStringData(d, pos, unicode);
                name = r[0];
                pos = Integer.parseInt(r[1]);
            }
            if ((flags & HAS_RELATIVE_PATH) != 0) {
                String[] r = readStringData(d, pos, unicode);
                rel = r[0];
                pos = Integer.parseInt(r[1]);
            }
            if ((flags & HAS_WORKING_DIR) != 0) {
                String[] r = readStringData(d, pos, unicode);
                work = r[0];
                pos = Integer.parseInt(r[1]);
            }
            if ((flags & HAS_ARGUMENTS) != 0) {
                String[] r = readStringData(d, pos, unicode);
                args = r[0];
                pos = Integer.parseInt(r[1]);
            }

            return new Lnk(localBase, suffix, rel, work, args, true);
        } catch (Exception e) {
            return fail;
        }
    }

    /** Returns {@code [value, newPos]}. */
    private static String[] readStringData(byte[] d, int pos, boolean unicode) {
        if (pos + 2 > d.length) {
            return new String[]{null, String.valueOf(pos)};
        }
        int count = u16(d, pos);
        pos += 2;
        int bytes = unicode ? count * 2 : count;
        if (pos + bytes > d.length) {
            return new String[]{null, String.valueOf(pos)};
        }
        String s = unicode
                ? new String(d, pos, bytes, StandardCharsets.UTF_16LE)
                : new String(d, pos, bytes, StandardCharsets.ISO_8859_1);
        return new String[]{s, String.valueOf(pos + bytes)};
    }

    private static String cstringAnsi(byte[] d, int off) {
        if (off < 0 || off >= d.length) {
            return null;
        }
        int end = off;
        while (end < d.length && d[end] != 0) {
            end++;
        }
        return new String(d, off, end - off, StandardCharsets.ISO_8859_1);
    }

    private static String cstringUtf16(byte[] d, int off) {
        if (off < 0 || off + 1 >= d.length) {
            return null;
        }
        int end = off;
        while (end + 1 < d.length && !(d[end] == 0 && d[end + 1] == 0)) {
            end += 2;
        }
        return new String(d, off, end - off, StandardCharsets.UTF_16LE);
    }

    private static int u16(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8)
                | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }
}

package ru.moon.checker.parse;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for NTFS USN change-journal records (USN_RECORD_V2), the buffers
 * returned by {@code FSCTL_ENUM_USN_DATA} / {@code FSCTL_READ_USN_JOURNAL}.
 * Deleted and renamed files leave a trail here even after the file table entry
 * is reused — this is how the checker catches a cheat that was deleted right
 * before the inspection.
 */
public final class Usn {

    public static final long REASON_FILE_CREATE = 0x00000100L;
    public static final long REASON_FILE_DELETE = 0x00000200L;
    public static final long REASON_RENAME_OLD_NAME = 0x00001000L;
    public static final long REASON_RENAME_NEW_NAME = 0x00002000L;
    public static final long REASON_DATA_OVERWRITE = 0x00000001L;
    public static final long REASON_DATA_EXTEND = 0x00000002L;

    private Usn() {
    }

    public record Record(
            long fileReference,
            long parentReference,
            long usn,
            Instant timestamp,
            long reason,
            int fileAttributes,
            String fileName
    ) {
        public boolean isDeleted() {
            return (reason & REASON_FILE_DELETE) != 0;
        }

        public boolean isRename() {
            return (reason & (REASON_RENAME_OLD_NAME | REASON_RENAME_NEW_NAME)) != 0;
        }
    }

    /**
     * Parse a buffer that begins with an 8-byte next-USN cursor (as returned by
     * the FSCTL) followed by consecutive USN_RECORD_V2 structures.
     */
    public static List<Record> parseBuffer(byte[] buf, int length) {
        List<Record> out = new ArrayList<>();
        if (buf == null || length < 8) {
            return out;
        }
        int offset = 8; // skip the leading USN cursor
        while (offset + 60 <= length) {
            int recordLength = u32(buf, offset);
            if (recordLength < 60 || offset + recordLength > length) {
                break;
            }
            Record r = parseOne(buf, offset);
            if (r != null) {
                out.add(r);
            }
            offset += recordLength;
        }
        return out;
    }

    /** Parse a single USN_RECORD_V2 at the given offset. */
    public static Record parseOne(byte[] d, int off) {
        try {
            long fileRef = u64(d, off + 8);
            long parentRef = u64(d, off + 16);
            long usn = u64(d, off + 24);
            Instant ts = UserAssist.fileTimeToInstant(u64(d, off + 32));
            long reason = u32(d, off + 40) & 0xFFFFFFFFL;
            int attrs = u32(d, off + 52);
            int nameLen = u16(d, off + 56);
            int nameOff = u16(d, off + 58);
            String name = "";
            if (nameOff >= 0 && off + nameOff + nameLen <= d.length && nameLen > 0) {
                name = new String(d, off + nameOff, nameLen, StandardCharsets.UTF_16LE);
            }
            return new Record(fileRef, parentRef, usn, ts, reason, attrs, name);
        } catch (Exception e) {
            return null;
        }
    }

    public static String reasonToString(long reason) {
        StringBuilder sb = new StringBuilder();
        if ((reason & REASON_FILE_CREATE) != 0) sb.append("CREATE ");
        if ((reason & REASON_FILE_DELETE) != 0) sb.append("DELETE ");
        if ((reason & REASON_RENAME_OLD_NAME) != 0) sb.append("RENAME_OLD ");
        if ((reason & REASON_RENAME_NEW_NAME) != 0) sb.append("RENAME_NEW ");
        if ((reason & REASON_DATA_OVERWRITE) != 0) sb.append("OVERWRITE ");
        return sb.toString().trim();
    }

    private static int u16(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8);
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

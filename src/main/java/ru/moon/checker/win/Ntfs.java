package ru.moon.checker.win;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import ru.moon.checker.core.Platform;
import ru.moon.checker.parse.Usn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads NTFS metadata directly from a volume handle, the same technique
 * "Everything" and USN-journal tools use.
 *
 * <ul>
 *   <li>{@link #buildIndex(char)} enumerates the entire Master File Table via
 *       {@code FSCTL_ENUM_USN_DATA} — a full-disk file listing in seconds,
 *       far faster than walking the tree.</li>
 *   <li>{@link #readJournalChanges(char)} reads the USN change journal
 *       ({@code FSCTL_READ_USN_JOURNAL}) to recover deleted/renamed files.</li>
 * </ul>
 *
 * Requires administrator rights and a real Windows host; every entry point
 * degrades to an empty result otherwise, so callers can fall back to a plain
 * filesystem walk.
 */
public final class Ntfs {

    private static final int GENERIC_READ = 0x80000000;
    private static final int FILE_SHARE_READ = 0x1;
    private static final int FILE_SHARE_WRITE = 0x2;
    private static final int OPEN_EXISTING = 3;

    private static final int FSCTL_ENUM_USN_DATA = 0x000900b3;
    private static final int FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    private static final int FSCTL_READ_USN_JOURNAL = 0x000900bb;

    private static final int FILE_ATTRIBUTE_DIRECTORY = 0x10;
    private static final int BUFFER_SIZE = 1 << 20; // 1 MiB
    private static final long ROOT_REF = 0x0005_0000_0000_0005L;

    private Ntfs() {
    }

    public static boolean isSupported() {
        return Platform.isWindows();
    }

    /** One MFT entry: its name and the file reference of its parent dir. */
    public record Node(String name, long parentRef, boolean directory) {
    }

    /** In-memory MFT index for a single volume, with path resolution. */
    public static final class Index {
        private final char letter;
        private final Map<Long, Node> nodes;

        Index(char letter, Map<Long, Node> nodes) {
            this.letter = letter;
            this.nodes = nodes;
        }

        public int size() {
            return nodes.size();
        }

        public Map<Long, Node> nodes() {
            return nodes;
        }

        /** Full path for a file reference, e.g. {@code C:\Users\me\loader.exe}. */
        public String resolvePath(long ref) {
            StringBuilder sb = new StringBuilder();
            long cur = ref;
            int guard = 0;
            List<String> parts = new ArrayList<>();
            while (guard++ < 256) {
                Node n = nodes.get(cur);
                if (n == null || cur == n.parentRef || n.name.equals(".")) {
                    break;
                }
                parts.add(n.name);
                if (cur == ROOT_REF || n.parentRef == 0) {
                    break;
                }
                cur = n.parentRef;
            }
            sb.append(letter).append(":");
            for (int i = parts.size() - 1; i >= 0; i--) {
                sb.append('\\').append(parts.get(i));
            }
            return sb.toString();
        }
    }

    private static HANDLE openVolume(char letter) {
        String path = "\\\\.\\" + letter + ":";
        HANDLE h = Kernel32.INSTANCE.CreateFile(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null,
                OPEN_EXISTING,
                0,
                null);
        if (h == null || h.equals(WinBase.INVALID_HANDLE_VALUE)) {
            return null;
        }
        return h;
    }

    public static Index buildIndex(char letter) {
        Map<Long, Node> nodes = new HashMap<>();
        if (!isSupported()) {
            return new Index(letter, nodes);
        }
        HANDLE h = openVolume(letter);
        if (h == null) {
            return new Index(letter, nodes);
        }
        try (Memory in = new Memory(24); Memory out = new Memory(BUFFER_SIZE)) {
            long nextRef = 0;
            IntByReference bytesReturned = new IntByReference();
            for (int pass = 0; pass < 100_000; pass++) {
                in.setLong(0, nextRef);        // StartFileReferenceNumber
                in.setLong(8, 0L);             // LowUsn
                in.setLong(16, Long.MAX_VALUE); // HighUsn
                boolean ok = Kernel32.INSTANCE.DeviceIoControl(
                        h, FSCTL_ENUM_USN_DATA, in, (int) in.size(),
                        out, (int) out.size(), bytesReturned, null);
                int returned = bytesReturned.getValue();
                if (!ok || returned <= 8) {
                    break;
                }
                byte[] buf = out.getByteArray(0, returned);
                for (Usn.Record r : Usn.parseBuffer(buf, returned)) {
                    boolean dir = (r.fileAttributes() & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    nodes.put(r.fileReference(), new Node(r.fileName(), r.parentReference(), dir));
                }
                nextRef = out.getLong(0);
            }
        } catch (Throwable t) {
            // best-effort; return what we have
        } finally {
            Kernel32.INSTANCE.CloseHandle(h);
        }
        return new Index(letter, nodes);
    }

    /**
     * Read deletion/rename records from the USN journal. Capped to keep memory
     * and time bounded; returns most-recent-first is not guaranteed (journal
     * order).
     */
    public static List<Usn.Record> readJournalChanges(char letter) {
        List<Usn.Record> out = new ArrayList<>();
        if (!isSupported()) {
            return out;
        }
        HANDLE h = openVolume(letter);
        if (h == null) {
            return out;
        }
        try (Memory query = new Memory(80); Memory readIn = new Memory(40); Memory buf = new Memory(BUFFER_SIZE)) {
            IntByReference br = new IntByReference();
            boolean ok = Kernel32.INSTANCE.DeviceIoControl(
                    h, FSCTL_QUERY_USN_JOURNAL, null, 0,
                    query, (int) query.size(), br, null);
            if (!ok) {
                return out;
            }
            long journalId = query.getLong(0);
            long firstUsn = query.getLong(8);
            long nextUsnEnd = query.getLong(16);

            long startUsn = firstUsn;
            int totalRecords = 0;
            for (int pass = 0; pass < 100_000 && totalRecords < 2_000_000; pass++) {
                readIn.setLong(0, startUsn);      // StartUsn
                readIn.setInt(8, 0xFFFFFFFF);     // ReasonMask (all)
                readIn.setInt(12, 0);             // ReturnOnlyOnClose
                readIn.setLong(16, 0L);           // Timeout
                readIn.setLong(24, 0L);           // BytesToWaitFor
                readIn.setLong(32, journalId);    // UsnJournalID
                boolean rok = Kernel32.INSTANCE.DeviceIoControl(
                        h, FSCTL_READ_USN_JOURNAL, readIn, (int) readIn.size(),
                        buf, (int) buf.size(), br, null);
                int returned = br.getValue();
                if (!rok || returned <= 8) {
                    break;
                }
                byte[] bytes = buf.getByteArray(0, returned);
                List<Usn.Record> recs = Usn.parseBuffer(bytes, returned);
                for (Usn.Record r : recs) {
                    if (r.isDeleted() || r.isRename()) {
                        out.add(r);
                    }
                }
                totalRecords += recs.size();
                long newStart = buf.getLong(0);
                if (newStart <= startUsn || newStart >= nextUsnEnd) {
                    break;
                }
                startUsn = newStart;
            }
        } catch (Throwable t) {
            // best-effort
        } finally {
            Kernel32.INSTANCE.CloseHandle(h);
        }
        return out;
    }
}

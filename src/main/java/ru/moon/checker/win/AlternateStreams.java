package ru.moon.checker.win;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import ru.moon.checker.core.Platform;

import java.util.ArrayList;
import java.util.List;

/**
 * Enumerates NTFS Alternate Data Streams on a file. A payload hidden in an ADS
 * (e.g. {@code loader.exe:cheat}) is invisible in Explorer and to naive
 * scanners — a favourite way to smuggle a cheat DLL. This maps the
 * {@code FindFirstStreamW}/{@code FindNextStreamW} APIs, which JNA does not
 * expose out of the box.
 */
public final class AlternateStreams {

    /** Extra JNA binding for the stream-enumeration APIs. */
    private interface K32 extends StdCallLibrary {
        K32 INSTANCE = Native.load("kernel32", K32.class, W32APIOptions.DEFAULT_OPTIONS);

        HANDLE FindFirstStreamW(WString lpFileName, int infoLevel, Memory data, int flags);

        boolean FindNextStreamW(HANDLE handle, Memory data);
    }

    private static final int FIND_STREAM_INFO_STANDARD = 0;
    private static final int ERROR_HANDLE_EOF = 38;
    private static final int STRUCT_SIZE = 8 + 296 * 2; // LARGE_INTEGER + WCHAR[MAX_PATH+36]

    private AlternateStreams() {
    }

    public record Stream(String name, long size) {
    }

    /**
     * Streams Windows, browsers, antivirus and sync tools write on ordinary files. Only
     * small ones are benign: a cheat hidden under one of these names would be large.
     */
    private static final java.util.Set<String> BENIGN = java.util.Set.of(
            "zone.identifier",        // "downloaded from the internet" marker (every download)
            "smartscreen",            // Edge / SmartScreen download verdict
            "kavichs",                // Kaspersky iChecker cache
            "com.dropbox.attrs", "com.dropbox.attributes",
            "oecustomproperty",       // Outlook Express / Windows Mail
            "encryptable",            // Windows thumbnail cache
            "favicon",                // Internet Explorer shortcuts
            "afp_afpinfo", "afp_resource", "afp_deleted", // files copied from a Mac
            "ms-properties", "wofcompresseddata",         // Windows property store, CompactOS
            "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",     // Explorer summary information
            "\u0005summaryinformation", "\u0005documentsummaryinformation");
    /** A stream this large can hold a program; anything smaller is a note or a marker. */
    public static final long PAYLOAD_BYTES = 32 * 1024;

    /** True for a small stream with a name Windows or common software is known to write. */
    public static boolean isBenign(String name, long size) {
        return name != null && size < PAYLOAD_BYTES && BENIGN.contains(name.toLowerCase(java.util.Locale.ROOT));
    }

    /**
     * Non-default data streams on {@code path}. The default stream ("::$DATA")
     * and small streams with benign names ({@link #isBenign}) are excluded.
     */
    public static List<Stream> list(String path) {
        List<Stream> out = new ArrayList<>();
        if (!Platform.isWindows() || path == null) {
            return out;
        }
        HANDLE h = null;
        try (Memory buf = new Memory(STRUCT_SIZE)) {
            h = K32.INSTANCE.FindFirstStreamW(new WString(path), FIND_STREAM_INFO_STANDARD, buf, 0);
            if (h == null || h.equals(WinBase.INVALID_HANDLE_VALUE)) {
                return out;
            }
            do {
                long size = buf.getLong(0);
                String name = buf.getWideString(8); // e.g. ":cheat:$DATA"
                String clean = cleanName(name);
                if (clean != null && !clean.isEmpty() && !isBenign(clean, size)) {
                    out.add(new Stream(clean, size));
                }
            } while (K32.INSTANCE.FindNextStreamW(h, buf));
        } catch (Throwable t) {
            // API missing or access denied — best-effort
        } finally {
            if (h != null && !h.equals(WinBase.INVALID_HANDLE_VALUE)) {
                Kernel32.INSTANCE.CloseHandle(h);
            }
        }
        return out;
    }

    /** ":name:$DATA" -> "name"; "::$DATA" (default) -> "". */
    static String cleanName(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw;
        if (s.startsWith(":")) {
            s = s.substring(1);
        }
        int colon = s.indexOf(':');
        if (colon >= 0) {
            s = s.substring(0, colon);
        }
        return s;
    }
}

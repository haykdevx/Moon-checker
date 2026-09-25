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
import java.util.Locale;
import java.util.Set;

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
     * Streams Windows and common sync clients attach to ordinary files. They are
     * tiny metadata blobs; a payload hidden under one of these names is still
     * reported because {@link #isBenign} also bounds the size.
     */
    private static final Set<String> BENIGN_NAMES = Set.of(
            "zone.identifier",          // Mark-of-the-Web on downloads
            "smartscreen",              // Edge/SmartScreen verdict on downloads
            "streamedfilestate",        // 32-byte state blob Windows 11 puts on files in %TEMP%
            "com.dropbox.attributes", "com.dropbox.attrs",
            "ms-properties",            // OneDrive / property store
            "oecustomproperty", "encryptable", "favicon",
            "afp_afpinfo", "afp_resource",
            "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}");
    static final long BENIGN_MAX_SIZE = 4096;

    /**
     * Non-default data streams on {@code path}. The default stream ("::$DATA")
     * and small, well-known metadata streams (see {@link #isBenign}) are excluded.
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
                if (clean != null && !clean.isEmpty()) {
                    Stream st = new Stream(clean, size);
                    if (!isBenign(st)) {
                        out.add(st);
                    }
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

    /** A well-known metadata stream of plausible metadata size. */
    static boolean isBenign(Stream st) {
        return st.size() <= BENIGN_MAX_SIZE && BENIGN_NAMES.contains(st.name().toLowerCase(Locale.ROOT));
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

package ru.moon.checker.win;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.ptr.IntByReference;
import ru.moon.checker.core.Platform;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Enumerates fixed (local, non-removable) drive letters — the volumes worth
 * scanning. Network and removable drives are skipped.
 */
public final class Volumes {

    private static final int DRIVE_FIXED = 3;

    private Volumes() {
    }

    /**
     * Volume serial number -> drive letter for fixed drives. Prefetch records
     * paths as {@code \VOLUME{<created>-<serial>}\...}; this maps them back to
     * {@code C:\...}.
     */
    public static Map<Long, Character> serialToLetter() {
        Map<Long, Character> out = new HashMap<>();
        for (char d : fixedDrives()) {
            try {
                IntByReference serial = new IntByReference();
                char[] name = new char[261];
                char[] fs = new char[261];
                if (Kernel32.INSTANCE.GetVolumeInformation(d + ":\\", name, name.length, serial, null, null,
                        fs, fs.length)) {
                    out.put(serial.getValue() & 0xFFFFFFFFL, d);
                }
            } catch (Throwable ignored) {
                // unreadable volume: its paths stay in \VOLUME{..} form
            }
        }
        return out;
    }

    public static List<Character> fixedDrives() {
        List<Character> out = new ArrayList<>();
        if (!Platform.isWindows()) {
            return out;
        }
        for (File root : File.listRoots()) {
            String p = root.getPath(); // e.g. "C:\\"
            if (p.length() < 2 || !Character.isLetter(p.charAt(0))) {
                continue;
            }
            try {
                int type = Kernel32.INSTANCE.GetDriveType(p);
                if (type == DRIVE_FIXED) {
                    out.add(Character.toUpperCase(p.charAt(0)));
                }
            } catch (Throwable t) {
                // if we cannot classify, include it — better to scan than miss
                out.add(Character.toUpperCase(p.charAt(0)));
            }
        }
        return out;
    }
}

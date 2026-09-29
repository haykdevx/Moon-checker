package ru.moon.checker.win;

import com.sun.jna.platform.win32.Kernel32;
import ru.moon.checker.core.Platform;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Enumerates fixed (local, non-removable) drive letters — the volumes worth
 * scanning. Network and removable drives are skipped.
 */
public final class Volumes {

    private static final int DRIVE_FIXED = 3;

    private Volumes() {
    }

    /** "NTFS", "exFAT", "FAT32", "ReFS"…, or "" when Windows does not say. */
    public static String fileSystem(char letter) {
        if (!Platform.isWindows()) {
            return "";
        }
        try {
            char[] fs = new char[64];
            boolean ok = Kernel32.INSTANCE.GetVolumeInformation(letter + ":\\", null, 0, null, null, null, fs, fs.length);
            return ok ? com.sun.jna.Native.toString(fs) : "";
        } catch (Throwable t) {
            return "";
        }
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

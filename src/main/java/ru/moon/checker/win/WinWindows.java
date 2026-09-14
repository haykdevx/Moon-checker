package ru.moon.checker.win;

import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinDef.HWND;
import com.sun.jna.platform.win32.WinUser;
import ru.moon.checker.core.Platform;

import java.util.ArrayList;
import java.util.List;

/**
 * Enumerates the titles of visible top-level windows. External / overlay cheats
 * frequently create a visible window ("Nixware", "Fatality", a menu overlay)
 * whose title matches a signature even when the executable was renamed.
 */
public final class WinWindows {

    private WinWindows() {
    }

    public static List<String> visibleTitles() {
        List<String> titles = new ArrayList<>();
        if (!Platform.isWindows()) {
            return titles;
        }
        try {
            User32 user32 = User32.INSTANCE;
            WinUser.WNDENUMPROC cb = (HWND hWnd, com.sun.jna.Pointer data) -> {
                try {
                    if (!user32.IsWindowVisible(hWnd)) {
                        return true;
                    }
                    int len = user32.GetWindowTextLength(hWnd);
                    if (len <= 0) {
                        return true;
                    }
                    char[] buf = new char[len + 1];
                    int read = user32.GetWindowText(hWnd, buf, buf.length);
                    if (read > 0) {
                        titles.add(new String(buf, 0, read));
                    }
                } catch (Throwable ignored) {
                    // keep enumerating
                }
                return true;
            };
            user32.EnumWindows(cb, null);
        } catch (Throwable t) {
            // best-effort
        }
        return titles;
    }
}

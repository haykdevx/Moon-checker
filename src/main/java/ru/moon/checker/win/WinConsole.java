package ru.moon.checker.win;

import com.sun.jna.Native;
import com.sun.jna.win32.StdCallLibrary;
import ru.moon.checker.core.Platform;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Encoding of classic console tools ({@code reg.exe}, {@code sc.exe},
 * {@code bcdedit}) when their output is piped: the OEM code page — cp866 on
 * Russian Windows, cp437 on US English — not UTF-8 and not the ANSI page.
 */
public final class WinConsole {

    private static volatile Charset cached;

    private interface K32 extends StdCallLibrary {
        K32 INSTANCE = Native.load("kernel32", K32.class);

        int GetOEMCP();
    }

    private WinConsole() {
    }

    public static Charset charset() {
        Charset c = cached;
        if (c == null) {
            c = resolve();
            cached = c;
        }
        return c;
    }

    private static Charset resolve() {
        if (!Platform.isWindows()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return forCodePage(K32.INSTANCE.GetOEMCP());
        } catch (Throwable t) {
            return StandardCharsets.UTF_8;
        }
    }

    /** Java charset for a Windows code page number, UTF-8 when unknown. */
    static Charset forCodePage(int codePage) {
        if (codePage == 65001) {
            return StandardCharsets.UTF_8;
        }
        for (String name : new String[]{"cp" + codePage, "IBM" + codePage, "x-IBM" + codePage, "windows-" + codePage}) {
            try {
                return Charset.forName(name);
            } catch (Exception ignored) {
                // try the next alias
            }
        }
        return StandardCharsets.UTF_8;
    }
}

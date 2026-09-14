package ru.moon.checker.win;

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;
import com.sun.jna.platform.win32.WinReg.HKEY;
import ru.moon.checker.core.Platform;

import java.util.Map;
import java.util.TreeMap;

/**
 * Null-safe wrapper over JNA's registry helpers. Every method returns an empty
 * / null result instead of throwing, so callers never need try/catch for a
 * missing key — which is the common case during forensics.
 */
public final class Registry {

    public static final HKEY HKLM = WinReg.HKEY_LOCAL_MACHINE;
    public static final HKEY HKCU = WinReg.HKEY_CURRENT_USER;
    public static final HKEY HKU = WinReg.HKEY_USERS;

    private Registry() {
    }

    /** A (hive, path) pair, handy for iterating the same key across hives. */
    public record HKEYPair(HKEY root, String path) {
    }

    private static boolean win() {
        return Platform.isWindows();
    }

    public static boolean keyExists(HKEY root, String path) {
        if (!win()) {
            return false;
        }
        try {
            return Advapi32Util.registryKeyExists(root, path);
        } catch (Throwable t) {
            return false;
        }
    }

    public static String[] subKeys(HKEY root, String path) {
        if (!win() || !keyExists(root, path)) {
            return new String[0];
        }
        try {
            return Advapi32Util.registryGetKeys(root, path);
        } catch (Throwable t) {
            return new String[0];
        }
    }

    public static String getString(HKEY root, String path, String name) {
        if (!win()) {
            return null;
        }
        try {
            if (Advapi32Util.registryValueExists(root, path, name)) {
                return Advapi32Util.registryGetStringValue(root, path, name);
            }
        } catch (Throwable t) {
            // fall through
        }
        return null;
    }

    public static byte[] getBinary(HKEY root, String path, String name) {
        if (!win()) {
            return null;
        }
        try {
            if (Advapi32Util.registryValueExists(root, path, name)) {
                return Advapi32Util.registryGetBinaryValue(root, path, name);
            }
        } catch (Throwable t) {
            // fall through
        }
        return null;
    }

    public static int getIntOr(HKEY root, String path, String name, int fallback) {
        if (!win()) {
            return fallback;
        }
        try {
            if (Advapi32Util.registryValueExists(root, path, name)) {
                return Advapi32Util.registryGetIntValue(root, path, name);
            }
        } catch (Throwable t) {
            // fall through
        }
        return fallback;
    }

    /** All values under a key as name -> object; empty map on any problem. */
    public static Map<String, Object> values(HKEY root, String path) {
        if (!win() || !keyExists(root, path)) {
            return new TreeMap<>();
        }
        try {
            return Advapi32Util.registryGetValues(root, path);
        } catch (Throwable t) {
            return new TreeMap<>();
        }
    }

    /** Raw binary values under a key (needed for UserAssist Count blobs). */
    public static Map<String, byte[]> binaryValues(HKEY root, String path) {
        Map<String, byte[]> out = new TreeMap<>();
        for (String name : values(root, path).keySet()) {
            byte[] b = getBinary(root, path, name);
            if (b != null) {
                out.put(name, b);
            }
        }
        return out;
    }
}

package ru.moon.checker.win;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinReg;
import com.sun.jna.platform.win32.WinReg.HKEY;
import com.sun.jna.ptr.IntByReference;
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

    /**
     * All values under a key as name -> object; empty map on any problem.
     *
     * <p>JNA's bulk reader throws on value types it does not map
     * ({@code REG_RESOURCE_LIST}, {@code REG_LINK}, a zero-length DWORD...), which
     * used to discard every value in the key. On that error the key is enumerated
     * one value at a time instead; unmappable values keep their name with a
     * {@code null} value, so name-based artefacts (BAM, MUICache) are not lost.
     */
    public static Map<String, Object> values(HKEY root, String path) {
        if (!win() || !keyExists(root, path)) {
            return new TreeMap<>();
        }
        try {
            return Advapi32Util.registryGetValues(root, path);
        } catch (Throwable t) {
            return valuesOneByOne(root, path);
        }
    }

    private static Map<String, Object> valuesOneByOne(HKEY root, String path) {
        Map<String, Object> out = new TreeMap<>();
        HKEY key = null;
        try {
            key = Advapi32Util.registryGetKey(root, path, WinNT.KEY_READ).getValue();
            IntByReference count = new IntByReference();
            IntByReference maxName = new IntByReference();
            if (Advapi32.INSTANCE.RegQueryInfoKey(key, null, null, null, null, null, null,
                    count, maxName, null, null, null) != 0) {
                return out;
            }
            char[] name = new char[maxName.getValue() + 1];
            for (int i = 0; i < count.getValue(); i++) {
                IntByReference nameLen = new IntByReference(name.length);
                IntByReference type = new IntByReference();
                if (Advapi32.INSTANCE.RegEnumValue(key, i, name, nameLen, null, type, (Pointer) null, null) != 0) {
                    continue;
                }
                String n = new String(name, 0, nameLen.getValue());
                out.put(n, readTyped(root, path, n, type.getValue()));
            }
        } catch (Throwable t) {
            // best-effort: return whatever was enumerated
        } finally {
            if (key != null) {
                try {
                    Advapi32Util.registryCloseKey(key);
                } catch (Throwable ignored) {
                    // already closed
                }
            }
        }
        return out;
    }

    private static Object readTyped(HKEY root, String path, String name, int type) {
        try {
            return switch (type) {
                case WinNT.REG_SZ, WinNT.REG_EXPAND_SZ -> Advapi32Util.registryGetStringValue(root, path, name);
                case WinNT.REG_DWORD -> Advapi32Util.registryGetIntValue(root, path, name);
                case WinNT.REG_QWORD -> Advapi32Util.registryGetLongValue(root, path, name);
                case WinNT.REG_BINARY -> Advapi32Util.registryGetBinaryValue(root, path, name);
                case WinNT.REG_MULTI_SZ -> Advapi32Util.registryGetStringArray(root, path, name);
                default -> null;
            };
        } catch (Throwable t) {
            return null;
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

package ru.moon.checker.win;

import java.util.Locale;
import java.util.function.Function;

/**
 * Turns AmCache registry keys into records. Pure functions over a value lookup
 * ({@code name -> string value or null}), so the layouts are unit-testable
 * without a Windows registry.
 *
 * <ul>
 *   <li>{@code Root\InventoryApplicationFile\<id>} — Windows 10 1709+: every
 *       executable seen ({@code LowerCaseLongPath}, {@code FileId}, {@code Name}).</li>
 *   <li>{@code Root\File\<volume GUID>\<file reference>} — Windows 8 to 10 1607:
 *       numbered values, {@code 15} = full path, {@code 101} = SHA-1.</li>
 *   <li>{@code Root\InventoryDriverBinary\<path>} — every driver binary the OS
 *       inventoried, with its SHA-1, signing state and kernel-mode flag, kept after
 *       the driver is removed (key name is the lower-case path with '/').</li>
 * </ul>
 */
public final class AmCacheRecords {

    private AmCacheRecords() {
    }

    /**
     * A driver binary from {@code InventoryDriverBinary}.
     *
     * @param path       e.g. {@code c:\windows\system32\drivers\iqvw64e.sys}
     * @param name       file name
     * @param sha1       bare lower-case SHA-1, or null
     * @param signed     {@code DriverSigned=1}
     * @param kernelMode {@code DriverIsKernelMode=1}
     * @param company    {@code DriverCompany}
     * @param service    service name the driver was registered under
     * @param lastWrite  {@code DriverLastWriteTime} as recorded (local, "MM/dd/yyyy HH:mm:ss")
     */
    public record Driver(String path, String name, String sha1, boolean signed, boolean kernelMode,
                         String company, String service, String lastWrite) {
    }

    static AmCache.Entry inventoryFile(Function<String, String> value) {
        String path = value.apply("LowerCaseLongPath");
        String name = value.apply("Name");
        if (path == null && name == null) {
            return null;
        }
        return new AmCache.Entry(path, AmCache.normalizeFileId(value.apply("FileId")), name);
    }

    static AmCache.Entry legacyFile(Function<String, String> value) {
        String path = value.apply("15");
        if (path == null || path.isBlank()) {
            return null;
        }
        return new AmCache.Entry(path, AmCache.normalizeFileId(value.apply("101")), baseName(path));
    }

    static Driver inventoryDriver(String keyName, Function<String, String> value) {
        String path = keyName == null ? null : keyName.replace('/', '\\');
        String name = value.apply("DriverName");
        if (name == null || name.isBlank()) {
            name = path == null ? null : baseName(path);
        }
        if (name == null) {
            return null;
        }
        return new Driver(path, name, AmCache.normalizeFileId(value.apply("DriverId")),
                "1".equals(trim(value.apply("DriverSigned"))), "1".equals(trim(value.apply("DriverIsKernelMode"))),
                blankToNull(value.apply("DriverCompany")), blankToNull(value.apply("Service")),
                blankToNull(value.apply("DriverLastWriteTime")));
    }

    static String baseName(String path) {
        String p = path.replace('/', '\\');
        int i = p.lastIndexOf('\\');
        return (i >= 0 ? p.substring(i + 1) : p).toLowerCase(Locale.ROOT);
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}

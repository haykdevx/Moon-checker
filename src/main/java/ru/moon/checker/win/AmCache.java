package ru.moon.checker.win;

import ru.moon.checker.core.Log;
import ru.moon.checker.core.Platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Reads the Windows AmCache hive
 * ({@code C:\Windows\AppCompat\Programs\Amcache.hve}). AmCache records the full
 * path and SHA-1 of executables Windows has seen — and keeps entries long after
 * the file itself is deleted. It is one of the strongest "this cheat existed and
 * ran here" artefacts and survives most cleanup short of wiping the hive.
 */
public final class AmCache {

    private AmCache() {
    }

    public record Entry(String path, String sha1, String name) {
    }

    /** A driver binary Windows has seen ({@code Root\InventoryDriverBinary}). */
    public record Driver(String path, String signed) {
    }

    /** Everything read from one mount of the hive. */
    public record Snapshot(List<Entry> files, List<Driver> drivers) {
        static Snapshot empty() {
            return new Snapshot(List.of(), List.of());
        }
    }

    /**
     * AmCache {@code FileId} is the SHA-1 prefixed with "0000". Normalise it to
     * a bare 40-char lowercase SHA-1, or null if it doesn't look like one.
     */
    public static String normalizeFileId(String fileId) {
        if (fileId == null) {
            return null;
        }
        String s = fileId.trim().toLowerCase(Locale.ROOT);
        if (s.length() == 44 && s.startsWith("0000")) {
            s = s.substring(4);
        }
        return s.matches("[0-9a-f]{40}") ? s : null;
    }

    /** Back-compat: just the executable entries. */
    public static List<Entry> read() {
        return readAll().files();
    }

    /** Mount the hive once and read both application files and driver binaries. */
    public static Snapshot readAll() {
        List<Entry> files = new ArrayList<>();
        List<Driver> drivers = new ArrayList<>();
        if (!Platform.isWindows()) {
            return Snapshot.empty();
        }
        Path hive = Platform.windowsDir().resolve("AppCompat").resolve("Programs").resolve("Amcache.hve");
        if (!Files.isRegularFile(hive)) {
            return Snapshot.empty();
        }
        String tempKey = "MoonAmcache";
        boolean loaded = false;
        try {
            Process p = new ProcessBuilder("reg", "load", "HKLM\\" + tempKey, hive.toString())
                    .redirectErrorStream(true).start();
            loaded = p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0;
            if (!loaded) {
                return Snapshot.empty();
            }
            String base = tempKey + "\\Root\\InventoryApplicationFile";
            for (String sub : Registry.subKeys(Registry.HKLM, base)) {
                String keyPath = base + "\\" + sub;
                String path = Registry.getString(Registry.HKLM, keyPath, "LowerCaseLongPath");
                String fileId = Registry.getString(Registry.HKLM, keyPath, "FileId");
                String name = Registry.getString(Registry.HKLM, keyPath, "Name");
                if (path != null || name != null) {
                    files.add(new Entry(path, normalizeFileId(fileId), name));
                }
            }
            String drvBase = tempKey + "\\Root\\InventoryDriverBinary";
            for (String sub : Registry.subKeys(Registry.HKLM, drvBase)) {
                String keyPath = drvBase + "\\" + sub;
                String path = Registry.getString(Registry.HKLM, keyPath, "DriverName");
                String signed = Registry.getString(Registry.HKLM, keyPath, "DriverSigned");
                drivers.add(new Driver(path != null ? path : sub, signed));
            }
        } catch (Exception e) {
            Log.warn("AmCache read failed", e);
        } finally {
            if (loaded) {
                try {
                    new ProcessBuilder("reg", "unload", "HKLM\\" + tempKey)
                            .redirectErrorStream(true).start().waitFor(10, TimeUnit.SECONDS);
                } catch (Exception e) {
                    Log.warn("AmCache unload failed", e);
                }
            }
        }
        return new Snapshot(files, drivers);
    }
}

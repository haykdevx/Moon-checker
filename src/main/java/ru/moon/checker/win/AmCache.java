package ru.moon.checker.win;

import ru.moon.checker.core.Log;
import ru.moon.checker.core.Platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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

    /** Everything read from one mount of the hive; {@code problem} is why nothing could be read. */
    public record Snapshot(List<Entry> files, List<Driver> drivers, String problem) {
        static Snapshot empty() {
            return new Snapshot(List.of(), List.of(), null);
        }

        static Snapshot failed(String why) {
            return new Snapshot(List.of(), List.of(), why);
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

    /**
     * Mount the hive once and read both application files and driver binaries.
     * Windows often keeps Amcache.hve open, and then {@code reg load} refuses it; a
     * copy is taken through a shadow copy ({@code esentutl /vss}, built into Windows)
     * and that copy is read. When neither works the snapshot says why — the collector
     * turns that into a collection error, never into "nothing found".
     */
    public static Snapshot readAll() {
        if (!Platform.isWindows()) {
            return Snapshot.empty();
        }
        Path hive = Platform.windowsDir().resolve("AppCompat").resolve("Programs").resolve("Amcache.hve");
        if (!Files.isRegularFile(hive)) {
            return Snapshot.failed("Amcache.hve not found at " + hive);
        }
        String key = "MoonAmcache_" + ProcessHandle.current().pid();
        WinCommand.Result direct = WinCommand.run(30, "reg", "load", "HKLM\\" + key, hive.toString());
        if (direct.ok()) {
            return readMounted(key);
        }
        Path copyDir = null;
        try {
            copyDir = Files.createTempDirectory("moon-amcache");
            Path copy = copyDir.resolve("Amcache.hve");
            WinCommand.Result vss = WinCommand.run(120, "esentutl.exe", "/y", hive.toString(), "/vss", "/d",
                    copy.toString());
            for (String log : new String[]{".LOG1", ".LOG2"}) {  // transaction logs make the copy consistent
                Path src = hive.resolveSibling("Amcache.hve" + log);
                if (Files.isRegularFile(src)) {
                    WinCommand.run(60, "esentutl.exe", "/y", src.toString(), "/vss", "/d",
                            copyDir.resolve("Amcache.hve" + log).toString());
                }
            }
            if (!Files.isRegularFile(copy)) {
                return Snapshot.failed("Amcache.hve is locked and the shadow copy failed: "
                        + firstLine(direct.output()) + " / " + firstLine(vss.output()));
            }
            WinCommand.Result load = WinCommand.run(30, "reg", "load", "HKLM\\" + key, copy.toString());
            if (!load.ok()) {
                return Snapshot.failed("the copy of Amcache.hve could not be loaded: " + firstLine(load.output()));
            }
            return readMounted(key);
        } catch (Exception e) {
            return Snapshot.failed("Amcache.hve could not be copied: " + e.getMessage());
        } finally {
            if (copyDir != null) {
                deleteQuietly(copyDir);
            }
        }
    }

    private static Snapshot readMounted(String key) {
        List<Entry> files = new ArrayList<>();
        List<Driver> drivers = new ArrayList<>();
        try {
            String base = key + "\\Root\\InventoryApplicationFile";
            for (String sub : Registry.subKeys(Registry.HKLM, base)) {
                String keyPath = base + "\\" + sub;
                String path = Registry.getString(Registry.HKLM, keyPath, "LowerCaseLongPath");
                String fileId = Registry.getString(Registry.HKLM, keyPath, "FileId");
                String name = Registry.getString(Registry.HKLM, keyPath, "Name");
                if (path != null || name != null) {
                    files.add(new Entry(path, normalizeFileId(fileId), name));
                }
            }
            String drvBase = key + "\\Root\\InventoryDriverBinary";
            for (String sub : Registry.subKeys(Registry.HKLM, drvBase)) {
                // the key name is the driver's full path (forward slashes); DriverName is only the file name
                String signed = Registry.getString(Registry.HKLM, drvBase + "\\" + sub, "DriverSigned");
                drivers.add(new Driver(sub.replace('/', '\\'), signed));
            }
        } catch (Exception e) {
            Log.warn("AmCache read failed", e);
        } finally {
            WinCommand.run(15, "reg", "unload", "HKLM\\" + key);
        }
        if (files.isEmpty() && drivers.isEmpty()) {
            return Snapshot.failed("Amcache.hve was mounted but held no inventory (unexpected layout)");
        }
        return new Snapshot(files, drivers, null);
    }

    static String firstLine(String s) {
        if (s == null) {
            return "";
        }
        for (String line : s.split("\\R")) {
            if (!line.isBlank()) {
                return line.strip();
            }
        }
        return "";
    }

    private static void deleteQuietly(Path dir) {
        try (var walk = Files.walk(dir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                    // a file the OS still holds: the temp folder is cleaned up later
                }
            });
        } catch (Exception ignored) {
            // nothing to clean
        }
    }
}

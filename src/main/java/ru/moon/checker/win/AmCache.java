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

    /** Mount point under HKLM; stable so a mount left by a crashed run is reclaimed. */
    static final String TEMP_KEY = "MoonAmcache";

    private AmCache() {
    }

    public record Entry(String path, String sha1, String name) {
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

    /**
     * A mounted AmCache hive. The live file is tried first; on Windows 10/11 the
     * system holds it open, so a VSS snapshot (with transaction logs) is mounted
     * instead. Closing unloads the key and deletes the snapshot.
     */
    public static final class Mount implements AutoCloseable {
        private final String key;
        private final Path hiveFile;
        private final boolean snapshot;
        private final String error;
        private final Path snapshotDir;

        private Mount(String key, Path hiveFile, boolean snapshot, String error, Path snapshotDir) {
            this.key = key;
            this.hiveFile = hiveFile;
            this.snapshot = snapshot;
            this.error = error;
            this.snapshotDir = snapshotDir;
        }

        public boolean loaded() {
            return error == null;
        }

        /** Registry path of the hive root under HKLM, e.g. {@code MoonAmcache\Root}. */
        public String root() {
            return key + "\\Root";
        }

        public Path hiveFile() {
            return hiveFile;
        }

        public boolean fromSnapshot() {
            return snapshot;
        }

        public String error() {
            return error;
        }

        @Override
        public void close() {
            if (loaded()) {
                HiveMount.unload(HiveMount.Root.HKLM, key);
            }
            HiveMount.deleteSnapshot(snapshotDir);
        }
    }

    public static Mount mount(String key) {
        Path hive = Platform.windowsDir().resolve("AppCompat").resolve("Programs").resolve("Amcache.hve");
        if (!Platform.isWindows() || !Files.isRegularFile(hive)) {
            return new Mount(key, hive, false, "no " + hive, null);
        }
        HiveMount.LoadResult live = HiveMount.load(HiveMount.Root.HKLM, key, hive);
        if (live.loaded()) {
            return new Mount(key, hive, false, null, null);
        }
        Path dir = null;
        try {
            dir = Files.createTempDirectory("moon-amcache");
            Path copy = HiveMount.snapshot(hive, dir);
            if (copy == null) {
                HiveMount.deleteSnapshot(dir);
                return new Mount(key, hive, false, "live hive locked (" + live.output() + ") and VSS copy failed", null);
            }
            HiveMount.LoadResult fromCopy = HiveMount.load(HiveMount.Root.HKLM, key, copy);
            return fromCopy.loaded() ? new Mount(key, copy, true, null, dir)
                    : new Mount(key, copy, true, "snapshot not mountable: " + fromCopy.output(), dir);
        } catch (Exception e) {
            HiveMount.deleteSnapshot(dir);
            return new Mount(key, hive, false, e.toString(), null);
        }
    }

    /** Everything read from one mount of the hive. */
    public record Snapshot(List<Entry> files, List<AmCacheRecords.Driver> drivers, String error) {
    }

    /** Executables seen by Windows (both hive layouts). */
    public static List<Entry> read() {
        return readAll().files();
    }

    /**
     * Mounts the hive once and reads the executable inventory (1709+ and the
     * older {@code Root\File} layout) plus the driver inventory.
     */
    public static Snapshot readAll() {
        List<Entry> files = new ArrayList<>();
        List<AmCacheRecords.Driver> drivers = new ArrayList<>();
        if (!Platform.isWindows()) {
            return new Snapshot(files, drivers, "not Windows");
        }
        try (Mount m = mount(TEMP_KEY)) {
            if (!m.loaded()) {
                Log.warn("AmCache hive not mounted: " + m.error());
                return new Snapshot(files, drivers, m.error());
            }
            String inventory = m.root() + "\\InventoryApplicationFile";
            for (String sub : Registry.subKeys(Registry.HKLM, inventory)) {
                add(files, AmCacheRecords.inventoryFile(lookup(inventory + "\\" + sub)));
            }
            String legacy = m.root() + "\\File";
            for (String volume : Registry.subKeys(Registry.HKLM, legacy)) {
                for (String ref : Registry.subKeys(Registry.HKLM, legacy + "\\" + volume)) {
                    add(files, AmCacheRecords.legacyFile(lookup(legacy + "\\" + volume + "\\" + ref)));
                }
            }
            String driverBase = m.root() + "\\InventoryDriverBinary";
            for (String sub : Registry.subKeys(Registry.HKLM, driverBase)) {
                add(drivers, AmCacheRecords.inventoryDriver(sub, lookup(driverBase + "\\" + sub)));
            }
        } catch (Exception e) {
            Log.warn("AmCache read failed", e);
            return new Snapshot(files, drivers, e.toString());
        }
        return new Snapshot(files, drivers, null);
    }

    private static java.util.function.Function<String, String> lookup(String keyPath) {
        return name -> Registry.getString(Registry.HKLM, keyPath, name);
    }

    private static <T> void add(List<T> list, T item) {
        if (item != null) {
            list.add(item);
        }
    }
}

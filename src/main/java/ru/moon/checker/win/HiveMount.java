package ru.moon.checker.win;

import ru.moon.checker.core.Exec;
import ru.moon.checker.core.Log;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Mounts an offline registry hive file under {@code HKLM\<key>} or
 * {@code HKU\<key>} with {@code reg load} and removes it again.
 *
 * <p>Robustness rules learned from live systems:
 * <ul>
 *   <li>a key left mounted by a crashed or killed earlier run makes every later
 *       {@code reg load} to that name fail, so a stale mount is unloaded first;</li>
 *   <li>{@code reg unload} fails while any handle into the hive is still open
 *       (including ones the registry itself is flushing), so it is retried.</li>
 * </ul>
 * {@code reg.exe} enables SeBackup/SeRestore itself; the caller must be elevated.
 */
public final class HiveMount {

    /** Root as understood by {@code reg.exe}. */
    public enum Root {
        HKLM(Registry.HKLM), HKU(Registry.HKU);

        final com.sun.jna.platform.win32.WinReg.HKEY hkey;

        Root(com.sun.jna.platform.win32.WinReg.HKEY hkey) {
            this.hkey = hkey;
        }
    }

    private static final Duration LOAD_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration UNLOAD_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration SNAPSHOT_TIMEOUT = Duration.ofSeconds(90);
    private static final int UNLOAD_ATTEMPTS = 4;

    private HiveMount() {
    }

    /** Outcome of a load attempt; {@code output} is reg.exe's (localised) message. */
    public record LoadResult(boolean loaded, boolean staleRemoved, String output) {
    }

    public static LoadResult load(Root root, String key, Path hiveFile) {
        boolean stale = false;
        if (Registry.keyExists(root.hkey, key)) {
            stale = unload(root, key);
            Log.warn("hive key " + root + "\\" + key + " was left mounted by an earlier run; unloaded=" + stale);
        }
        Exec.Result r = Exec.run(List.of("reg.exe", "load", root + "\\" + key, hiveFile.toString()),
                LOAD_TIMEOUT, WinConsole.charset());
        return new LoadResult(r.ok(), stale, r.output().strip());
    }

    /**
     * Copies a hive that the system holds open (e.g. {@code Amcache.hve}, where
     * {@code reg load} fails with a sharing violation on Windows 10/11) together
     * with its {@code .LOG1}/{@code .LOG2} transaction logs, using the Volume
     * Shadow Copy service via the built-in {@code esentutl /y /vss}. The logs let
     * {@code reg load} replay writes not yet flushed into the primary file.
     * Returns the copied hive, or null when the copy failed.
     */
    public static Path snapshot(Path hive, Path dir) {
        Path copy = null;
        for (String suffix : new String[]{"", ".LOG1", ".LOG2"}) {
            Path src = hive.resolveSibling(hive.getFileName() + suffix);
            if (!suffix.isEmpty() && !Files.isRegularFile(src)) {
                continue;
            }
            Path dst = dir.resolve(hive.getFileName() + suffix);
            Exec.Result r = Exec.run(List.of("esentutl.exe", "/y", src.toString(), "/vss", "/d", dst.toString()),
                    SNAPSHOT_TIMEOUT, WinConsole.charset());
            if (!r.ok() || !Files.isRegularFile(dst)) {
                Log.warn("esentutl snapshot of " + src + " failed: " + r.output().strip());
                if (suffix.isEmpty()) {
                    return null;
                }
                continue; // a missing log only loses unflushed changes
            }
            if (suffix.isEmpty()) {
                copy = dst;
            }
        }
        return copy;
    }

    /** Best-effort removal of a snapshot folder once its hive is unloaded. */
    public static void deleteSnapshot(Path dir) {
        if (dir == null) {
            return;
        }
        try (var files = Files.list(dir)) {
            files.forEach(f -> {
                try {
                    Files.deleteIfExists(f);
                } catch (Exception e) {
                    Log.warn("snapshot file still in use: " + f);
                }
            });
        } catch (Exception ignored) {
            // listing failed; try the directory anyway
        }
        try {
            Files.deleteIfExists(dir); // after the listing handle is closed (Windows)
        } catch (Exception ignored) {
            // leftover temp folder is harmless
        }
    }

    /** Unloads with retries; true once the key is gone. */
    public static boolean unload(Root root, String key) {
        for (int attempt = 1; attempt <= UNLOAD_ATTEMPTS; attempt++) {
            Exec.Result r = Exec.run(List.of("reg.exe", "unload", root + "\\" + key),
                    UNLOAD_TIMEOUT, WinConsole.charset());
            if (r.ok() || !Registry.keyExists(root.hkey, key)) {
                return true;
            }
            try {
                Thread.sleep(250L * attempt);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        Log.warn("could not unload " + root + "\\" + key);
        return false;
    }
}

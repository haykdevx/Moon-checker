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

    public static List<Entry> read() {
        List<Entry> out = new ArrayList<>();
        if (!Platform.isWindows()) {
            return out;
        }
        Path hive = Platform.windowsDir().resolve("AppCompat").resolve("Programs").resolve("Amcache.hve");
        if (!Files.isRegularFile(hive)) {
            return out;
        }
        String tempKey = "MoonAmcache";
        boolean loaded = false;
        try {
            Process p = new ProcessBuilder("reg", "load", "HKLM\\" + tempKey, hive.toString())
                    .redirectErrorStream(true).start();
            loaded = p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0;
            if (!loaded) {
                return out;
            }
            String base = tempKey + "\\Root\\InventoryApplicationFile";
            for (String sub : Registry.subKeys(Registry.HKLM, base)) {
                String keyPath = base + "\\" + sub;
                String path = Registry.getString(Registry.HKLM, keyPath, "LowerCaseLongPath");
                String fileId = Registry.getString(Registry.HKLM, keyPath, "FileId");
                String name = Registry.getString(Registry.HKLM, keyPath, "Name");
                if (path != null || name != null) {
                    out.add(new Entry(path, normalizeFileId(fileId), name));
                }
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
        return out;
    }
}

package ru.moon.checker.core;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Thin OS abstraction. All Windows-specific logic checks {@link #isWindows()}
 * first so the app still starts (and tests still run) on Linux/macOS, where
 * Windows modules simply report that they were skipped.
 */
public final class Platform {

    private Platform() {
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    public static boolean isLinux() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("linux") || os.contains("nix") || os.contains("nux");
    }

    public static String osName() {
        return System.getProperty("os.name", "unknown");
    }

    /** e.g. {@code C:\}. Falls back to {@code C:\} if the env var is missing. */
    public static Path systemDrive() {
        String d = System.getenv("SystemDrive");
        if (d == null || d.isBlank()) {
            d = "C:";
        }
        return Path.of(d + File.separator);
    }

    public static Path windowsDir() {
        String w = System.getenv("SystemRoot");
        if (w == null || w.isBlank()) {
            w = "C:\\Windows";
        }
        return Path.of(w);
    }

    public static Path prefetchDir() {
        return windowsDir().resolve("Prefetch");
    }

    /**
     * Every local user profile that has its own folder under {@code C:\Users}.
     * On non-Windows this returns the current {@code user.home} so parsers can
     * still be exercised against test fixtures.
     */
    public static List<Path> userProfiles() {
        List<Path> out = new ArrayList<>();
        if (isLinux()) {
            // enumerate /home/* plus /root (when running elevated); fall back to
            // the current user's home if nothing is enumerable.
            Path home = Path.of("/home");
            if (Files.isDirectory(home)) {
                try (var stream = Files.list(home)) {
                    stream.filter(Files::isDirectory).forEach(out::add);
                } catch (Exception ignored) {
                    // best-effort
                }
            }
            Path root = Path.of("/root");
            if (Files.isDirectory(root)) {
                out.add(root);
            }
            if (out.isEmpty()) {
                out.add(Path.of(System.getProperty("user.home", "/tmp")));
            }
            return out;
        }
        if (!isWindows()) {
            out.add(Path.of(System.getProperty("user.home")));
            return out;
        }
        Path users = systemDrive().resolve("Users");
        if (!Files.isDirectory(users)) {
            return out;
        }
        try (var stream = Files.list(users)) {
            stream.filter(Files::isDirectory)
                  .filter(p -> {
                      String n = p.getFileName().toString();
                      return !n.equalsIgnoreCase("Public")
                              && !n.equalsIgnoreCase("Default")
                              && !n.equalsIgnoreCase("Default User")
                              && !n.equalsIgnoreCase("All Users");
                  })
                  .forEach(out::add);
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }

    /** {@code <profile>\AppData\Local} for a given user profile. */
    public static Path localAppData(Path profile) {
        return profile.resolve("AppData").resolve("Local");
    }

    /** {@code <profile>\AppData\Roaming} for a given user profile. */
    public static Path roamingAppData(Path profile) {
        return profile.resolve("AppData").resolve("Roaming");
    }
}

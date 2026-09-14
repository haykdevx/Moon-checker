package ru.moon.checker.linux;

import ru.moon.checker.core.Platform;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Read-only access to Linux {@code /proc}. Used by the Linux check modules to
 * enumerate processes, their executables and, critically, their memory maps —
 * an injected {@code .so} (LD_PRELOAD or ptrace injection) shows up as a mapped
 * library in the target process, often with a {@code (deleted)} marker.
 */
public final class Proc {

    private Proc() {
    }

    public static boolean available() {
        return Platform.isLinux() && Files.isDirectory(Path.of("/proc"));
    }

    /** All numeric PIDs currently under /proc. */
    public static List<Integer> pids() {
        List<Integer> out = new ArrayList<>();
        if (!available()) {
            return out;
        }
        try (var stream = Files.list(Path.of("/proc"))) {
            stream.forEach(p -> {
                String n = p.getFileName().toString();
                if (n.chars().allMatch(Character::isDigit)) {
                    try {
                        out.add(Integer.parseInt(n));
                    } catch (NumberFormatException ignored) {
                    }
                }
            });
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }

    public static String comm(int pid) {
        return readTrim(Path.of("/proc", String.valueOf(pid), "comm"));
    }

    /** Full command line, NUL-separated in procfs, joined with spaces. */
    public static String cmdline(int pid) {
        byte[] b = readBytes(Path.of("/proc", String.valueOf(pid), "cmdline"));
        if (b == null) {
            return null;
        }
        return new String(b, StandardCharsets.UTF_8).replace('\0', ' ').trim();
    }

    /** Resolved path of the process image (may end with " (deleted)"). */
    public static String exe(int pid) {
        try {
            Path link = Path.of("/proc", String.valueOf(pid), "exe");
            return Files.readSymbolicLink(link).toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** Lines of {@code /proc/<pid>/maps}. */
    public static List<String> maps(int pid) {
        List<String> out = new ArrayList<>();
        try {
            out.addAll(Files.readAllLines(Path.of("/proc", String.valueOf(pid), "maps"),
                    StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            // permission / gone
        }
        return out;
    }

    /** {@code /proc/<pid>/environ} as raw entries (KEY=VALUE). */
    public static List<String> environ(int pid) {
        List<String> out = new ArrayList<>();
        byte[] b = readBytes(Path.of("/proc", String.valueOf(pid), "environ"));
        if (b == null) {
            return out;
        }
        for (String s : new String(b, StandardCharsets.UTF_8).split("\0")) {
            if (!s.isBlank()) {
                out.add(s);
            }
        }
        return out;
    }

    /** The distinct file paths mapped into a process (the last column of maps). */
    public static List<String> mappedFiles(int pid) {
        List<String> out = new ArrayList<>();
        for (String line : maps(pid)) {
            int idx = line.indexOf('/');
            if (idx > 0) {
                out.add(line.substring(idx));
            }
        }
        return out;
    }

    private static String readTrim(Path p) {
        String s = readString(p);
        return s == null ? null : s.trim();
    }

    static String readString(Path p) {
        try {
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readBytes(Path p) {
        try {
            return Files.readAllBytes(p);
        } catch (Exception e) {
            return null;
        }
    }
}

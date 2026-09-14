package ru.moon.checker.linux;

import ru.moon.checker.core.Platform;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Linux kernel / system state probes: elevation, loaded kernel modules, kernel
 * taint (out-of-tree / unsigned / force-loaded modules), and the global
 * {@code /etc/ld.so.preload} (a classic library-injection and rootkit hook).
 */
public final class LinuxInfo {

    private LinuxInfo() {
    }

    /** True when the effective UID is 0 (root) — required for full coverage. */
    public static boolean isRoot() {
        if (!Platform.isLinux()) {
            return false;
        }
        String status = Proc.readString(Path.of("/proc/self/status"));
        if (status != null) {
            for (String line : status.split("\n")) {
                if (line.startsWith("Uid:")) {
                    String[] parts = line.split("\\s+");
                    // Uid: real effective saved fs  -> effective is index 2
                    if (parts.length >= 3) {
                        return "0".equals(parts[2]);
                    }
                }
            }
        }
        return "root".equals(System.getProperty("user.name"));
    }

    public static String kernelRelease() {
        String s = Proc.readString(Path.of("/proc/sys/kernel/osrelease"));
        return s == null ? "unknown" : s.trim();
    }

    /** Loaded kernel module names from {@code /proc/modules}. */
    public static List<String> loadedModules() {
        List<String> out = new ArrayList<>();
        if (!Platform.isLinux()) {
            return out;
        }
        try {
            for (String line : Files.readAllLines(Path.of("/proc/modules"), StandardCharsets.UTF_8)) {
                int sp = line.indexOf(' ');
                if (sp > 0) {
                    out.add(line.substring(0, sp));
                }
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }

    /** Kernel taint bitmask ({@code /proc/sys/kernel/tainted}); 0 = clean. */
    public static long taint() {
        String s = Proc.readString(Path.of("/proc/sys/kernel/tainted"));
        if (s == null) {
            return 0;
        }
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** Human description of the set taint bits relevant to cheat/rootkit modules. */
    public static String taintDescription(long t) {
        List<String> bits = new ArrayList<>();
        if ((t & (1L << 0)) != 0) bits.add("proprietary module (G/P)");
        if ((t & (1L << 1)) != 0) bits.add("force-loaded module (F)");
        if ((t & (1L << 2)) != 0) bits.add("SMP with non-SMP kernel");
        if ((t & (1L << 3)) != 0) bits.add("force-unloaded module (R)");
        if ((t & (1L << 12)) != 0) bits.add("out-of-tree module (O)");
        if ((t & (1L << 13)) != 0) bits.add("unsigned module (E)");
        return bits.isEmpty() ? "flags=" + t : String.join(", ", bits);
    }

    /** Entries in {@code /etc/ld.so.preload} — should normally be empty. */
    public static List<String> ldSoPreload() {
        List<String> out = new ArrayList<>();
        Path p = Path.of("/etc/ld.so.preload");
        if (!Files.isRegularFile(p)) {
            return out;
        }
        try {
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    out.add(line.trim());
                }
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }
}

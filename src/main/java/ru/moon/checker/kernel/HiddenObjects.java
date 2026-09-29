package ru.moon.checker.kernel;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Rootkit detection by disagreement: compare what the kernel reports against
 * what user-mode can see. Anything the kernel knows about but user-mode cannot
 * enumerate has been deliberately hidden.
 *
 * <p>All logic here is pure so it can be unit-tested without a kernel driver.
 */
public final class HiddenObjects {

    private HiddenObjects() {
    }

    /** Parse {@code KPID <pid> <comm>} lines emitted by the Linux moonmon module. */
    public static Set<Integer> parseKernelPids(List<String> reportLines) {
        Set<Integer> out = new TreeSet<>();
        if (reportLines == null) {
            return out;
        }
        for (String line : reportLines) {
            if (line == null || !line.startsWith("KPID ")) {
                continue;
            }
            String[] parts = line.trim().split("\\s+");
            if (parts.length >= 2) {
                try {
                    out.add(Integer.parseInt(parts[1]));
                } catch (NumberFormatException ignored) {
                    // malformed line
                }
            }
        }
        return out;
    }

    /** Map {@code KPID <pid> <comm>} to pid -> comm, for naming a hidden process. */
    public static String commOf(List<String> reportLines, int pid) {
        if (reportLines == null) {
            return null;
        }
        String prefix = "KPID " + pid + " ";
        for (String line : reportLines) {
            if (line != null && line.startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    /**
     * PIDs the kernel lists that user-mode cannot see. Caller should re-verify
     * each candidate (a process can legitimately exit between the two reads).
     */
    public static List<Integer> hiddenPids(Set<Integer> kernelPids, Set<Integer> visiblePids) {
        List<Integer> out = new ArrayList<>();
        if (kernelPids == null) {
            return out;
        }
        for (Integer pid : kernelPids) {
            if (visiblePids == null || !visiblePids.contains(pid)) {
                out.add(pid);
            }
        }
        return out;
    }

    /**
     * PIDs the kernel lists that are really hidden from the {@code /proc} listing, after ruling out
     * the races between two snapshots taken at different moments:
     * <ul>
     *   <li>the process exited in between — {@code /proc/<pid>} no longer answers ({@code alive} false),
     *       which is also what a PID from another PID namespace looks like: not reported;</li>
     *   <li>the process started in between — it is in a second listing taken now: not reported;</li>
     *   <li>the PID was reused by a new process — its name now differs from the kernel's: not reported.</li>
     * </ul>
     * What remains answers to its own {@code /proc/<pid>} while the directory listing leaves it out:
     * the signature of a listing filter (an {@code LD_PRELOAD} or {@code ld.so.preload} rootkit hooking
     * readdir). An empty result is not proof of a clean kernel: a kernel-mode rootkit hides from both views.
     */
    public static List<Integer> confirmedHidden(Set<Integer> kernelPids, Set<Integer> firstListing,
                                                java.util.function.IntPredicate alive,
                                                java.util.function.Supplier<Set<Integer>> listAgain,
                                                java.util.function.IntFunction<String> nameNow,
                                                java.util.Map<Integer, String> kernelNames) {
        List<Integer> candidates = hiddenPids(kernelPids, firstListing);
        List<Integer> out = new ArrayList<>();
        if (candidates.isEmpty()) {
            return out;
        }
        Set<Integer> second = listAgain.get();
        for (Integer pid : candidates) {
            if (!alive.test(pid) || (second != null && second.contains(pid))) {
                continue;
            }
            String was = kernelNames.get(pid);
            String now = nameNow.apply(pid);
            if (was != null && now != null && !now.strip().equals(was)) {
                continue;   // a new process got the same number
            }
            out.add(pid);
        }
        return out;
    }

    /**
     * Kernel modules that appear in one enumeration but not the other.
     * A module loaded but unlinked from {@code /proc/modules} (while still
     * present in {@code /sys/module}) is a classic LKM rootkit trick.
     */
    public static List<String> moduleDisagreement(Collection<String> procModules,
                                                  Collection<String> sysModules) {
        Set<String> a = lower(procModules);
        Set<String> b = lower(sysModules);
        List<String> out = new ArrayList<>();
        for (String m : b) {
            if (!a.contains(m)) {
                out.add(m + " (in /sys/module, missing from /proc/modules)");
            }
        }
        for (String m : a) {
            if (!b.contains(m)) {
                out.add(m + " (in /proc/modules, missing from /sys/module)");
            }
        }
        return out;
    }

    private static Set<String> lower(Collection<String> in) {
        Set<String> out = new LinkedHashSet<>();
        if (in == null) {
            return out;
        }
        for (String s : in) {
            if (s != null && !s.isBlank()) {
                // /sys/module uses '_' where /proc/modules may use '-'
                out.add(s.trim().toLowerCase(Locale.ROOT).replace('-', '_'));
            }
        }
        return out;
    }

    /**
     * Boot options that weaken kernel integrity, parsed from the Windows
     * {@code SystemStartOptions} registry value (or a bcdedit dump).
     * Any of these present means unsigned kernel code can be loaded.
     */
    public static List<String> weakBootOptions(String systemStartOptions) {
        List<String> found = new ArrayList<>();
        if (systemStartOptions == null) {
            return found;
        }
        String s = systemStartOptions.toUpperCase(Locale.ROOT);
        record Opt(String token, String meaning) {
        }
        Opt[] opts = {
                new Opt("TESTSIGNING", "test-signing: unsigned drivers can load"),
                new Opt("NOINTEGRITYCHECKS", "driver signature enforcement disabled"),
                new Opt("DISABLE_INTEGRITY_CHECKS", "driver signature enforcement disabled"),
                new Opt("DEBUG", "kernel debugger enabled"),
                new Opt("WINPE", "booted into WinPE"),
                new Opt("SAFEBOOT", "booted in safe mode")
        };
        // whole switches only: "NODEBUG" is not "DEBUG"; "SAFEBOOT:MINIMAL" is SAFEBOOT
        java.util.Set<String> switches = new java.util.HashSet<>();
        for (String token : s.trim().split("\\s+")) {
            switches.add(token.replaceFirst("^[/-]+", "").split("[=:]", 2)[0]);
        }
        for (Opt o : opts) {
            if (switches.contains(o.token())) {
                found.add(o.token() + " — " + o.meaning());
            }
        }
        return found;
    }
}

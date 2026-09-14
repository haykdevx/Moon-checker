package ru.moon.checker.win;

import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.HANDLEByReference;
import com.sun.jna.ptr.IntByReference;
import ru.moon.checker.core.Platform;

import java.util.Locale;
import java.util.Optional;

/**
 * Miscellaneous machine-state probes: administrator elevation, virtual-machine
 * detection, and test-signing status. Each returns a conservative default off
 * Windows so the rest of the app is unaffected.
 */
public final class WinInfo {

    private static final int TOKEN_QUERY = 0x0008;

    private WinInfo() {
    }

    /** True if the current process is running elevated (as administrator). */
    public static boolean isElevated() {
        if (!Platform.isWindows()) {
            return false;
        }
        try {
            HANDLEByReference token = new HANDLEByReference();
            boolean opened = Advapi32.INSTANCE.OpenProcessToken(
                    Kernel32.INSTANCE.GetCurrentProcess(), TOKEN_QUERY, token);
            if (!opened) {
                return false;
            }
            try {
                WinNT.TOKEN_ELEVATION elevation = new WinNT.TOKEN_ELEVATION();
                IntByReference returnLength = new IntByReference();
                boolean ok = Advapi32.INSTANCE.GetTokenInformation(
                        token.getValue(),
                        WinNT.TOKEN_INFORMATION_CLASS.TokenElevation,
                        elevation, elevation.size(), returnLength);
                return ok && elevation.TokenIsElevated != 0;
            } finally {
                Kernel32.INSTANCE.CloseHandle(token.getValue());
            }
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Detect common hypervisors from BIOS / system identity strings and
     * guest-tool services. Returns the detected product name, or empty.
     */
    public static Optional<String> detectVirtualMachine() {
        if (!Platform.isWindows()) {
            return Optional.empty();
        }
        String bios = "\\HARDWARE\\DESCRIPTION\\System\\BIOS";
        String[] values = {"SystemManufacturer", "SystemProductName", "BIOSVendor", "BIOSVersion"};
        for (String v : values) {
            String s = Registry.getString(Registry.HKLM, "HARDWARE\\DESCRIPTION\\System\\BIOS", v);
            String hit = matchVm(s);
            if (hit != null) {
                return Optional.of(hit + " (" + v + "=" + s + ")");
            }
        }
        // guest-tool services
        String[][] svc = {
                {"VBoxService", "VirtualBox"}, {"VBoxGuest", "VirtualBox"},
                {"vmtools", "VMware"}, {"vmmemctl", "VMware"},
                {"vmicheartbeat", "Hyper-V"}, {"vmci", "Hyper-V"},
                {"qemu-ga", "QEMU"}
        };
        for (String[] pair : svc) {
            if (Registry.keyExists(Registry.HKLM, "SYSTEM\\CurrentControlSet\\Services\\" + pair[0])) {
                return Optional.of(pair[1] + " (service " + pair[0] + ")");
            }
        }
        return Optional.empty();
    }

    private static String matchVm(String s) {
        if (s == null) {
            return null;
        }
        String l = s.toLowerCase(Locale.ROOT);
        if (l.contains("vmware")) return "VMware";
        if (l.contains("virtualbox") || l.contains("innotek") || l.contains("vbox")) return "VirtualBox";
        if (l.contains("qemu")) return "QEMU";
        if (l.contains("kvm")) return "KVM";
        if (l.contains("xen")) return "Xen";
        if (l.contains("microsoft corporation") && l.contains("virtual")) return "Hyper-V";
        if (l.contains("parallels")) return "Parallels";
        return null;
    }

    /**
     * Whether Windows test-signing mode is enabled (allows unsigned kernel
     * drivers — a common precondition for kernel cheats). Uses bcdedit, which
     * needs the elevation we already hold. Empty if it cannot be determined.
     */
    public static Optional<Boolean> testSigningEnabled() {
        if (!Platform.isWindows()) {
            return Optional.empty();
        }
        try {
            Process p = new ProcessBuilder("cmd", "/c", "bcdedit", "/enum", "{current}")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            String l = out.toLowerCase(Locale.ROOT);
            if (l.contains("testsigning")) {
                return Optional.of(l.contains("testsigning") && l.contains("yes"));
            }
            return Optional.of(false);
        } catch (Throwable t) {
            return Optional.empty();
        }
    }
}

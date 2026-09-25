package ru.moon.checker.win;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.HANDLEByReference;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import ru.moon.checker.core.Platform;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Miscellaneous machine-state probes: administrator elevation, virtual-machine
 * detection, and driver-signing state. Each returns a conservative default off
 * Windows so the rest of the app is unaffected.
 */
public final class WinInfo {

    private static final int TOKEN_QUERY = 0x0008;
    private static final int SYSTEM_CODE_INTEGRITY_INFORMATION = 103;
    static final int CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
    static final int CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = 0x80;

    private static final Pattern XEN = Pattern.compile("\\bxen\\b");

    private WinInfo() {
    }

    private interface NtDll extends StdCallLibrary {
        NtDll INSTANCE = Native.load("ntdll", NtDll.class);

        int NtQuerySystemInformation(int infoClass, Pointer info, int length, IntByReference returnLength);
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
     * Detect a hypervisor from the SMBIOS identity strings, then from services
     * that only exist <em>inside</em> a guest (guest additions / tools). Host-side
     * components (Hyper-V integration services, VMware's vmci bus driver) are
     * deliberately not used: they are present on ordinary gaming PCs.
     */
    public static Optional<String> detectVirtualMachine() {
        if (!Platform.isWindows()) {
            return Optional.empty();
        }
        String bios = "HARDWARE\\DESCRIPTION\\System\\BIOS";
        String manufacturer = Registry.getString(Registry.HKLM, bios, "SystemManufacturer");
        String product = Registry.getString(Registry.HKLM, bios, "SystemProductName");
        String vendor = Registry.getString(Registry.HKLM, bios, "BIOSVendor");
        String version = Registry.getString(Registry.HKLM, bios, "BIOSVersion");
        String hit = matchVm(manufacturer, product, vendor, version);
        if (hit != null) {
            return Optional.of(hit + " (" + manufacturer + " / " + product + ")");
        }
        String[][] guestServices = {
                {"VBoxGuest", "VirtualBox"}, {"VBoxSF", "VirtualBox"},
                {"VMTools", "VMware"}, {"vm3dmp", "VMware"}, {"vmhgfs", "VMware"},
                {"QEMU-GA", "QEMU"}, {"prl_tg", "Parallels"}
        };
        for (String[] pair : guestServices) {
            if (Registry.keyExists(Registry.HKLM, "SYSTEM\\CurrentControlSet\\Services\\" + pair[0])) {
                return Optional.of(pair[1] + " (guest service " + pair[0] + ")");
            }
        }
        return Optional.empty();
    }

    /** Hypervisor product from SMBIOS strings, or null for physical hardware. */
    static String matchVm(String manufacturer, String product, String biosVendor, String biosVersion) {
        String m = lower(manufacturer);
        String p = lower(product);
        String all = m + " " + p + " " + lower(biosVendor) + " " + lower(biosVersion);
        if (all.contains("vmware")) return "VMware";
        if (all.contains("virtualbox") || all.contains("innotek") || all.contains("vbox")) return "VirtualBox";
        if (all.contains("qemu")) return "QEMU";
        if (all.contains("kvm")) return "KVM";
        if (all.contains("bochs")) return "Bochs";
        if (XEN.matcher(all).find()) return "Xen";
        if (all.contains("parallels")) return "Parallels";
        if (m.contains("microsoft corporation") && p.contains("virtual machine")) return "Hyper-V";
        if (all.contains("amazon ec2")) return "Amazon EC2";
        if (all.contains("google compute engine")) return "Google Compute Engine";
        return null;
    }

    /** Driver-signing relaxations active in the <em>current</em> boot. */
    public record SigningState(boolean testSigning, boolean integrityChecksOff, boolean kernelDebug, String source) {
        public boolean anyRelaxed() {
            return testSigning || integrityChecksOff || kernelDebug;
        }
    }

    /**
     * Whether the running kernel accepts test-signed / unsigned drivers (a
     * common precondition for kernel cheats). Asks the kernel directly
     * ({@code SystemCodeIntegrityInformation}); falls back to the loader options
     * the system booted with. Unlike parsing {@code bcdedit}, neither depends on
     * the UI language, needs elevation, or reflects a not-yet-rebooted change.
     */
    public static Optional<SigningState> signingState() {
        if (!Platform.isWindows()) {
            return Optional.empty();
        }
        String startOptions = Registry.getString(Registry.HKLM,
                "SYSTEM\\CurrentControlSet\\Control", "SystemStartOptions");
        SigningState fromBoot = startOptions == null ? null : parseStartOptions(startOptions);
        Integer ci = codeIntegrityOptions();
        if (ci != null) {
            boolean integrityOff = fromBoot != null && fromBoot.integrityChecksOff();
            return Optional.of(new SigningState((ci & CODEINTEGRITY_OPTION_TESTSIGN) != 0, integrityOff,
                    (ci & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0,
                    "CodeIntegrityOptions=0x" + Integer.toHexString(ci)));
        }
        return Optional.ofNullable(fromBoot);
    }

    /** Parse {@code SystemStartOptions}, e.g. {@code " NOEXECUTE=OPTIN  TESTSIGNING"}. */
    static SigningState parseStartOptions(String options) {
        boolean test = false;
        boolean integrity = false;
        boolean debug = false;
        for (String token : options.trim().toUpperCase(Locale.ROOT).split("[\\s/]+")) {
            switch (token) {
                case "TESTSIGNING" -> test = true;
                case "DISABLE_INTEGRITY_CHECKS", "NOINTEGRITYCHECKS" -> integrity = true;
                case "DEBUG" -> debug = true;
                default -> { }
            }
        }
        return new SigningState(test, integrity, debug, "SystemStartOptions=" + options.trim());
    }

    private static Integer codeIntegrityOptions() {
        try (Memory buf = new Memory(8)) {
            buf.setInt(0, 8); // SYSTEM_CODEINTEGRITY_INFORMATION.Length
            buf.setInt(4, 0);
            int status = NtDll.INSTANCE.NtQuerySystemInformation(
                    SYSTEM_CODE_INTEGRITY_INFORMATION, buf, 8, new IntByReference());
            return status == 0 ? buf.getInt(4) : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}

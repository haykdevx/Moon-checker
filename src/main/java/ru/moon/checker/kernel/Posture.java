package ru.moon.checker.kernel;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The platform's security settings, as context for the reviewer. None of them is
 * evidence of cheating: a PC with Secure Boot off is ordinary. They say how much a
 * kernel-level cheat would have to defeat, and one of them — the vulnerable-driver
 * blocklist switched off on purpose — lowers trust in the report.
 *
 * <p>Pure parsing here; the collector reads the registry / sysfs and passes values in.
 */
public final class Posture {

    /** On / off / not configured (Windows default) / cannot tell. */
    public enum State { ON, OFF, DEFAULT, UNKNOWN }

    /** Windows posture from registry DWORDs; -1 = value absent. */
    public record Windows(State secureBoot, State memoryIntegrity, State vbs, State driverBlocklist, boolean tpm20) {

        /** The blocklist was switched off by a setting (absent means Windows' default, on for 11 22H2+). */
        public boolean blocklistDisabled() {
            return driverBlocklist == State.OFF;
        }

        public String summary() {
            return "Secure Boot: " + word(secureBoot, "legacy BIOS")
                    + "; memory integrity (HVCI): " + word(memoryIntegrity, "not configured")
                    + "; VBS: " + word(vbs, "not configured")
                    + "; vulnerable-driver blocklist: " + word(driverBlocklist, "Windows default")
                    + "; TPM 2.0: " + (tpm20 ? "present" : "not found");
        }
    }

    /** Linux posture from sysfs / procfs text. */
    public record Linux(State secureBoot, String lockdown, State moduleSigEnforce, int ptraceScope) {
        public String summary() {
            return "Secure Boot: " + word(secureBoot, "legacy BIOS")
                    + "; kernel lockdown: " + (lockdown == null ? "unknown" : lockdown)
                    + "; module signatures enforced: " + word(moduleSigEnforce, "unknown")
                    + "; ptrace scope: " + (ptraceScope < 0 ? "unknown" : ptraceScope
                    + (ptraceScope == 0 ? " (any process of the user can read another's memory)" : ""));
        }
    }

    private Posture() {
    }

    /** A registry DWORD: 1 on, 0 off, absent (-1) = the default meaning. */
    public static State dword(int value, boolean absentMeansDefault) {
        if (value == 1) {
            return State.ON;
        }
        if (value == 0) {
            return State.OFF;
        }
        return absentMeansDefault ? State.DEFAULT : State.UNKNOWN;
    }

    /** VBS: 0 off, 1 on, 2 "on with DMA protection"; absent = not configured. */
    public static State vbs(int value) {
        return value < 0 ? State.DEFAULT : value == 0 ? State.OFF : State.ON;
    }

    /**
     * The {@code SecureBoot-8be4df61-…} efivar: 4 attribute bytes, then the value byte.
     * No efivar at all on an EFI system is unknown; no EFI at all is legacy BIOS (null).
     */
    public static State efiSecureBoot(byte[] efivar, boolean efiPresent) {
        if (!efiPresent) {
            return State.DEFAULT;
        }
        if (efivar == null || efivar.length < 5) {
            return State.UNKNOWN;
        }
        return efivar[4] == 1 ? State.ON : State.OFF;
    }

    /** {@code /sys/kernel/security/lockdown}: "[none] integrity confidentiality" → "none". */
    public static String lockdown(String text) {
        if (text == null) {
            return null;
        }
        int a = text.indexOf('['), b = text.indexOf(']');
        return a >= 0 && b > a ? text.substring(a + 1, b) : null;
    }

    /** {@code sig_enforce}: "Y" / "N". */
    public static State yesNo(String text) {
        if (text == null) {
            return State.UNKNOWN;
        }
        String t = text.trim().toUpperCase(Locale.ROOT);
        return t.equals("Y") || t.equals("1") ? State.ON : t.equals("N") || t.equals("0") ? State.OFF : State.UNKNOWN;
    }

    public static int ptraceScope(String text) {
        try {
            return text == null ? -1 : Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static String word(State s, String defaultWord) {
        return switch (s) {
            case ON -> "on";
            case OFF -> "off";
            case DEFAULT -> defaultWord;
            case UNKNOWN -> "unknown";
        };
    }

    /** Registry locations, kept together so the collector and the docs agree. */
    public static List<String> windowsSources() {
        List<String> l = new ArrayList<>();
        l.add("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\UEFISecureBootEnabled");
        l.add("HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled");
        l.add("HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity");
        l.add("HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\\VulnerableDriverBlocklistEnable");
        l.add("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\ACPI\\MSFT0101 (TPM 2.0 device)");
        return l;
    }
}

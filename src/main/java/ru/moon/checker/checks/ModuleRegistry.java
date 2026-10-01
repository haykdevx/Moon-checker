package ru.moon.checker.checks;

import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Platform;

import java.util.ArrayList;
import java.util.List;

/** Selects the set of check modules appropriate for the host OS. */
public final class ModuleRegistry {

    private ModuleRegistry() {
    }

    /** The full Windows inspection suite. */
    public static List<CheckModule> windowsModules() {
        return List.of(
                new Cs2IntegrityCheck(),
                new LiveGameCheck(),
                new FileScanCheck(),
                new DeletedEvidenceCheck(),
                new ExecutionTraceCheck(),
                new AmCacheCheck(),
                new PersistenceCheck(),
                new KernelCheck(),
                new EnvironmentCheck(),
                new BrowserHistoryCheck(),
                new SteamAccountsCheck(),
                new MacroUsbCheck(),
                new DefenderCheck(),
                new DnsCacheCheck(),
                new AntiForensicCheck()
        );
    }

    /** The Linux inspection suite. */
    public static List<CheckModule> linuxModules() {
        return List.of(
                new Cs2IntegrityCheck(),
                new LinuxProcessCheck(),
                new LinuxFileScanCheck(),
                new KernelCheck(),
                new LinuxHistoryCheck(),
                new LinuxPersistenceCheck(),
                new SteamAccountsCheck()
        );
    }

    /** Modules to actually run on this machine. */
    public static List<CheckModule> forCurrentOs() {
        if (Platform.isLinux()) {
            return linuxModules();
        }
        return windowsModules();
    }

    /** Back-compat: the Windows suite (used by tooling/screenshots). */
    public static List<CheckModule> all() {
        return windowsModules();
    }

    /** Every module across all platforms — for i18n key coverage tests. */
    public static List<CheckModule> everyModule() {
        List<CheckModule> out = new ArrayList<>(windowsModules());
        for (CheckModule m : linuxModules()) {
            if (out.stream().noneMatch(x -> x.id().equals(m.id()))) {
                out.add(m);
            }
        }
        return out;
    }
}

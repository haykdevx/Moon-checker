package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.win.Registry;
import ru.moon.checker.win.WinInfo;
import ru.moon.checker.win.WinProcess;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Inspects the live machine state: running processes, kernel drivers
 * (bring-your-own-vulnerable-driver / manual mappers), DMA cheat hardware
 * (FPGA PCIe cards) and virtual machines. Test signing is the kernel collector's.
 */
public final class EnvironmentCheck implements CheckModule {

    public static final String ID = "environment";

    /** Vendor/hardware-id fragments associated with DMA cheat hardware. */
    private static final String[] DMA_HWIDS = {
            "ven_10ee",   // Xilinx FPGA (Screamer, CaptainDMA, PCILeech-family)
            "screamer", "pcileech", "captaindma", "leetdma", "enigma_x1", "ft601"
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.environment");
    }

    @Override
    public Category category() {
        return Category.ENVIRONMENT;
    }

    @Override
    public void run(ScanContext ctx) {
        processes(ctx);
        windowTitles(ctx);
        drivers(ctx);
        dmaHardware(ctx);
        systemState(ctx);
        pcInfo(ctx);
    }

    /** A restart shortly before the check: whatever lived only in memory is gone. Context, not evidence. */
    static String recentRestartNote(long uptimeMinutes) {
        return uptimeMinutes < 15 ? "PC restarted " + uptimeMinutes + " min before the check: anything that lived only "
                + "in memory (a running cheat, an open handle) is gone; files and traces on disk are not affected" : null;
    }

    private void pcInfo(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        String cpu = ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKLM,
                "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
        String bios = "HARDWARE\\DESCRIPTION\\System\\BIOS";
        String board = join(ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKLM, bios, "BaseBoardManufacturer"),
                ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKLM, bios, "BaseBoardProduct"));
        String system = join(ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKLM, bios, "SystemManufacturer"),
                ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKLM, bios, "SystemProductName"));
        java.util.List<String> gpus = new java.util.ArrayList<>();
        String display = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
        for (String sub : ru.moon.checker.win.Registry.subKeys(ru.moon.checker.win.Registry.HKLM, display)) {
            String desc = ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKLM, display + "\\" + sub, "DriverDesc");
            if (desc != null && !gpus.contains(desc)) {
                gpus.add(desc);
            }
        }
        long ramMb = -1;
        long uptimeMin = -1;
        int monitors = -1;
        try {
            var mem = new com.sun.jna.platform.win32.WinBase.MEMORYSTATUSEX();
            if (com.sun.jna.platform.win32.Kernel32.INSTANCE.GlobalMemoryStatusEx(mem)) {
                ramMb = mem.ullTotalPhys.longValue() / (1024 * 1024);
            }
            uptimeMin = com.sun.jna.platform.win32.Kernel32.INSTANCE.GetTickCount64() / 60_000;
            monitors = com.sun.jna.platform.win32.User32.INSTANCE.GetSystemMetrics(80);   // SM_CMONITORS
        } catch (Throwable ignored) {
            // the summary is context; a missing value is shown as unknown
        }
        ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.INFO, "Данные о ПК / PC information")
                .module(ID).kind(EvidenceKind.CONTEXT).rule("environment:pc-info")
                .detail("CPU: " + orUnknown(cpu) + "; GPU: " + (gpus.isEmpty() ? "unknown" : String.join(", ", gpus))
                        + "; RAM: " + (ramMb > 0 ? (ramMb + 512) / 1024 + " GB" : "unknown")
                        + "; board: " + orUnknown(board) + "; system: " + orUnknown(system)
                        + "; monitors: " + (monitors >= 0 ? monitors : "unknown")
                        + "; uptime: " + (uptimeMin >= 0 ? uptimeMin / 60 + " h " + uptimeMin % 60 + " min" : "unknown"))
                .source("registry, kernel32").build());
        String note = uptimeMin >= 0 ? recentRestartNote(uptimeMin) : null;
        if (note != null) {
            ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.INFO,
                            "ПК перезагружен перед проверкой / PC restarted shortly before the check")
                    .module(ID).kind(EvidenceKind.CONTEXT).rule("environment:recent-restart")
                    .detail(note).source("GetTickCount64").build());
        }
    }

    private static String join(String a, String b) {
        String s = ((a == null ? "" : a.strip()) + " " + (b == null ? "" : b.strip())).strip();
        return s.isEmpty() ? null : s;
    }

    private static String orUnknown(String s) {
        return s == null || s.isBlank() ? "unknown" : s.strip();
    }

    private void windowTitles(ScanContext ctx) {
        java.util.Set<String> reported = new java.util.HashSet<>();
        for (String title : ru.moon.checker.win.WinWindows.visibleTitles()) {
            ctx.signatures().matchCheatName(title).ifPresent(rule -> {
                if (reported.add(rule.label())) {
                    ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.CRITICAL,
                                    "Окно чита на экране / Cheat window/overlay open")
                            .module(ID)
                            .detail(rule.label() + "  — заголовок окна: " + title)
                            .evidence(title)
                            .source("window title")
                            .build());
                }
            });
        }
    }

    private void processes(ScanContext ctx) {
        ctx.log(I18n.t("log.processes"));
        for (WinProcess.Proc p : WinProcess.list()) {
            if (ctx.isCancelled()) {
                return;
            }
            // Escalate only rules that were already strong: a MEDIUM keyword
            // must not turn into a CHEAT verdict just because a process
            // happens to carry it in its name.
            ctx.signatures().matchCheatName(p.name()).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.ENVIRONMENT,
                                    rule.severity() == Severity.HIGH || rule.severity() == Severity.CRITICAL
                                            ? Severity.CRITICAL : rule.severity(),
                                    "Процесс чита запущен / Cheat process is running")
                            .module(ID)
                            .detail(rule.label() + "  (pid " + p.pid() + ")")
                            .evidence(p.path() != null ? p.path() : p.name())
                            .source("running process")
                            .openPath(parentOf(p.path()))
                            .build()));
            // deep-inspect processes running from user-writable locations
            if (p.path() != null) {
                String lower = p.path().toLowerCase(Locale.ROOT);
                if (FileInspection.isSuspiciousLocation(lower)) {
                    try {
                        FileInspection.inspect(Path.of(p.path()), ctx, ID, Category.ENVIRONMENT);
                    } catch (Exception ignored) {
                    }
                }
            }
        }
    }

    private void drivers(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        Path driversDir = Platform.windowsDir().resolve("System32").resolve("drivers");
        if (!Files.isDirectory(driversDir)) {
            return;
        }
        ctx.log(I18n.t("log.drivers"));
        FileInspection.walk(driversDir, 5000, 1, f -> {
            String name = f.getFileName().toString();
            ctx.signatures().matchDriver(name).ifPresent(rule ->
                    ctx.emit(DriverPlacement.finding(rule, f.toString(), ID, "drivers directory")));
        }, ctx);
    }

    private void dmaHardware(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        String base = "SYSTEM\\CurrentControlSet\\Enum\\PCI";
        for (String device : Registry.subKeys(Registry.HKLM, base)) {
            String deviceLower = device.toLowerCase(Locale.ROOT);
            String matched = matchDma(deviceLower);
            String desc = null;
            String instPath = base + "\\" + device;
            for (String inst : Registry.subKeys(Registry.HKLM, instPath)) {
                String d = Registry.getString(Registry.HKLM, instPath + "\\" + inst, "DeviceDesc");
                String fn = Registry.getString(Registry.HKLM, instPath + "\\" + inst, "FriendlyName");
                String combined = ((d == null ? "" : d) + " " + (fn == null ? "" : fn)).toLowerCase(Locale.ROOT);
                if (matched == null) {
                    matched = matchDma(combined);
                }
                if (matched != null) {
                    desc = d != null ? d : fn;
                    break;
                }
            }
            if (matched != null) {
                ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.MEDIUM,
                                "Возможное DMA-железо (FPGA PCIe) / Possible DMA cheat hardware")
                        .module(ID)
                        .detail("PCI device matched '" + matched + "'"
                                + (desc != null ? " — " + desc : "") + " — проверьте вручную")
                        .evidence(device)
                        .source("PCI enumeration")
                        .build());
            }
        }
    }

    private void systemState(ScanContext ctx) {
        // test signing is reported once, by the kernel collector (boot options)
        WinInfo.detectVirtualMachine().ifPresent(vm ->
                ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.MEDIUM,
                                "Проверка запущена в виртуальной машине / Running inside a virtual machine")
                        .module(ID)
                        .kind(EvidenceKind.CONFIGURATION).rule("environment:virtual-machine")
                        .detail(vm + " — игрок может проходить проверку не на игровом ПК")
                        .source("VM detection")
                        .build()));
    }

    private String matchDma(String s) {
        if (s == null) {
            return null;
        }
        for (String id : DMA_HWIDS) {
            if (s.contains(id)) {
                return id;
            }
        }
        return null;
    }

    private static String parentOf(String path) {
        if (path == null) {
            return null;
        }
        int i = path.lastIndexOf('\\');
        return i > 0 ? path.substring(0, i) : path;
    }
}

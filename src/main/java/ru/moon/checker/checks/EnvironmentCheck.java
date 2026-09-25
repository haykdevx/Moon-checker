package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
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
 * (FPGA PCIe cards) and virtual machines.
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
            ctx.signatures().matchCheatName(p.name()).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.CRITICAL,
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
                    ctx.emit(Finding.builder(Category.ENVIRONMENT, rule.severity(),
                                    "Уязвимый/маппер драйвер / Vulnerable or mapper driver")
                            .module(ID)
                            .detail(rule.label())
                            .evidence(f.toString())
                            .source("drivers directory")
                            .openPath(driversDir.toString())
                            .build()));
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
                        .weight(20)
                        .build());
            }
        }
    }

    private void systemState(ScanContext ctx) {
        // driver-signing state is reported once, by KernelCheck
        WinInfo.detectVirtualMachine().ifPresent(vm ->
                ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.MEDIUM,
                                "Проверка запущена в виртуальной машине / Running inside a virtual machine")
                        .module(ID)
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

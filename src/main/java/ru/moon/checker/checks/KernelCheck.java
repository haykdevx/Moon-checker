package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.kernel.KernelBridge;
import ru.moon.checker.linux.LinuxInfo;
import ru.moon.checker.win.Registry;
import ru.moon.checker.win.WinInfo;

import java.util.List;
import java.util.Locale;

/**
 * Kernel-level inspection, cross-platform.
 *
 * <p>If the Moon kernel driver is loaded ({@link KernelBridge}) it consumes the
 * driver's report — kernel-enumerated drivers/modules and any objects hidden
 * from user-mode by a rootkit. Otherwise it falls back to the best user-mode
 * view of kernel state:
 * <ul>
 *   <li>Windows: loaded kernel-mode services (drivers), test-signing state,
 *       and matches against the vulnerable-driver / cheat signatures.</li>
 *   <li>Linux: {@code /proc/modules}, kernel taint (out-of-tree / unsigned /
 *       force-loaded), and {@code /etc/ld.so.preload} injection.</li>
 * </ul>
 */
public final class KernelCheck implements CheckModule {

    public static final String ID = "kernel";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.kernel");
    }

    @Override
    public Category category() {
        return Category.KERNEL;
    }

    @Override
    public boolean windowsOnly() {
        return false; // runs on Windows and Linux
    }

    @Override
    public void run(ScanContext ctx) {
        ctx.log(I18n.t("log.kernel"));
        KernelBridge.Report report = KernelBridge.read();
        ru.moon.checker.kernel.KernelReport parsed = null;
        if (report.present()) {
            parsed = ru.moon.checker.kernel.KernelReport.parse(report.lines());
            consumeDriverReport(ctx, parsed.records(), report.source());
            hiddenProcesses(ctx, parsed, report.source());
        } else {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.INFO,
                            "Kernel-драйвер Moon не загружен / Moon kernel driver not loaded")
                    .module(ID)
                    .detail("Работает режим пользователя (user-mode fallback). Загрузите драйвер для скрытых объектов.")
                    .source("kernel bridge")
                    .build());
        }
        if (Platform.isWindows()) {
            windowsFallback(ctx);
        } else if (Platform.isLinux()) {
            linuxFallback(ctx);
        }
        if (parsed != null && !parsed.complete()) {
            // the component is installed but its view is partial: that is missing telemetry,
            // not a clean result — surface it as a collection error (incomplete scan)
            throw new IllegalStateException("kernel component report incomplete: " + parsed.problem());
        }
    }

    /** Paths a Windows kernel module normally loads from; anything else is noted, not judged. */
    static boolean systemDriverPath(String path) {
        String p = path.toLowerCase(Locale.ROOT);
        return p.startsWith("\\systemroot\\") || p.startsWith("\\??\\c:\\windows\\")
                || p.startsWith("c:\\windows\\") || p.startsWith("\\windows\\");
    }

    private void consumeDriverReport(ScanContext ctx, java.util.List<String> records, String source) {
        for (String l : records) {
            if (!l.startsWith("DRIVER ")) {
                continue;
            }
            String path = l.substring(7);
            String low = path.toLowerCase(Locale.ROOT);
            if (!systemDriverPath(path)) {
                // anti-cheats of other games (EasyAntiCheat, FACEIT) and vendor tools load from
                // Program Files: visible to the reviewer, never a reason to review on its own
                ctx.emit(Finding.builder(Category.KERNEL, Severity.LOW,
                                "Драйвер загружен не из папки Windows / Driver loaded from outside the Windows folder")
                        .module(ID).rule("kernel:driver-outside-windows")
                        .detail("Kernel module image outside \\Windows (common for legitimate third-party drivers)")
                        .evidence(path).source(source).build());
            }
            ctx.signatures().matchDriver(low).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.KERNEL, rule.severity(),
                                    "Драйвер ядра совпал с сигнатурой / Kernel driver matches signature")
                            .module(ID).detail(rule.label() + " — " + path).evidence(path).source(source).build()));
            ctx.signatures().matchCheatName(low).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                                    "Чит в отчёте ядра / Cheat object in kernel report")
                            .module(ID).detail(rule.label() + " — " + path).evidence(path).source(source).build()));
        }
    }

    /**
     * Processes the kernel driver lists that {@code /proc} does not show. Each
     * candidate is re-verified, because a process legitimately exiting between
     * the two reads would otherwise look hidden.
     */
    private void hiddenProcesses(ScanContext ctx, ru.moon.checker.kernel.KernelReport parsed, String source) {
        java.util.Set<Integer> kernelPids =
                ru.moon.checker.kernel.HiddenObjects.parseKernelPids(parsed.records());
        if (kernelPids.isEmpty()) {
            return;
        }
        java.util.Set<Integer> visible =
                new java.util.HashSet<>(ru.moon.checker.linux.Proc.pids());
        for (Integer pid : ru.moon.checker.kernel.HiddenObjects.hiddenPids(kernelPids, visible)) {
            // re-verify: still absent from /proc?
            if (java.nio.file.Files.exists(java.nio.file.Path.of("/proc", String.valueOf(pid)))) {
                continue;
            }
            String comm = ru.moon.checker.kernel.HiddenObjects.commOf(parsed.records(), pid);
            ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                            "Скрытый процесс (руткит) / Process hidden from user-mode")
                    .module(ID).kind(EvidenceKind.CONCEALMENT).rule("kernel:hidden-process")
                    .detail("PID " + pid + (comm != null ? " (" + comm + ")" : "")
                            + " виден ядру, но отсутствует в /proc")
                    .evidence("pid " + pid)
                    .source(source)
                    .build());
        }
    }

    private void windowsFallback(ScanContext ctx) {
        String base = "SYSTEM\\CurrentControlSet\\Services";
        for (String name : Registry.subKeys(Registry.HKLM, base)) {
            if (ctx.isCancelled()) {
                return;
            }
            int type = Registry.getIntOr(Registry.HKLM, base + "\\" + name, "Type", -1);
            if (type != 1 && type != 2) {
                continue; // 1 = kernel driver, 2 = file-system driver
            }
            String image = Registry.getString(Registry.HKLM, base + "\\" + name, "ImagePath");
            String probe = (name + " " + (image == null ? "" : image)).toLowerCase(Locale.ROOT);
            ctx.signatures().matchDriver(probe).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.KERNEL, rule.severity(),
                                    "Загружен уязвимый/маппер драйвер / Vulnerable or mapper driver loaded")
                            .module(ID).detail(rule.label() + " — " + name)
                            .evidence(image != null ? image : name).source("kernel service").build()));
            ctx.signatures().matchCheatName(probe).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                                    "Драйвер чита в ядре / Cheat kernel driver")
                            .module(ID).detail(rule.label() + " — " + name)
                            .evidence(image != null ? image : name).source("kernel service").build()));
        }
        // Boot options that weaken kernel integrity (test-signing, DSE off,
        // kernel debugger) — all preconditions for loading a cheat driver.
        String startOptions = Registry.getString(Registry.HKLM,
                "SYSTEM\\CurrentControlSet\\Control", "SystemStartOptions");
        for (String weak : ru.moon.checker.kernel.HiddenObjects.weakBootOptions(startOptions)) {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.HIGH,
                            "Ослаблена защита ядра при загрузке / Kernel integrity weakened at boot")
                    .kind(EvidenceKind.CONFIGURATION).rule("kernel:boot-integrity-weakened")
                    .module(ID)
                    .detail(weak)
                    .evidence(startOptions)
                    .source("SystemStartOptions")
                    .build());
        }

        WinInfo.testSigningEnabled().ifPresent(on -> {
            if (on) {
                ctx.emit(Finding.builder(Category.KERNEL, Severity.HIGH,
                                "Отключена проверка подписи драйверов / Driver signature enforcement off (test-signing)")
                        .kind(EvidenceKind.CONFIGURATION).rule("kernel:dse-off")
                        .module(ID)
                        .detail("Позволяет загрузить неподписанный драйвер чита в ядро.")
                        .source("bcdedit").build());
            }
        });
    }

    private void linuxFallback(ScanContext ctx) {
        long taint = LinuxInfo.taint();
        boolean suspiciousTaint = (taint & ((1L << 12) | (1L << 13) | (1L << 1))) != 0; // O/E/F
        if (suspiciousTaint) {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.MEDIUM,
                            "Ядро помечено (out-of-tree/unsigned) / Kernel tainted")
                    .kind(EvidenceKind.CONTEXT).rule("kernel:tainted") // NVIDIA's driver taints most gaming kernels
                    .module(ID)
                    .detail(LinuxInfo.taintDescription(taint))
                    .source("/proc/sys/kernel/tainted").build());
        }
        for (String mod : LinuxInfo.loadedModules()) {
            ctx.signatures().matchCheatName(mod).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                                    "Модуль ядра чита загружен / Cheat kernel module loaded")
                            .module(ID).detail(rule.label() + " — " + mod)
                            .evidence(mod).source("/proc/modules").build()));
            ctx.signatures().matchDriver(mod).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.KERNEL, rule.severity(),
                                    "Подозрительный модуль ядра / Suspicious kernel module")
                            .module(ID).detail(rule.label() + " — " + mod)
                            .evidence(mod).source("/proc/modules").build()));
        }
        // A module unlinked from /proc/modules but still present in /sys/module
        // (or vice versa) is a classic LKM rootkit hiding trick.
        for (String mismatch : ru.moon.checker.kernel.HiddenObjects.moduleDisagreement(
                LinuxInfo.loadedModules(), LinuxInfo.sysModules())) {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.HIGH,
                            "Скрытый модуль ядра / Kernel module hidden from one view")
                    .kind(EvidenceKind.CONCEALMENT).rule("kernel:module-hidden")
                    .module(ID)
                    .detail(mismatch)
                    .evidence(mismatch)
                    .source("/proc/modules vs /sys/module")
                    .build());
        }

        List<String> preload = LinuxInfo.ldSoPreload();
        for (String entry : preload) {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.HIGH,
                            "Глобальная инъекция библиотеки / Global library injection (ld.so.preload)")
                    .module(ID)
                    .detail("Каждый процесс загружает: " + entry)
                    .evidence("/etc/ld.so.preload → " + entry)
                    .source("ld.so.preload").build());
        }
    }
}

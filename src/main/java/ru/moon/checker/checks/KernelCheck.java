package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
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
        if (report.present()) {
            consumeDriverReport(ctx, report);
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
    }

    private void consumeDriverReport(ScanContext ctx, KernelBridge.Report report) {
        for (String line : report.lines()) {
            String l = line.trim();
            if (l.isEmpty()) {
                continue;
            }
            // driver contract: "HIDDEN <type> <name>" or "DRIVER <name> <path>"
            if (l.startsWith("HIDDEN ")) {
                ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                                "Скрытый объект ядра (руткит) / Kernel object hidden from user-mode")
                        .module(ID).detail(l.substring(7)).source(report.source()).build());
            } else {
                String low = l.toLowerCase(Locale.ROOT);
                ctx.signatures().matchDriver(low).ifPresent(rule ->
                        ctx.emit(Finding.builder(Category.KERNEL, rule.severity(),
                                        "Драйвер ядра совпал с сигнатурой / Kernel driver matches signature")
                                .module(ID).detail(rule.label() + " — " + l).source(report.source()).build()));
                ctx.signatures().matchCheatName(low).ifPresent(rule ->
                        ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                                        "Чит в отчёте ядра / Cheat object in kernel report")
                                .module(ID).detail(rule.label() + " — " + l).source(report.source()).build()));
            }
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
        WinInfo.testSigningEnabled().ifPresent(on -> {
            if (on) {
                ctx.emit(Finding.builder(Category.KERNEL, Severity.HIGH,
                                "Отключена проверка подписи драйверов / Driver signature enforcement off (test-signing)")
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

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
        switch (report.state()) {
            case COLLECTED -> {
                parsed = ru.moon.checker.kernel.KernelReport.parse(report.lines());
                consumeDriverReport(ctx, parsed.records(), report.source());
                int hidden = hiddenProcesses(ctx, parsed, report.source());
                if (parsed.complete()) {
                    ctx.emit(Finding.builder(Category.KERNEL, Severity.INFO,
                                    "Сверка с ядром выполнена / Kernel cross-view compared")
                            .module(ID).kind(EvidenceKind.CONTEXT).rule("kernel:cross-view")
                            .detail(parsed.records().size() + " kernel records compared with the user-mode view; "
                                    + hidden + " discrepancy(ies) left after re-checking races. An empty result is "
                                    + "not proof of a clean kernel: a kernel-mode rootkit, a manually mapped driver, "
                                    + "a hypervisor or DMA device is invisible to both views.")
                            .source(report.source()).build());
                }
            }
            case ABSENT -> ctx.emit(Finding.builder(Category.KERNEL, Severity.INFO,
                            "Kernel-драйвер Moon не загружен / Moon kernel driver not loaded")
                    .module(ID)
                    .detail("Работает режим пользователя (user-mode fallback). Загрузите драйвер для скрытых объектов.")
                    .source("kernel bridge")
                    .build());
            case INACCESSIBLE -> ctx.emit(Finding.builder(Category.KERNEL, Severity.INFO,
                            "Kernel-компонент есть, но недоступен / Kernel component present but not accessible")
                    .module(ID).kind(EvidenceKind.CONTEXT).rule("kernel:component-inaccessible")
                    .detail(report.source() + ": " + report.detail() + " — run the checker as administrator/root.")
                    .source("kernel bridge").build());
            case FAILED -> ctx.partial("kernel component " + report.source() + " is installed but its report could not "
                    + "be read (" + report.detail() + "); the user-mode checks ran without it");
        }
        if (Platform.isWindows()) {
            windowsFallback(ctx);
            windowsPosture(ctx);
        } else if (Platform.isLinux()) {
            linuxFallback(ctx);
            linuxPosture(ctx);
        }
        if (parsed != null && !parsed.complete()) {
            // installed, but its view is incompatible or cut short: missing telemetry, not a clean result
            ctx.partial("kernel component report incomplete: " + parsed.problem());
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
                    ctx.emit(DriverPlacement.finding(rule, path, ID, source)));
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
    private int hiddenProcesses(ScanContext ctx, ru.moon.checker.kernel.KernelReport parsed, String source) {
        java.util.Set<Integer> kernelPids =
                ru.moon.checker.kernel.HiddenObjects.parseKernelPids(parsed.records());
        if (kernelPids.isEmpty()) {
            return 0;
        }
        java.util.Map<Integer, String> kernelNames = new java.util.HashMap<>();
        for (Integer pid : kernelPids) {
            kernelNames.put(pid, ru.moon.checker.kernel.HiddenObjects.commOf(parsed.records(), pid));
        }
        java.util.List<Integer> hidden = ru.moon.checker.kernel.HiddenObjects.confirmedHidden(kernelPids,
                new java.util.HashSet<>(ru.moon.checker.linux.Proc.pids()),
                pid -> java.nio.file.Files.exists(java.nio.file.Path.of("/proc", String.valueOf(pid))),
                () -> new java.util.HashSet<>(ru.moon.checker.linux.Proc.pids()),
                KernelCheck::commNow, kernelNames);
        for (Integer pid : hidden) {
            String comm = kernelNames.get(pid);
            ctx.emit(Finding.builder(Category.KERNEL, Severity.CRITICAL,
                            "Скрытый процесс (руткит) / Process hidden from user-mode")
                    .module(ID).kind(EvidenceKind.CONCEALMENT).rule("kernel:hidden-process")
                    .detail("PID " + pid + (comm != null ? " (" + comm + ")" : "")
                            + " виден ядру и отвечает по /proc/" + pid + ", но пропущен в списке /proc "
                            + "(перепроверено дважды) — фильтр списка процессов")
                    .evidence("pid " + pid)
                    .source(source)
                    .build());
        }
        return hidden.size();
    }

    /** /proc/<pid>/comm with the kernel module's sanitising, so the two names compare like for like. */
    static String commNow(int pid) {
        try {
            String raw = java.nio.file.Files.readString(java.nio.file.Path.of("/proc", String.valueOf(pid), "comm")).strip();
            StringBuilder sb = new StringBuilder();
            for (char c : raw.toCharArray()) {
                sb.append(c >= 0x21 && c <= 0x7e ? c : '?');
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
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
                    ctx.emit(DriverPlacement.finding(rule, image != null ? image : name, ID,
                            "kernel service " + name)));
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

        // the boot options above already say it; bcdedit only when the registry value is missing
        if (startOptions == null && WinInfo.testSigningEnabled().orElse(false)) {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.HIGH,
                            "Отключена проверка подписи драйверов / Driver signature enforcement off (test-signing)")
                    .kind(EvidenceKind.CONFIGURATION).rule("kernel:dse-off")
                    .module(ID)
                    .detail("Позволяет загрузить неподписанный драйвер чита в ядро.")
                    .source("bcdedit").build());
        }
    }

    /** Platform security settings: one line of context, plus a finding only for deliberate weakening. */
    private void windowsPosture(ScanContext ctx) {
        String base = "SYSTEM\\CurrentControlSet\\Control\\";
        ru.moon.checker.kernel.Posture.Windows w = new ru.moon.checker.kernel.Posture.Windows(
                ru.moon.checker.kernel.Posture.dword(
                        Registry.getIntOr(Registry.HKLM, base + "SecureBoot\\State", "UEFISecureBootEnabled", -1), true),
                ru.moon.checker.kernel.Posture.dword(Registry.getIntOr(Registry.HKLM,
                        base + "DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", "Enabled", -1), true),
                ru.moon.checker.kernel.Posture.vbs(Registry.getIntOr(Registry.HKLM,
                        base + "DeviceGuard", "EnableVirtualizationBasedSecurity", -1)),
                ru.moon.checker.kernel.Posture.dword(Registry.getIntOr(Registry.HKLM,
                        base + "CI\\Config", "VulnerableDriverBlocklistEnable", -1), true),
                Registry.keyExists(Registry.HKLM, "SYSTEM\\CurrentControlSet\\Enum\\ACPI\\MSFT0101"));
        emitPosture(ctx, w.summary(), "registry");
        if (w.blocklistDisabled()) {
            ctx.emit(Finding.builder(Category.KERNEL, Severity.LOW,
                            "Блок-лист уязвимых драйверов отключён / Vulnerable-driver blocklist turned off")
                    .kind(EvidenceKind.CONFIGURATION).rule("kernel:driver-blocklist-off")
                    .module(ID)
                    .detail("VulnerableDriverBlocklistEnable=0: Windows no longer refuses drivers Microsoft "
                            + "lists as abusable — a step some kernel cheats need")
                    .source("registry CI\\Config").build());
        }
    }

    private void linuxPosture(ScanContext ctx) {
        java.nio.file.Path efi = java.nio.file.Path.of("/sys/firmware/efi");
        byte[] sb = readBytes(java.nio.file.Path.of(
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"));
        ru.moon.checker.kernel.Posture.Linux l = new ru.moon.checker.kernel.Posture.Linux(
                ru.moon.checker.kernel.Posture.efiSecureBoot(sb, java.nio.file.Files.isDirectory(efi)),
                ru.moon.checker.kernel.Posture.lockdown(readText("/sys/kernel/security/lockdown")),
                ru.moon.checker.kernel.Posture.yesNo(readText("/sys/module/module/parameters/sig_enforce")),
                ru.moon.checker.kernel.Posture.ptraceScope(readText("/proc/sys/kernel/yama/ptrace_scope")));
        emitPosture(ctx, l.summary(), "sysfs / procfs");
    }

    private void emitPosture(ScanContext ctx, String summary, String source) {
        ctx.emit(Finding.builder(Category.KERNEL, Severity.INFO,
                        "Настройки безопасности платформы / Platform security settings")
                .kind(EvidenceKind.CONTEXT).rule("kernel:platform-posture")
                .module(ID).detail(summary).source(source).build());
    }

    private static byte[] readBytes(java.nio.file.Path p) {
        try {
            return java.nio.file.Files.readAllBytes(p);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readText(String path) {
        byte[] b = readBytes(java.nio.file.Path.of(path));
        return b == null ? null : new String(b, java.nio.charset.StandardCharsets.UTF_8).trim();
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

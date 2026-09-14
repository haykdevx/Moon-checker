package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.win.Registry;
import ru.moon.checker.win.WinProcess;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Detects mouse-macro / auto-clicker software (Bloody, X7, Logitech, Razer,
 * AutoHotkey, etc.) via installed-programs, running processes and script files,
 * and lists USB storage devices that have been connected (USBSTOR history), the
 * way USBDeview did — useful when a cheat was run from a USB stick.
 */
public final class MacroUsbCheck implements CheckModule {

    public static final String ID = "peripherals";

    private static final String[] UNINSTALL_KEYS = {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.peripherals");
    }

    @Override
    public Category category() {
        return Category.PERIPHERALS;
    }

    @Override
    public void run(ScanContext ctx) {
        macroSoftware(ctx);
        ahkScripts(ctx);
        usbHistory(ctx);
    }

    private void macroSoftware(ScanContext ctx) {
        ctx.log(I18n.t("log.macro"));
        Set<String> reported = new LinkedHashSet<>();

        // installed programs
        for (String key : UNINSTALL_KEYS) {
            for (var root : new Registry.HKEYPair[]{
                    new Registry.HKEYPair(Registry.HKLM, key),
                    new Registry.HKEYPair(Registry.HKCU, key)}) {
                for (String sub : Registry.subKeys(root.root(), root.path())) {
                    String display = Registry.getString(root.root(), root.path() + "\\" + sub, "DisplayName");
                    if (display == null) {
                        continue;
                    }
                    ctx.signatures().matchMacroTool(display).ifPresent(rule -> {
                        if (reported.add(rule.label())) {
                            ctx.emit(macroFinding(rule.label(), display, "installed program", rule.severity()));
                        }
                    });
                }
            }
        }

        // running processes
        for (WinProcess.Proc p : WinProcess.list()) {
            ctx.signatures().matchMacroTool(p.name()).ifPresent(rule -> {
                if (reported.add(rule.label() + ":proc")) {
                    ctx.emit(macroFinding(rule.label(), p.name(), "running process", rule.severity()));
                }
            });
        }
    }

    private Finding macroFinding(String label, String evidence, String source, Severity sev) {
        return Finding.builder(Category.PERIPHERALS, sev,
                        "Макрос/авто-кликер ПО / Macro or auto-clicker software")
                .module(ID)
                .detail(label)
                .evidence(evidence)
                .source(source)
                .build();
    }

    private void ahkScripts(ScanContext ctx) {
        for (var profile : Platform.userProfiles()) {
            for (var root : new java.nio.file.Path[]{
                    profile.resolve("Desktop"),
                    profile.resolve("Documents"),
                    profile.resolve("Downloads"),
                    Platform.roamingAppData(profile)}) {
                FileInspection.walk(root, 4000, 6, f -> {
                    if (f.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".ahk")) {
                        ctx.emit(Finding.builder(Category.PERIPHERALS, Severity.LOW,
                                        "AutoHotkey скрипт / AutoHotkey script")
                                .module(ID)
                                .detail("AHK scripts can implement triggerbots / no-recoil macros")
                                .evidence(f.toString())
                                .source("file")
                                .openPath(f.getParent() != null ? f.getParent().toString() : null)
                                .build());
                    }
                }, ctx);
            }
        }
    }

    private void usbHistory(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        String base = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
        String[] devices = Registry.subKeys(Registry.HKLM, base);
        if (devices.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        int shown = 0;
        for (String d : devices) {
            if (shown++ < 12) {
                sb.append(prettyUsb(d)).append("; ");
            }
        }
        ctx.emit(Finding.builder(Category.PERIPHERALS, Severity.INFO,
                        "История USB-накопителей / USB storage history")
                .module(ID)
                .detail(devices.length + " устройств(а): " + sb)
                .source("USBSTOR")
                .build());
    }

    private static String prettyUsb(String key) {
        // Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00 -> SanDisk Ultra
        String s = key.replace("Disk&", "").replace("Ven_", "").replace("Prod_", " ")
                .replace("Rev_", " ").replace("&", " ");
        return s.trim();
    }
}

package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Severity;
import ru.moon.checker.signatures.SignatureRule;

import java.util.Locale;

/**
 * What a vulnerable-driver match means depends on where the driver lives.
 *
 * <p>Many drivers on the vulnerable-driver list ship with everyday gaming software:
 * MSI Afterburner, RGB and fan-control utilities, motherboard suites, another game's
 * anti-cheat. Installed by that software they sit in Windows' driver folders or under
 * Program Files, and their presence says nothing about cheating. A cheat that abuses
 * such a driver (bring-your-own-vulnerable-driver) drops its own copy where a user
 * program can write — Temp, AppData, Downloads, the Desktop — and loads it from there.
 * So: a system or vendor location is context for the reviewer; an unusual location
 * asks for a look; a user-writable location keeps the rule's full severity.
 * Manual-mapper names (the tool, not a vendor driver) are never legitimate.
 */
public final class DriverPlacement {

    public enum Place { SYSTEM, VENDOR, UNUSUAL, USER_WRITABLE }

    private DriverPlacement() {
    }

    /** Where a driver path points. Accepts NT ({@code \??\C:\…}), {@code \SystemRoot\…}, relative and AmCache forms. */
    public static Place of(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return Place.UNUSUAL;
        }
        String p = rawPath.trim().replace('/', '\\').toLowerCase(Locale.ROOT);
        for (String prefix : new String[]{"\\??\\", "\\\\?\\", "\\\\.\\"}) {
            if (p.startsWith(prefix)) {
                p = p.substring(prefix.length());
            }
        }
        if (p.startsWith("\\systemroot\\") || p.startsWith("%systemroot%\\") || p.startsWith("%windir%\\")) {
            p = "c:\\windows\\" + p.substring(p.indexOf('\\', 1) + 1);
        } else if (p.startsWith("system32\\") || p.startsWith("syswow64\\")) {
            p = "c:\\windows\\" + p;
        }
        if (p.contains("\\temp\\") || p.contains("\\tmp\\") || p.contains("\\appdata\\") || p.contains("\\downloads\\")
                || p.contains("\\desktop\\") || p.contains("\\$recycle.bin\\") || p.contains("\\users\\public\\")
                || p.contains("\\onedrive\\") || p.matches("^[a-z]:\\\\[^\\\\]+$")) {
            return Place.USER_WRITABLE;
        }
        if (p.matches("^[a-z]:\\\\windows\\\\.*")) {
            return Place.SYSTEM;
        }
        if (p.matches("^[a-z]:\\\\(program files|program files \\(x86\\)|programdata)\\\\.*")) {
            return Place.VENDOR;
        }
        if (p.contains("\\users\\")) {
            return Place.USER_WRITABLE;
        }
        return Place.UNUSUAL;
    }

    /** Manual mappers are tools, never a vendor's driver: full severity wherever they are. */
    static boolean isMapperTool(SignatureRule rule) {
        String pattern = rule.pattern() == null ? "" : rule.pattern();
        return pattern.contains("mapper");
    }

    /** The finding for a vulnerable-driver rule match on {@code path}. */
    public static Finding finding(SignatureRule rule, String path, String module, String source) {
        Place place = isMapperTool(rule) ? Place.USER_WRITABLE : of(path);
        return switch (place) {
            case SYSTEM, VENDOR -> Finding.builder(Category.KERNEL, Severity.LOW,
                            "Уязвимый, но легитимный драйвер установлен / Vulnerable driver installed by software")
                    .module(module).kind(EvidenceKind.CONTEXT).rule("kernel:vulnerable-driver-installed")
                    .detail(rule.label() + " — installed in a " + (place == Place.SYSTEM ? "Windows" : "program")
                            + " folder; usually part of hardware or monitoring software")
                    .evidence(path).source(source).build();
            case UNUSUAL -> Finding.builder(Category.KERNEL, min(rule.severity(), Severity.MEDIUM),
                            "Уязвимый драйвер в необычной папке / Vulnerable driver in an unusual folder")
                    .module(module).rule("kernel:vulnerable-driver")
                    .detail(rule.label() + " — not in a Windows or program folder")
                    .evidence(path).source(source).build();
            case USER_WRITABLE -> Finding.builder(Category.KERNEL, rule.severity(),
                            "Уязвимый/маппер драйвер из пользовательской папки / Vulnerable or mapper driver in a user folder")
                    .module(module).rule("kernel:vulnerable-driver")
                    .detail(rule.label() + " — where cheat loaders drop drivers they abuse")
                    .evidence(path).source(source).build();
        };
    }

    private static Severity min(Severity a, Severity b) {
        return a.compareTo(b) <= 0 ? a : b;
    }
}

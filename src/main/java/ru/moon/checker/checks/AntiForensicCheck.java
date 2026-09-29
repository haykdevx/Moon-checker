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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Detects tell-tale signs the PC was "cleaned" before the check: cleared event
 * logs, Prefetch/SysMain turned off, a very recent Windows reinstall, and
 * cleaner tools (CCleaner, PrivaZer, BleachBit, Wise, Privacy Eraser...) that
 * are installed or have run. On their own these aren't proof of cheating, but a
 * freshly-wiped machine right before an inspection is highly suspicious.
 */
public final class AntiForensicCheck implements CheckModule {

    public static final String ID = "antiforensic";

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
        return I18n.t("module.antiforensic");
    }

    @Override
    public Category category() {
        return Category.ANTIFORENSIC;
    }

    @Override
    public void run(ScanContext ctx) {
        clearedEventLogs(ctx);
        prefetchDisabled(ctx);
        freshInstall(ctx);
        cleanerTools(ctx);
    }

    private void clearedEventLogs(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        ctx.log(I18n.t("log.eventlog"));
        // Security 1102 = audit log cleared, System 104 = event log cleared
        String out = powershell(
                "$e=@(); "
                + "$e+=Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue; "
                + "$e+=Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 5 -ErrorAction SilentlyContinue; "
                + "$e | ForEach-Object { $_.TimeCreated.ToString('o') + '|' + $_.Id }");
        if (out == null) {
            return;
        }
        for (String line : out.split("\\R")) {
            line = line.trim();
            if (line.isEmpty() || !line.contains("|")) {
                continue;
            }
            Instant when = parseInstant(line.substring(0, line.indexOf('|')));
            ctx.emit(Finding.builder(Category.ANTIFORENSIC, Severity.HIGH,
                            "Журнал событий очищен / Event log was cleared")
                    .module(ID)
                    .detail("Windows event log cleared (id " + line.substring(line.indexOf('|') + 1) + ")")
                    .source("Security/System event log")
                    .when(when)
                    .build());
        }
    }

    private void prefetchDisabled(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        int prefetch = Registry.getIntOr(Registry.HKLM,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
                "EnablePrefetcher", 3);
        if (prefetch == 0) {
            ctx.emit(Finding.builder(Category.ANTIFORENSIC, Severity.MEDIUM,
                            "Prefetch отключён / Prefetch disabled")
                    .module(ID)
                    .detail("EnablePrefetcher=0 — execution history is being suppressed")
                    .source("registry")
                    .build());
        }
        int sysmain = Registry.getIntOr(Registry.HKLM,
                "SYSTEM\\CurrentControlSet\\Services\\SysMain", "Start", 2);
        if (sysmain == 4) {
            ctx.emit(Finding.builder(Category.ANTIFORENSIC, Severity.LOW,
                            "Служба SysMain отключена / SysMain service disabled")
                    .module(ID)
                    .detail("SysMain (Superfetch) disabled — often done to reduce prefetch traces")
                    .source("registry")
                    .build());
        }
    }

    private void freshInstall(ScanContext ctx) {
        int installDate = Registry.getIntOr(Registry.HKLM,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate", 0);
        if (installDate <= 0) {
            return;
        }
        Instant installed = Instant.ofEpochSecond(installDate & 0xFFFFFFFFL);
        long days = Duration.between(installed, Instant.now()).toDays();
        if (days < 0 || days > 7) {
            return;
        }
        // A feature update (e.g. 24H2 -> 25H2) rewrites InstallDate too; it leaves
        // "Source OS (Updated on …)" keys under HKLM\SYSTEM\Setup, a clean reinstall does not.
        if (featureUpdate(Registry.subKeys(Registry.HKLM, "SYSTEM\\Setup"))) {
            ctx.emit(Finding.builder(Category.ANTIFORENSIC, Severity.INFO,
                            "Недавнее крупное обновление Windows / Recent Windows feature update")
                    .module(ID).kind(ru.moon.checker.core.EvidenceKind.CONTEXT).rule("antiforensic:feature-update")
                    .detail("Windows was upgraded in place " + days + " day(s) ago; execution history from before "
                            + "the update may be shorter")
                    .source("registry InstallDate + Setup\\Source OS")
                    .when(installed)
                    .build());
            return;
        }
        ctx.emit(Finding.builder(Category.ANTIFORENSIC, Severity.MEDIUM,
                        "Свежая переустановка Windows / Recent Windows reinstall")
                .module(ID).rule("antiforensic:fresh-install")
                .detail("Windows was installed " + days + " day(s) ago — possible wipe before the check")
                .source("registry InstallDate")
                .when(installed)
                .build());
    }

    /** In-place upgrades leave "Source OS (Updated on …)" keys; a clean install has none. */
    static boolean featureUpdate(String[] setupSubKeys) {
        for (String k : setupSubKeys) {
            if (k != null && k.toLowerCase(Locale.ROOT).startsWith("source os")) {
                return true;
            }
        }
        return false;
    }

    /** Cleaner found by: installed / ran at some point / ran within the last day / running now. */
    enum CleanerEvidence { INSTALLED, RAN_BEFORE, RAN_RECENTLY, RUNNING }

    /**
     * Having a cleaner installed is common (CCleaner ships with many PCs) and only context;
     * running one shortly before a check is what hides traces. Secure-wipe tools keep their
     * rule's severity whenever they ran.
     */
    static Severity cleanerSeverity(Severity ruleSeverity, CleanerEvidence how) {
        return switch (how) {
            case INSTALLED -> Severity.LOW;
            case RAN_BEFORE -> ruleSeverity.compareTo(Severity.HIGH) >= 0 ? Severity.MEDIUM : Severity.LOW;
            case RAN_RECENTLY -> ruleSeverity.compareTo(Severity.MEDIUM) >= 0 ? ruleSeverity : Severity.MEDIUM;
            case RUNNING -> Severity.HIGH;
        };
    }

    private void cleanerTools(ScanContext ctx) {
        Set<String> reported = new LinkedHashSet<>();
        // installed
        for (String key : UNINSTALL_KEYS) {
            for (String sub : Registry.subKeys(Registry.HKLM, key)) {
                String display = Registry.getString(Registry.HKLM, key + "\\" + sub, "DisplayName");
                if (display != null) {
                    ctx.signatures().matchCleaner(display).ifPresent(rule -> {
                        if (reported.add(rule.label())) {
                            ctx.emit(cleaner(rule.label(), display, "installed program",
                                    cleanerSeverity(rule.severity(), CleanerEvidence.INSTALLED)));
                        }
                    });
                }
            }
        }
        // ran (prefetch)
        Path pf = Platform.prefetchDir();
        if (Files.isDirectory(pf)) {
            // a prefetch file is rewritten every time its program runs: its date is the last run
            Instant dayAgo = Instant.now().minus(Duration.ofHours(24));
            FileInspection.walk(pf, 5000, 1, f -> ctx.signatures().matchCleaner(f.getFileName().toString())
                    .ifPresent(rule -> {
                        if (reported.add(rule.label() + ":pf")) {
                            Instant last = lastModified(f);
                            boolean recent = last != null && last.isAfter(dayAgo);
                            ctx.emit(cleaner(rule.label(), f.getFileName().toString(),
                                    recent ? "Prefetch (ran in the last 24 h)" : "Prefetch (ran)",
                                    cleanerSeverity(rule.severity(),
                                            recent ? CleanerEvidence.RAN_RECENTLY : CleanerEvidence.RAN_BEFORE)));
                        }
                    }), ctx);
        }
        // running
        for (WinProcess.Proc p : WinProcess.list()) {
            ctx.signatures().matchCleaner(p.name()).ifPresent(rule -> {
                if (reported.add(rule.label() + ":proc")) {
                    ctx.emit(cleaner(rule.label(), p.name(), "running process",
                            cleanerSeverity(rule.severity(), CleanerEvidence.RUNNING)));
                }
            });
        }
    }

    private Finding cleaner(String label, String evidence, String source, Severity sev) {
        return Finding.builder(Category.ANTIFORENSIC, sev,
                        "Инструмент очистки / Cleaner tool")
                .module(ID)
                .detail(label + " — " + source)
                .evidence(evidence)
                .source(source)
                .build();
    }

    private static Instant lastModified(Path f) {
        try {
            return Files.getLastModifiedTime(f).toInstant();
        } catch (Exception e) {
            return null;
        }
    }

    private Instant parseInstant(String iso) {
        try {
            return Instant.parse(iso);
        } catch (Exception e) {
            return null;
        }
    }

    private String powershell(String script) {
        ru.moon.checker.win.WinCommand.Result r = ru.moon.checker.win.WinCommand.powershell(45, script);
        return r.timedOut() || r.exitCode() < 0 ? null : r.output();
    }
}

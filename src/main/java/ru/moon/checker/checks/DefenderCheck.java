package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Reads Windows Defender's own threat-detection history via PowerShell
 * ({@code Get-MpThreatDetection}). A past "HackTool" / injector detection is
 * strong evidence a cheat was on the machine. Also flags real-time protection
 * being turned off, which cheaters do before running a loader.
 */
public final class DefenderCheck implements CheckModule {

    public static final String ID = "defender";

    private static final String[] HIGH_KEYWORDS = {
            "hacktool", "cheatengine", "keygen", "inject", "aimbot", "wallhack",
            "gamehack", "cheat", "trainer"
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public boolean required() {
        return false; // context for the reviewer, not coverage the verdict depends on
    }

    @Override
    public String displayName() {
        return I18n.t("module.defender");
    }

    @Override
    public Category category() {
        return Category.DEFENDER;
    }

    @Override
    public void run(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        ctx.log(I18n.t("log.defender"));
        threatHistory(ctx);
        protectionState(ctx);
    }

    private void threatHistory(ScanContext ctx) {
        String script = "Get-MpThreatDetection | ForEach-Object { "
                + "$_.InitialDetectionTime.ToString('o') + '|' + "
                + "($_.Resources -join ';') } ; "
                + "Get-MpThreat | ForEach-Object { 'THREAT|' + $_.ThreatName }";
        String out = powershell(script);
        if (out == null) {
            return;
        }
        Set<String> seen = new LinkedHashSet<>();
        for (String line : out.split("\\R")) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            String lower = line.toLowerCase(Locale.ROOT);
            boolean relevant = false;
            Severity sev = Severity.MEDIUM;
            for (String kw : HIGH_KEYWORDS) {
                if (lower.contains(kw)) {
                    relevant = true;
                    if (!kw.equals("trainer")) {
                        sev = Severity.HIGH;
                    }
                    break;
                }
            }
            // also match player cheat signatures inside the detection resource path
            if (!relevant && ctx.signatures().matchCheatName(lower).isPresent()) {
                relevant = true;
                sev = Severity.HIGH;
            }
            if (relevant && seen.add(line)) {
                ctx.emit(Finding.builder(Category.DEFENDER, sev,
                                "Defender ранее обнаружил угрозу / Defender detected a threat")
                        .module(ID)
                        .detail(line.replace("THREAT|", "").replace("|", "  —  "))
                        .source("Get-MpThreatDetection")
                        .build());
            }
        }
    }

    private void protectionState(ScanContext ctx) {
        String out = powershell("(Get-MpPreference).DisableRealtimeMonitoring");
        if (out != null && out.trim().equalsIgnoreCase("true")) {
            ctx.emit(Finding.builder(Category.DEFENDER, Severity.MEDIUM,
                            "Защита в реальном времени отключена / Real-time protection disabled")
                    .module(ID)
                    .detail("Defender real-time monitoring is turned off")
                    .source("Get-MpPreference")
                    .build());
        }
    }

    private String powershell(String script) {
        try {
            Process p = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", script)
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor(30, TimeUnit.SECONDS);
            return out;
        } catch (Throwable t) {
            return null;
        }
    }
}

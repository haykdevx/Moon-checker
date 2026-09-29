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

/**
 * Reads Windows Defender's own threat-detection history via PowerShell
 * ({@code Get-MpThreatDetection}). A past game-hack / injector detection is strong
 * evidence a cheat was on the machine.
 *
 * <p>Defender files many unrelated things under {@code HackTool}: Windows and Office
 * activators (AutoKMS, KMSpico), keygens and cracks. They are everywhere on Russian
 * gaming PCs and say nothing about cheating in CS2, so a detection counts only when
 * its name or file points at a game hack; anything else under HackTool is context.
 * Real-time protection being off is a setting: it lowers trust in the report and is
 * never a reason for review on its own.
 */
public final class DefenderCheck implements CheckModule {

    public static final String ID = "defender";

    /** Detection names that point at game hacking (checked on the lower-cased name + resources). */
    static final String[] GAME_HACK = {
            "gamehack", "cheatengine", "cheat", "aimbot", "wallhack", "triggerbot", "inject", "trainer"
    };
    /** HackTool families that are software piracy, not game hacking. */
    static final String[] PIRACY = {"autokms", "kmsauto", "kmspico", "kms", "keygen", "crack", "patch", "activator"};

    /** How a Defender history line should be treated. */
    enum Weight { CHEAT_HIGH, CHEAT_MEDIUM, CONTEXT, IGNORE }

    static Weight weigh(String lowerLine) {
        boolean piracy = false;
        for (String p : PIRACY) {
            if (lowerLine.contains(p)) {
                piracy = true;
                break;
            }
        }
        for (String kw : GAME_HACK) {
            // "Injector" alone is a generic malware family; a DLL injector filed as HackTool is a cheat loader
            boolean genericMalware = kw.equals("inject") && !lowerLine.contains("hacktool");
            if (lowerLine.contains(kw) && !genericMalware) {
                return kw.equals("trainer") ? Weight.CHEAT_MEDIUM : Weight.CHEAT_HIGH;
            }
        }
        if (lowerLine.contains("hacktool") || piracy) {
            return Weight.CONTEXT;
        }
        return Weight.IGNORE;
    }

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
            if (line.isEmpty() || !seen.add(line)) {
                continue;
            }
            String lower = line.toLowerCase(Locale.ROOT);
            Weight w = weigh(lower);
            // a player cheat signature inside the detected file's path counts as a game hack too
            if (w != Weight.CHEAT_HIGH && ctx.signatures().matchCheatName(lower).isPresent()) {
                w = Weight.CHEAT_HIGH;
            }
            String detail = line.replace("THREAT|", "").replace("|", "  —  ");
            switch (w) {
                case CHEAT_HIGH, CHEAT_MEDIUM -> ctx.emit(Finding.builder(Category.DEFENDER,
                                w == Weight.CHEAT_HIGH ? Severity.HIGH : Severity.MEDIUM,
                                "Defender ранее обнаружил чит-инструмент / Defender detected a game-hack tool")
                        .module(ID).rule("defender:game-hack-detected")
                        .detail(detail).source("Get-MpThreatDetection").build());
                case CONTEXT -> ctx.emit(Finding.builder(Category.DEFENDER, Severity.INFO,
                                "Defender обнаруживал хак-утилиту (не игровую) / Defender detected a non-game hack tool")
                        .module(ID).kind(ru.moon.checker.core.EvidenceKind.CONTEXT).rule("defender:other-hacktool")
                        .detail(detail + " — activators, keygens and cracks are filed here too")
                        .source("Get-MpThreatDetection").build());
                case IGNORE -> {
                    // ordinary malware or PUA detections are not about the game
                }
            }
        }
    }

    private void protectionState(ScanContext ctx) {
        String out = powershell("(Get-MpPreference).DisableRealtimeMonitoring");
        if (out != null && out.trim().equalsIgnoreCase("true")) {
            ctx.emit(Finding.builder(Category.DEFENDER, Severity.LOW,
                            "Защита в реальном времени отключена / Real-time protection disabled")
                    .module(ID).kind(ru.moon.checker.core.EvidenceKind.CONFIGURATION).rule("defender:realtime-off")
                    .detail("Defender real-time monitoring is turned off by a setting (many gamers do this for "
                            + "performance; a third-party antivirus does not change this setting)")
                    .source("Get-MpPreference")
                    .build());
        }
    }

    private String powershell(String script) {
        ru.moon.checker.win.WinCommand.Result r = ru.moon.checker.win.WinCommand.powershell(30, script);
        return r.timedOut() || r.exitCode() < 0 ? null : r.output();
    }
}

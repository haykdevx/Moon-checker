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
        exclusions(ctx);
    }

    /** How one antivirus exclusion is reported. */
    record ExclusionCall(Severity severity, ru.moon.checker.core.EvidenceKind kind, String rule, String why) {
    }

    /**
     * Whether an exclusion hides something. Excluding a user-writable folder, a whole drive or all
     * programs (.exe/.dll/.sys) is how cheats keep the antivirus away; a program folder excluded
     * for performance (games, IDEs, build tools) is context.
     */
    static ExclusionCall classifyExclusion(String type, String value) {
        String v = value == null ? "" : value.strip();
        String lower = v.toLowerCase(java.util.Locale.ROOT);
        var concealment = ru.moon.checker.core.EvidenceKind.CONCEALMENT;
        var context = ru.moon.checker.core.EvidenceKind.CONTEXT;
        switch (type) {
            case "Extension" -> {
                String ext = lower.startsWith(".") ? lower.substring(1) : lower;
                if (java.util.Set.of("exe", "dll", "sys", "scr", "com", "bat", "ps1").contains(ext)) {
                    return new ExclusionCall(Severity.HIGH, concealment, "defender:exclusion-programs",
                            "every ." + ext + " file is excluded from antivirus scanning");
                }
                return new ExclusionCall(Severity.LOW, context, "defender:exclusion", "file type excluded");
            }
            case "Process" -> {
                return new ExclusionCall(Severity.LOW, context, "defender:exclusion", "process excluded from scanning");
            }
            default -> {
                String n = Locations.normalize(v, true);
                if (n != null && n.matches("^[a-z]:\\\\?$")) {
                    return new ExclusionCall(Severity.HIGH, concealment, "defender:exclusion-drive",
                            "a whole drive is excluded from antivirus scanning");
                }
                return switch (Locations.classify(v)) {
                    case USER_WRITABLE, NETWORK, UNKNOWN -> new ExclusionCall(Severity.MEDIUM, concealment,
                            "defender:exclusion-user-folder", "a folder an ordinary user can write to is excluded");
                    case OTHER -> new ExclusionCall(Severity.LOW, context, "defender:exclusion",
                            "folder excluded (often a game library or tools folder)");
                    case PROGRAM, SYSTEM -> new ExclusionCall(Severity.LOW, context, "defender:exclusion",
                            "program or system folder excluded");
                };
            }
        }
    }

    private void exclusions(ScanContext ctx) {
        String out = powershell("$p = Get-MpPreference; "
                + "foreach ($x in $p.ExclusionPath) { 'Path|' + $x }; "
                + "foreach ($x in $p.ExclusionProcess) { 'Process|' + $x }; "
                + "foreach ($x in $p.ExclusionExtension) { 'Extension|' + $x }");
        java.util.List<String[]> items = new java.util.ArrayList<>();
        if (out != null) {
            for (String line : out.split("\\R")) {
                int bar = line.indexOf('|');
                if (bar > 0 && !line.substring(bar + 1).isBlank() && !line.contains("N/A")) {
                    items.add(new String[]{line.substring(0, bar).strip(), line.substring(bar + 1).strip()});
                }
            }
        }
        if (items.isEmpty()) {  // older Windows or no PowerShell module: the registry has the same lists
            for (String type : new String[]{"Path", "Process", "Extension"}) {
                String key = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\" + (type.equals("Path") ? "Paths"
                        : type.equals("Process") ? "Processes" : "Extensions");
                for (String name : ru.moon.checker.win.Registry.values(ru.moon.checker.win.Registry.HKLM, key).keySet()) {
                    items.add(new String[]{type, name});
                }
            }
        }
        for (String[] it : items) {
            var cheat = ctx.signatures().matchCheatName(it[1].toLowerCase(java.util.Locale.ROOT));
            ExclusionCall call = classifyExclusion(it[0], it[1]);
            Finding.Builder b = Finding.builder(Category.DEFENDER,
                            cheat.isPresent() ? cheat.get().severity() : call.severity(),
                            "Исключение антивируса / Antivirus exclusion")
                    .module(ID).rule(cheat.isPresent() ? "defender:exclusion-cheat-name" : call.rule())
                    .detail(it[0] + " exclusion: " + call.why() + cheat.map(r -> " — " + r.label()).orElse(""))
                    .evidence(it[1]).source("Windows Defender exclusions");
            if (cheat.isEmpty()) {
                b.kind(call.kind());
            }
            ctx.emit(b.build());
        }
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

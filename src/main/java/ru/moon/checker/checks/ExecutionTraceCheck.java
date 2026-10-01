package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.Lnk;
import ru.moon.checker.parse.Prefetch;
import ru.moon.checker.parse.PrefetchBody;
import ru.moon.checker.parse.UserAssist;
import ru.moon.checker.win.Registry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;

/**
 * Correlates every Windows "this program ran" artefact against the cheat
 * signatures: Prefetch, Background Activity Moderator (BAM), UserAssist,
 * MUICache, the Program Compatibility Assistant store, RunMRU, and Recent
 * shortcuts. Together these survive most casual cleanup and pin an execution
 * to a timestamp.
 */
public final class ExecutionTraceCheck implements CheckModule {

    public static final String ID = "execution";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.execution");
    }

    @Override
    public Category category() {
        return Category.EXECUTION;
    }

    @Override
    public void run(ScanContext ctx) {
        prefetch(ctx);
        bam(ctx);
        try (ru.moon.checker.win.UserHives.Scope scope = ru.moon.checker.win.UserHives.open()) {
            for (ru.moon.checker.win.UserHives.User user : scope.users()) {
                if (ctx.isCancelled()) {
                    return;
                }
                userAssist(ctx, user);
                muiCache(ctx, user);
                compatAssistant(ctx, user);
                featureUsage(ctx, user);
                runMru(ctx, user);
            }
        }
        recentLnk(ctx);
    }

    private void report(ScanContext ctx, String name, String evidence, String source, Instant when) {
        ctx.signatures().matchCheatName(baseName(name)).ifPresent(rule ->
                ctx.emit(Finding.builder(Category.EXECUTION, rule.severity(),
                                "Запуск чита зафиксирован / Cheat execution recorded")
                        .module(ID)
                        .detail(rule.label() + " — " + source)
                        .evidence(evidence)
                        .source(source)
                        .when(when)
                        .build()));
    }

    private void prefetch(ScanContext ctx) {
        Path dir = Platform.prefetchDir();
        if (!Files.isDirectory(dir)) {
            return;
        }
        ctx.log(I18n.t("log.prefetch"));
        java.util.Set<String> seen = new java.util.HashSet<>();
        FileInspection.walk(dir, 5000, 1, f -> {
            Prefetch.Info info = Prefetch.fromFileName(f.getFileName().toString());
            if (info == null) {
                return;
            }
            Instant when = null;
            try {
                when = Files.getLastModifiedTime(f).toInstant();
            } catch (Exception ignored) {
            }
            // Decompress and parse the .pf body: real run times + every module
            // the program loaded at startup.
            PrefetchBody.Body body = readBody(f);
            if (body != null && body.lastRun() != null) {
                when = body.lastRun();
            }
            report(ctx, info.exeName(), f.toString(), "Prefetch", when);
            if (body != null) {
                loadedModules(ctx, info.exeName(), body, when, seen);
            }
        }, ctx);
    }

    private PrefetchBody.Body readBody(Path f) {
        try {
            if (Files.size(f) > 8L * 1024 * 1024) {
                return null;
            }
            return PrefetchBody.parse(Files.readAllBytes(f));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * A cheat DLL in a program's Prefetch module list proves it was loaded into
     * that process — evidence that survives deleting the DLL itself.
     */
    private void loadedModules(ScanContext ctx, String exeName, PrefetchBody.Body body,
                               Instant when, java.util.Set<String> seen) {
        boolean game = isGame(exeName);
        for (String path : body.loadedFiles()) {
            if (path == null || path.isBlank()) {
                continue;
            }
            String lower = path.toLowerCase(Locale.ROOT);
            ctx.signatures().matchCheatName(lower).ifPresent(rule -> {
                if (!seen.add(exeName + "|" + rule.label() + "|" + baseName(path))) {
                    return;
                }
                Severity sev = game ? Severity.CRITICAL : escalate(rule.severity());
                ctx.emit(Finding.builder(Category.EXECUTION, sev,
                                "Чит-модуль загружен процессом / Cheat module loaded by a process")
                        .module(ID)
                        .detail(rule.label() + " — загружен " + exeName)
                        .evidence(path)
                        .source("Prefetch (loaded modules)")
                        .when(when)
                        .build());
            });
        }
    }

    private boolean isGame(String exeName) {
        if (exeName == null) {
            return false;
        }
        String l = exeName.toLowerCase(Locale.ROOT);
        return l.startsWith("cs2") || l.startsWith("csgo") || l.contains("counter");
    }

    private Severity escalate(Severity s) {
        return s == Severity.HIGH ? Severity.CRITICAL : s;
    }

    private void bam(ScanContext ctx) {
        String base = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
        for (String sid : Registry.subKeys(Registry.HKLM, base)) {
            String path = base + "\\" + sid;
            for (String valueName : Registry.values(Registry.HKLM, path).keySet()) {
                if (!valueName.contains("\\")) {
                    continue; // only the exe-path entries
                }
                Instant when = null;
                byte[] data = Registry.getBinary(Registry.HKLM, path, valueName);
                if (data != null && data.length >= 8) {
                    when = UserAssist.fileTimeToInstant(le64(data));
                }
                report(ctx, valueName, valueName, "BAM", when);
            }
        }
    }

    private void userAssist(ScanContext ctx, ru.moon.checker.win.UserHives.User user) {
        String base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
        for (String guid : Registry.subKeys(user.root(), user.path(base))) {
            String countPath = user.path(base + "\\" + guid + "\\Count");
            Map<String, byte[]> values = Registry.binaryValues(user.root(), countPath);
            for (var e : values.entrySet()) {
                UserAssist.Entry ua = UserAssist.parse(e.getKey(), e.getValue());
                if (ua.path() == null) {
                    continue;
                }
                report(ctx, ua.path(), ua.path()
                        + (ua.runCount() > 0 ? "  (runs=" + ua.runCount() + ")" : "")
                        + "  [" + user.label() + "]",
                        "UserAssist", ua.lastRun());
            }
        }
    }

    private void muiCache(ScanContext ctx, ru.moon.checker.win.UserHives.User user) {
        String path = user.path("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
        for (String valueName : Registry.values(user.root(), path).keySet()) {
            report(ctx, valueName, valueName + "  [" + user.label() + "]", "MUICache", null);
        }
    }

    private void compatAssistant(ScanContext ctx, ru.moon.checker.win.UserHives.User user) {
        String path = user.path("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");
        for (String valueName : Registry.values(user.root(), path).keySet()) {
            report(ctx, valueName, valueName + "  [" + user.label() + "]", "CompatibilityAssistant", null);
        }
    }

    /** Taskbar usage Windows keeps per program: AppSwitched (switched to) and ShowJumpView (jump list opened). */
    private void featureUsage(ScanContext ctx, ru.moon.checker.win.UserHives.User user) {
        for (String key : new String[]{"AppSwitched", "ShowJumpView"}) {
            String path = user.path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\" + key);
            for (String valueName : Registry.values(user.root(), path).keySet()) {
                report(ctx, valueName, valueName + "  [" + user.label() + "]", "FeatureUsage " + key, null);
            }
        }
    }

    private void runMru(ScanContext ctx, ru.moon.checker.win.UserHives.User user) {
        String path = user.path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
        for (var e : Registry.values(user.root(), path).entrySet()) {
            if (e.getValue() != null) {
                String cmd = e.getValue().toString();
                report(ctx, cmd, cmd + "  [" + user.label() + "]", "RunMRU", null);
            }
        }
    }

    private void recentLnk(ScanContext ctx) {
        for (Path profile : Platform.userProfiles()) {
            Path recent = Platform.roamingAppData(profile)
                    .resolve("Microsoft").resolve("Windows").resolve("Recent");
            if (!Files.isDirectory(recent)) {
                continue;
            }
            FileInspection.walk(recent, 3000, 1, f -> {
                if (!f.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".lnk")) {
                    return;
                }
                try {
                    Lnk lnk = Lnk.parse(Files.readAllBytes(f));
                    if (!lnk.valid()) {
                        return;
                    }
                    String target = lnk.targetPath();
                    if (target != null) {
                        report(ctx, target, target, "Recent shortcut", null);
                    }
                    if (lnk.arguments() != null) {
                        ctx.signatures().matchCheatName(lnk.arguments().toLowerCase(Locale.ROOT))
                                .ifPresent(rule -> ctx.emit(Finding.builder(Category.EXECUTION, rule.severity(),
                                                "Аргументы запуска чита / Cheat launch arguments")
                                        .module(ID).detail(rule.label())
                                        .evidence(lnk.arguments()).source("Recent shortcut args").build()));
                    }
                } catch (Exception ignored) {
                }
            }, ctx);
        }
    }

    private static long le64(byte[] d) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (long) (d[i] & 0xFF) << (8 * i);
        }
        return v;
    }

    private static String baseName(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('/', '\\');
        int i = p.lastIndexOf('\\');
        String base = i >= 0 ? p.substring(i + 1) : p;
        int space = base.indexOf(' ');
        // strip trailing arguments for command-style entries
        if (space > 0 && base.toLowerCase(Locale.ROOT).contains(".exe")) {
            int exe = base.toLowerCase(Locale.ROOT).indexOf(".exe");
            base = base.substring(0, exe + 4);
        }
        return base.toLowerCase(Locale.ROOT);
    }
}

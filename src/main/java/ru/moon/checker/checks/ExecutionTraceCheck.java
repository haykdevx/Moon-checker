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
import ru.moon.checker.win.Volumes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Correlates every Windows "this program ran" artefact against the cheat
 * signatures: Prefetch (name, run count, real last-run times and the files each
 * program loaded), Background Activity Moderator (BAM), UserAssist,
 * MUICache, the Program Compatibility Assistant store, RunMRU, and Recent
 * shortcuts. Together these survive most casual cleanup and pin an execution
 * to a timestamp.
 */
public final class ExecutionTraceCheck implements CheckModule {

    public static final String ID = "execution";

    /** Real .pf files are a few KB to ~200 KB compressed. */
    private static final long MAX_PREFETCH_BYTES = 8L * 1024 * 1024;

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
                runMru(ctx, user);
            }
        }
        recentLnk(ctx);
    }

    private void report(ScanContext ctx, String name, String evidence, String source, Instant when) {
        report(ctx, name, evidence, source, when, "");
    }

    private void report(ScanContext ctx, String name, String evidence, String source, Instant when, String extra) {
        ctx.signatures().matchCheatName(baseName(name)).ifPresent(rule ->
                ctx.emit(Finding.builder(Category.EXECUTION, rule.severity(),
                                "Запуск чита зафиксирован / Cheat execution recorded")
                        .module(ID)
                        .detail(rule.label() + " — " + source + extra)
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
        Map<Long, Character> drives = Volumes.serialToLetter();
        FileInspection.walk(dir, 5000, 1, f -> {
            Prefetch.Info info = Prefetch.fromFileName(f.getFileName().toString());
            if (info == null) {
                return;
            }
            PrefetchBody.Info body = readBody(f);
            if (body == null) {
                // body unreadable: the name still proves execution; mtime ~ last run
                report(ctx, info.exeName(), f.toString(), "Prefetch", modified(f));
                return;
            }
            report(ctx, body.exeName().isEmpty() ? info.exeName() : body.exeName(), f.toString(), "Prefetch",
                    body.lastRun(), "  (runs=" + body.runCount() + ", last runs " + body.lastRuns() + ")");
            correlateLoadedFiles(ctx, f, body, drives);
        }, ctx);
    }

    /**
     * Every file a program loaded in its first seconds is in its Prefetch trace.
     * A cheat DLL in CS2's own trace is near-proof of injection; the same file in
     * any other program's trace (a loader, an injector) is reported at the rule's
     * severity.
     */
    static void correlateLoadedFiles(ScanContext ctx, Path pf, PrefetchBody.Info body, Map<Long, Character> drives) {
        boolean game = isGame(body.exeName());
        Set<String> seen = new HashSet<>();
        for (String loaded : body.loadedFiles()) {
            String base = baseName(loaded);
            if (base.equalsIgnoreCase(body.exeName())) {
                continue; // the program itself was already matched by name
            }
            ctx.signatures().matchCheatName(base).ifPresent(rule -> {
                if (!seen.add(rule.label() + "|" + base)) {
                    return;
                }
                String path = PrefetchBody.toDrivePath(loaded, drives);
                ctx.emit(Finding.builder(Category.EXECUTION, game ? Severity.CRITICAL : rule.severity(),
                                game ? "CS2 загрузил модуль чита / CS2 loaded a cheat module"
                                     : "Программа загрузила файл чита / Program loaded a cheat-signature file")
                        .module(ID)
                        .detail(rule.label() + " — loaded by " + body.exeName() + " (" + pf.getFileName()
                                + ", runs=" + body.runCount() + ")")
                        .evidence(path)
                        .source("Prefetch trace")
                        .when(body.lastRun())
                        .openPath(parentOf(path))
                        .build());
            });
        }
    }

    static boolean isGame(String exeName) {
        String e = exeName == null ? "" : exeName.toUpperCase(Locale.ROOT);
        return e.equals("CS2.EXE") || e.equals("CSGO.EXE");
    }

    private static PrefetchBody.Info readBody(Path pf) {
        try {
            return Files.size(pf) <= MAX_PREFETCH_BYTES ? PrefetchBody.parse(Files.readAllBytes(pf)) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Instant modified(Path f) {
        try {
            return Files.getLastModifiedTime(f).toInstant();
        } catch (Exception e) {
            return null;
        }
    }

    private static String parentOf(String path) {
        int i = path == null ? -1 : path.lastIndexOf('\\');
        return i > 0 ? path.substring(0, i) : null;
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

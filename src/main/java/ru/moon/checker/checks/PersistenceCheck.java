package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.Lnk;
import ru.moon.checker.parse.ScheduledTask;
import ru.moon.checker.win.Registry;
import ru.moon.checker.win.UserHives;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Inspects autostart / persistence — where a cheat loader, spoofer or injector
 * hides so it runs automatically: Run / RunOnce keys (all users), Windows
 * services, Scheduled Tasks, and the Startup folders. Matches the command each
 * one launches against the cheat signatures, and flags autostart entries that
 * run from abnormal locations (Temp, Public, Recycle Bin, a drive root).
 */
public final class PersistenceCheck implements CheckModule {

    public static final String ID = "persistence";

    private static final String[] RUN_SUBKEYS = {
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.persistence");
    }

    @Override
    public Category category() {
        return Category.PERSISTENCE;
    }

    @Override
    public void run(ScanContext ctx) {
        ctx.log(I18n.t("log.persistence"));
        runKeys(ctx);
        services(ctx);
        scheduledTasks(ctx);
        startupFolders(ctx);
    }

    private void runKeys(ScanContext ctx) {
        // machine-wide
        for (String sub : RUN_SUBKEYS) {
            readRunKey(ctx, Registry.HKLM, sub, "HKLM Run");
            readRunKey(ctx, Registry.HKLM, "Software\\WOW6432Node\\" + sub.substring("Software\\".length()), "HKLM Run (WOW64)");
        }
        // per-user
        try (UserHives.Scope scope = UserHives.open()) {
            for (UserHives.User user : scope.users()) {
                for (String sub : RUN_SUBKEYS) {
                    readRunKey(ctx, user.root(), user.path(sub), "Run [" + user.label() + "]");
                }
            }
        }
    }

    private void readRunKey(ScanContext ctx, com.sun.jna.platform.win32.WinReg.HKEY root, String path, String source) {
        for (var e : Registry.values(root, path).entrySet()) {
            if (e.getValue() == null) {
                continue;
            }
            matchCommand(ctx, source, e.getKey(), e.getValue().toString());
        }
    }

    private void services(ScanContext ctx) {
        String base = "SYSTEM\\CurrentControlSet\\Services";
        for (String name : Registry.subKeys(Registry.HKLM, base)) {
            if (ctx.isCancelled()) {
                return;
            }
            String imagePath = Registry.getString(Registry.HKLM, base + "\\" + name, "ImagePath");
            if (imagePath != null) {
                matchCommand(ctx, "service:" + name, name, imagePath);
            }
        }
    }

    private void scheduledTasks(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        Path tasks = Platform.windowsDir().resolve("System32").resolve("Tasks");
        if (!Files.isDirectory(tasks)) {
            return;
        }
        FileInspection.walk(tasks, 5000, 8, f -> {
            try {
                for (String cmd : ScheduledTask.execCommands(Files.readAllBytes(f))) {
                    matchCommand(ctx, "scheduled task: " + f.getFileName(), f.getFileName().toString(), cmd);
                }
            } catch (Exception ignored) {
            }
        }, ctx);
    }

    private void startupFolders(ScanContext ctx) {
        for (Path profile : Platform.userProfiles()) {
            Path startup = profile.resolve("AppData").resolve("Roaming").resolve("Microsoft")
                    .resolve("Windows").resolve("Start Menu").resolve("Programs").resolve("Startup");
            scanStartup(ctx, startup, "Startup [" + profile.getFileName() + "]");
        }
        String programData = System.getenv("ProgramData");
        if (programData != null) {
            scanStartup(ctx, Path.of(programData, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
                    "Startup (all users)");
        }
    }

    private void scanStartup(ScanContext ctx, Path dir, String source) {
        if (!Files.isDirectory(dir)) {
            return;
        }
        FileInspection.walk(dir, 2000, 2, f -> {
            String fn = f.getFileName().toString();
            String lower = fn.toLowerCase(Locale.ROOT);
            if (lower.endsWith(".lnk")) {
                try {
                    Lnk lnk = Lnk.parse(Files.readAllBytes(f));
                    String target = lnk.targetPath();
                    if (target != null) {
                        matchCommand(ctx, source, fn, target
                                + (lnk.arguments() != null ? " " + lnk.arguments() : ""));
                    }
                } catch (Exception ignored) {
                }
            } else {
                matchCommand(ctx, source, fn, f.toString());
            }
        }, ctx);
    }

    /** Match a launched command against cheat names, plus abnormal-location autostart. */
    private void matchCommand(ScanContext ctx, String source, String name, String command) {
        if (command == null) {
            return;
        }
        String probe = (name + " " + command).toLowerCase(Locale.ROOT);
        var rule = ctx.signatures().matchCheatName(probe);
        if (rule.isPresent()) {
            ctx.emit(Finding.builder(Category.PERSISTENCE, escalate(rule.get().severity()),
                            "Чит в автозагрузке / Cheat set to auto-run")
                    .module(ID)
                    .detail(rule.get().label() + " — " + source)
                    .evidence(command)
                    .source(source)
                    .build());
            return;
        }
        if (abnormalAutostart(command.toLowerCase(Locale.ROOT))) {
            ctx.emit(Finding.builder(Category.PERSISTENCE, Severity.LOW,
                            "Автозапуск из необычного места / Autostart from an unusual location")
                    .module(ID)
                    .detail(source + " — запускается из временной/скрытой папки")
                    .evidence(command)
                    .source(source)
                    .build());
        }
    }

    private boolean abnormalAutostart(String cmdLower) {
        return cmdLower.contains("\\temp\\")
                || cmdLower.contains("\\users\\public\\")
                || cmdLower.contains("\\$recycle.bin\\")
                || cmdLower.contains("\\appdata\\local\\temp")
                || cmdLower.matches(".*[a-z]:\\\\[^\\\\]+\\.exe.*"); // executable in a drive root
    }

    private Severity escalate(Severity s) {
        return s == Severity.HIGH ? Severity.CRITICAL : s;
    }
}

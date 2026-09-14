package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Linux autostart / persistence: XDG autostart {@code .desktop} files, systemd
 * user units, shell rc files ({@code .bashrc} / {@code .zshrc} / {@code .profile})
 * and per-user crontabs. Matches the launched command against the cheat
 * signatures and flags suspicious injection lines (LD_PRELOAD, {@code curl|bash}).
 */
public final class LinuxPersistenceCheck implements CheckModule {

    public static final String ID = "linuxpersist";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.linuxpersist");
    }

    @Override
    public Category category() {
        return Category.PERSISTENCE;
    }

    @Override
    public boolean windowsOnly() {
        return false;
    }

    @Override
    public void run(ScanContext ctx) {
        if (!Platform.isLinux()) {
            return;
        }
        ctx.log(I18n.t("log.persistence"));
        for (Path home : Platform.userProfiles()) {
            autostart(ctx, home);
            systemdUser(ctx, home);
            shellRc(ctx, home);
            crontab(ctx, home);
        }
    }

    private void autostart(ScanContext ctx, Path home) {
        Path dir = home.resolve(".config").resolve("autostart");
        FileInspection.walk(dir, 500, 2, f -> {
            if (!f.getFileName().toString().endsWith(".desktop")) {
                return;
            }
            try {
                for (String line : Files.readAllLines(f)) {
                    if (line.startsWith("Exec=")) {
                        matchCommand(ctx, "autostart: " + f.getFileName(), line.substring(5));
                    }
                }
            } catch (Exception ignored) {
            }
        }, ctx);
    }

    private void systemdUser(ScanContext ctx, Path home) {
        Path dir = home.resolve(".config").resolve("systemd").resolve("user");
        FileInspection.walk(dir, 1000, 3, f -> {
            if (!f.getFileName().toString().endsWith(".service")) {
                return;
            }
            try {
                for (String line : Files.readAllLines(f)) {
                    String l = line.trim();
                    if (l.startsWith("ExecStart=")) {
                        matchCommand(ctx, "systemd user: " + f.getFileName(), l.substring("ExecStart=".length()));
                    }
                }
            } catch (Exception ignored) {
            }
        }, ctx);
    }

    private void shellRc(ScanContext ctx, Path home) {
        for (String rc : new String[]{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"}) {
            Path f = home.resolve(rc);
            if (!Files.isRegularFile(f)) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(f)) {
                    String low = line.toLowerCase(Locale.ROOT);
                    if (low.contains("ld_preload") || (low.contains("curl") && low.contains("| bash"))
                            || (low.contains("wget") && low.contains("|sh"))) {
                        ctx.emit(Finding.builder(Category.PERSISTENCE, Severity.MEDIUM,
                                        "Подозрительная строка в " + rc + " / Suspicious shell-init line")
                                .module(ID).detail(line.strip()).evidence(f.toString()).source(rc).build());
                    }
                    ctx.signatures().matchCheatName(low).ifPresent(rule ->
                            ctx.emit(Finding.builder(Category.PERSISTENCE, rule.severity(),
                                            "Чит в " + rc + " / Cheat referenced in shell init")
                                    .module(ID).detail(rule.label() + "  —  " + line.strip())
                                    .evidence(f.toString()).source(rc).build()));
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void crontab(ScanContext ctx, Path home) {
        String user = home.getFileName().toString();
        for (Path spool : new Path[]{
                Path.of("/var/spool/cron/crontabs", user),
                Path.of("/var/spool/cron", user)}) {
            if (!Files.isRegularFile(spool)) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(spool)) {
                    if (line.startsWith("#") || line.isBlank()) {
                        continue;
                    }
                    matchCommand(ctx, "crontab: " + user, line);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void matchCommand(ScanContext ctx, String source, String command) {
        if (command == null) {
            return;
        }
        String low = command.toLowerCase(Locale.ROOT);
        ctx.signatures().matchCheatName(low).ifPresent(rule ->
                ctx.emit(Finding.builder(Category.PERSISTENCE, escalate(rule.severity()),
                                "Чит в автозагрузке / Cheat set to auto-run")
                        .module(ID).detail(rule.label() + " — " + source)
                        .evidence(command.strip()).source(source).build()));
    }

    private Severity escalate(Severity s) {
        return s == Severity.HIGH ? Severity.CRITICAL : s;
    }
}

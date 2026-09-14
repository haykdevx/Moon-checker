package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.linux.Proc;

import java.util.Locale;

/**
 * Linux running-process inspection. Matches process name / command line / image
 * path against the cheat signatures, and — for the running CS2 process —
 * examines its memory maps and environment for injected libraries:
 * {@code LD_PRELOAD}, a mapped {@code .so} in a temp/writable location, or a
 * mapping marked {@code (deleted)} (the library was deleted after being loaded,
 * a common way to hide an injected cheat).
 */
public final class LinuxProcessCheck implements CheckModule {

    public static final String ID = "linuxproc";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.linuxproc");
    }

    @Override
    public Category category() {
        return Category.ENVIRONMENT;
    }

    @Override
    public boolean windowsOnly() {
        return false;
    }

    @Override
    public void run(ScanContext ctx) {
        if (!Platform.isLinux() || !Proc.available()) {
            return;
        }
        ctx.log(I18n.t("log.linuxproc"));
        for (int pid : Proc.pids()) {
            if (ctx.isCancelled()) {
                return;
            }
            String comm = Proc.comm(pid);
            String cmdline = Proc.cmdline(pid);
            String exe = Proc.exe(pid);

            // The process IS the cheat only when its own image/name matches.
            String identity = ((comm == null ? "" : comm) + " "
                    + (exe == null ? "" : exe)).toLowerCase(Locale.ROOT);
            ctx.signatures().matchCheatName(identity).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.ENVIRONMENT, runningSeverity(rule.severity()),
                                    "Процесс чита запущен / Cheat process is running")
                            .module(ID)
                            .detail(rule.label() + "  (pid " + pid + ")")
                            .evidence(exe != null ? exe : comm)
                            .source("process")
                            .build()));

            // A match only in the command line is far weaker: a shell or editor
            // that merely mentions a cheat word is not a running cheat.
            if (cmdline != null && !isInterpreter(comm)) {
                String cmdLower = cmdline.toLowerCase(Locale.ROOT);
                if (ctx.signatures().matchCheatName(identity).isEmpty()) {
                    ctx.signatures().matchCheatName(cmdLower).ifPresent(rule ->
                            ctx.emit(Finding.builder(Category.ENVIRONMENT, weaken(rule.severity()),
                                            "Чит в командной строке процесса / Cheat referenced in a process command line")
                                    .module(ID)
                                    .detail(rule.label() + "  (pid " + pid + ", " + comm + ")")
                                    .evidence(cmdline.length() > 200 ? cmdline.substring(0, 200) : cmdline)
                                    .source("process cmdline")
                                    .build()));
                }
            }

            if (isGame(identity)) {
                inspectGameProcess(ctx, pid, comm);
            }
        }
    }

    /**
     * A cheat actually running is decisive — but only lift rules that were
     * already strong. A MEDIUM keyword like "bhop" must not become a CHEAT
     * verdict on its own (it briefly did: a bash process whose command line
     * contained the word was reported as a running cheat).
     */
    private Severity runningSeverity(Severity ruleSeverity) {
        return ruleSeverity == Severity.HIGH || ruleSeverity == Severity.CRITICAL
                ? Severity.CRITICAL
                : ruleSeverity;
    }

    /** Command-line mentions are context, never proof. */
    private Severity weaken(Severity ruleSeverity) {
        return switch (ruleSeverity) {
            case CRITICAL, HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    /** Shells and interpreters run other people's text; their cmdline is noise. */
    private boolean isInterpreter(String comm) {
        if (comm == null) {
            return true;
        }
        String c = comm.toLowerCase(Locale.ROOT);
        return c.equals("bash") || c.equals("sh") || c.equals("zsh") || c.equals("dash")
                || c.equals("fish") || c.startsWith("python") || c.equals("perl")
                || c.equals("node") || c.equals("java") || c.equals("grep")
                || c.equals("sed") || c.equals("awk") || c.equals("less")
                || c.equals("vim") || c.equals("nano") || c.equals("code");
    }

    private boolean isGame(String probe) {
        return probe.contains("cs2") || probe.contains("csgo")
                || probe.contains("counter-strike") || probe.contains("counterstrike");
    }

    private void inspectGameProcess(ScanContext ctx, int pid, String comm) {
        // injected libraries via mapped files
        for (String mapped : Proc.mappedFiles(pid)) {
            String lower = mapped.toLowerCase(Locale.ROOT);
            boolean deleted = lower.contains("(deleted)");
            String path = mapped.replace(" (deleted)", "").trim();

            ctx.signatures().matchCheatName(lower).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.CRITICAL,
                                    "Библиотека чита в процессе CS2 / Cheat library mapped into CS2")
                            .module(ID).detail(rule.label()).evidence(path).source("maps pid " + pid).build()));

            if (deleted && (lower.endsWith(".so") || lower.contains(".so"))) {
                ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.HIGH,
                                "Удалённая библиотека загружена в CS2 / Deleted library loaded in CS2")
                        .module(ID)
                        .detail("Инъекция: библиотека удалена после загрузки")
                        .evidence(path + " (deleted)").source("maps pid " + pid).build());
            } else if ((lower.endsWith(".so") || lower.contains("/.so"))
                    && (lower.startsWith("/tmp/") || lower.startsWith("/dev/shm/")
                    || lower.contains("/downloads/") || lower.contains("/.cache/"))) {
                ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.HIGH,
                                "Подозрительная библиотека в CS2 / Suspicious library in CS2")
                        .module(ID)
                        .detail("Загружена из временной/пользовательской папки: " + path)
                        .evidence(path).source("maps pid " + pid).build());
            }
        }
        // LD_PRELOAD injection
        for (String env : Proc.environ(pid)) {
            if (env.startsWith("LD_PRELOAD=") && env.length() > "LD_PRELOAD=".length()) {
                ctx.emit(Finding.builder(Category.ENVIRONMENT, Severity.HIGH,
                                "LD_PRELOAD в процессе CS2 / LD_PRELOAD injection in CS2")
                        .module(ID)
                        .detail(env)
                        .evidence(env).source("environ pid " + pid).build());
            }
        }
    }
}

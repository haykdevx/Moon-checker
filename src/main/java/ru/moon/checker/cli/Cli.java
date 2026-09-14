package ru.moon.checker.cli;

import ru.moon.checker.checks.ModuleRegistry;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Hashing;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanEngine;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Severity;
import ru.moon.checker.report.HtmlReport;
import ru.moon.checker.report.JsonReport;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.win.WinInfo;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * Headless entry point. Two modes:
 *
 * <ul>
 *   <li>{@code --cli} — run a full inspection without a GUI and write the HTML
 *       report + JSON evidence bundle. Useful for scripted/remote checks and
 *       for admins who want an archive without driving the UI.</li>
 *   <li>{@code --selftest} — run every module with short time budgets and print
 *       a per-module status table. This is what CI executes on a real Windows
 *       runner so the Windows-only code paths (registry, MFT/USN, AmCache,
 *       ADS, kernel services) are actually exercised on every push.</li>
 * </ul>
 *
 * Exit codes: 0 = the engine produced a result; 1 = the engine itself failed, or
 * (selftest) every module failed, which means the platform layer is broken.
 */
public final class Cli {

    private Cli() {
    }

    public static boolean handles(String[] args) {
        for (String a : args) {
            if ("--cli".equals(a) || "--selftest".equals(a) || "--version".equals(a) || "--help".equals(a)) {
                return true;
            }
        }
        return false;
    }

    public static int run(String[] args, String appVersion) {
        boolean selftest = has(args, "--selftest");
        if (has(args, "--help")) {
            printHelp();
            return 0;
        }
        if (has(args, "--version")) {
            System.out.println("Moon Checker " + appVersion + " (" + Platform.osName() + ")");
            return 0;
        }

        boolean elevated = Platform.isWindows()
                ? WinInfo.isElevated()
                : ru.moon.checker.linux.LinuxInfo.isRoot();
        EnvironmentInfo env = EnvironmentInfo.capture(elevated, appVersion, Hashing.selfHashShort());
        SignatureLoader.Result sig = SignatureLoader.load(Path.of("."));
        SignatureDb db = sig.db();
        CheckId checkId = CheckId.generate();

        System.out.println("Moon Checker " + appVersion + "  |  " + Platform.osName()
                + "  |  elevated=" + elevated);
        System.out.println("Check " + checkId.value() + "  |  signatures " + sig.origin()
                + " v" + db.version() + " (" + db.ruleCount() + " rules)");
        System.out.println();

        java.util.List<CheckModule> modules = ModuleRegistry.forCurrentOs();
        ScanEngine engine = selftest
                ? new ScanEngine(modules, progress(), Duration.ofSeconds(90), Duration.ofMinutes(5))
                : new ScanEngine(modules, progress());

        ScanResult result;
        try {
            result = engine.run(db, checkId, env);
        } catch (Throwable t) {
            System.err.println("ENGINE FAILED: " + t);
            t.printStackTrace();
            return 1;
        }

        printSummary(result);

        if (!selftest) {
            writeReports(result, outDir(args));
        }
        return selftest ? selftestExit(result) : 0;
    }

    private static ScanListener progress() {
        return new ScanListener() {
            @Override
            public void onModuleDone(CheckModule m, ModuleStatus s, int findings) {
                System.out.printf("  %-14s %-8s %d finding(s)%n", m.id(), s.name(), findings);
            }
        };
    }

    private static void printSummary(ScanResult r) {
        System.out.println();
        System.out.println("VERDICT: " + r.verdict() + "   score " + r.score() + "/100"
                + "   (" + r.duration().toSeconds() + "s)");
        System.out.println("  CRITICAL=" + r.countBySeverity(Severity.CRITICAL)
                + " HIGH=" + r.countBySeverity(Severity.HIGH)
                + " MEDIUM=" + r.countBySeverity(Severity.MEDIUM)
                + " LOW=" + r.countBySeverity(Severity.LOW)
                + " INFO=" + r.countBySeverity(Severity.INFO));
        System.out.println("  verification " + JsonReport.verificationCode(r));
        for (Finding f : r.findings()) {
            if (f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH) {
                System.out.println("  [" + f.severity() + "] " + f.title()
                        + (f.evidence() == null ? "" : "  -> " + f.evidence()));
            }
        }
    }

    /** Fail CI only when the platform layer is comprehensively broken. */
    private static int selftestExit(ScanResult r) {
        long ok = r.moduleStatus().values().stream().filter(s -> s == ModuleStatus.OK).count();
        long bad = r.moduleStatus().values().stream()
                .filter(s -> s == ModuleStatus.ERROR || s == ModuleStatus.TIMEOUT).count();
        System.out.println();
        System.out.println("SELFTEST: ok=" + ok + " failed=" + bad
                + " of " + r.moduleStatus().size() + " modules");
        for (Map.Entry<String, ModuleStatus> e : r.moduleStatus().entrySet()) {
            if (e.getValue() == ModuleStatus.ERROR || e.getValue() == ModuleStatus.TIMEOUT) {
                System.out.println("  FAILED: " + e.getKey() + " -> " + e.getValue());
            }
        }
        if (ok == 0) {
            System.err.println("SELFTEST FAILED: no module completed successfully");
            return 1;
        }
        return 0;
    }

    private static void writeReports(ScanResult r, Path dir) {
        try {
            Files.createDirectories(dir);
            Path html = dir.resolve("MoonCheck-" + r.checkId().value() + ".html");
            Path json = dir.resolve("MoonCheck-" + r.checkId().value() + ".json");
            Files.write(html, HtmlReport.render(r).getBytes(StandardCharsets.UTF_8));
            Files.write(json, JsonReport.renderBytes(r));
            System.out.println();
            System.out.println("Report:   " + html.toAbsolutePath());
            System.out.println("Evidence: " + json.toAbsolutePath());
        } catch (Exception e) {
            System.err.println("could not write reports: " + e.getMessage());
        }
    }

    private static Path outDir(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("--out".equals(args[i])) {
                return Path.of(args[i + 1]);
            }
        }
        return Path.of(".");
    }

    private static boolean has(String[] args, String flag) {
        for (String a : args) {
            if (flag.equals(a)) {
                return true;
            }
        }
        return false;
    }

    private static void printHelp() {
        System.out.println("""
                Moon Checker — CS2 anti-cheat inspection (cs2-moon.ru)

                  (no arguments)     launch the desktop UI
                  --cli [--out DIR]  run a full inspection headless and write
                                     the HTML report and JSON evidence bundle
                  --selftest         run every module with short time budgets and
                                     print a per-module status table (used by CI)
                  --version          print version and exit
                  --help             this text

                Run as administrator (Windows) or root (Linux) for full coverage.""");
    }
}

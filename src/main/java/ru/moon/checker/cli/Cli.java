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
import ru.moon.checker.net.ApiException;
import ru.moon.checker.net.MoonApi;
import ru.moon.checker.net.ProgressReporter;
import ru.moon.checker.net.ReportUploader;
import ru.moon.checker.net.ServerConfig;
import ru.moon.checker.net.SessionLink;
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
 * With {@code --cli --code XXXX-XXXX} the headless run connects to the Moon panel
 * like the GUI does: it streams progress and uploads the evidence to the admin who
 * issued the code.
 *
 * Exit codes: 0 = the engine produced a result; 1 = the engine itself failed, or
 * (selftest) every module failed, which means the platform layer is broken;
 * 2 = bad arguments; 5 = the results could not be delivered to the panel.
 */
public final class Cli {

    public static final int EXIT_USAGE = 2;
    public static final int EXIT_NOT_DELIVERED = 5;

    private Cli() {
    }

    public static boolean handles(String[] args) {
        for (String a : args) {
            if ("--cli".equals(a) || "--selftest".equals(a) || "--version".equals(a)
                    || "--help".equals(a) || "--verify".equals(a)) {
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
        String verifyPath = valueOf(args, "--verify");
        if (verifyPath != null) {
            return verifyBundle(verifyPath);
        }
        if (has(args, "--version")) {
            System.out.println("Moon Checker " + appVersion + " (" + Platform.osName() + ")");
            return 0;
        }

        boolean elevated = Platform.isWindows()
                ? WinInfo.isElevated()
                : ru.moon.checker.linux.LinuxInfo.isRoot();
        EnvironmentInfo env = EnvironmentInfo.capture(elevated, appVersion, Hashing.selfHashShort());
        SignatureLoader.Result sig = SignatureLoader.load(ru.moon.checker.Main.exeDir());
        SignatureDb db = sig.db();
        CheckId checkId = CheckId.generate();

        System.out.println("Moon Checker " + appVersion + "  |  " + Platform.osName()
                + "  |  elevated=" + elevated);
        System.out.println("Check " + checkId.value() + "  |  signatures " + sig.origin()
                + " v" + db.version() + " (" + db.ruleCount() + " rules)");
        System.out.println();

        java.util.List<CheckModule> modules = selectModules(ModuleRegistry.forCurrentOs(), valueOf(args, "--modules"));
        if (modules == null) {
            return EXIT_USAGE;
        }

        // optional link to the Moon panel: --code (+ --server) connects before scanning
        String code = selftest ? null : valueOf(args, "--code");
        MoonApi api = null;
        SessionLink link = null;
        if (code != null) {
            ServerConfig server = ServerConfig.resolve(valueOf(args, "--server"), false,
                    ru.moon.checker.Main.exeDir());
            if (!server.online()) {
                System.err.println("no usable Moon panel URL: " + server.error());
                return EXIT_USAGE;
            }
            api = new MoonApi(server.base(), appVersion);
            try {
                link = api.claim(code, env);
            } catch (ApiException e) {
                System.err.println("panel refused the code: " + e.describe(server.host()));
                return EXIT_NOT_DELIVERED;
            }
            System.out.println("Connected to " + server.host() + " — admin " + link.adminAlias()
                    + (link.playerName().isBlank() ? "" : ", player " + link.playerName()));
            System.out.println();
        }
        ProgressReporter reporter = link == null ? null : new ProgressReporter(api, link, null);
        ScanListener listener = reporter == null ? progress() : both(progress(), reporter);

        ScanEngine engine = selftest
                ? new ScanEngine(modules, listener, Duration.ofSeconds(90), Duration.ofMinutes(5))
                : new ScanEngine(modules, listener);
        engine.rules(sig.provenance()).fullSuite(ModuleRegistry.forCurrentOs());
        if (sig.error() != null) {
            System.out.println("Rules: " + sig.error());
        }
        if (reporter != null) {
            reporter.start(modules.size());
        }

        ScanResult result;
        try {
            result = engine.run(db, checkId, env,
                    selftest ? ru.moon.checker.core.Consent.none() : ru.moon.checker.core.Consent.cli());
        } catch (Throwable t) {
            System.err.println("ENGINE FAILED: " + t);
            t.printStackTrace();
            return 1;
        } finally {
            if (reporter != null) {
                reporter.stop();
            }
        }

        printSummary(result);

        if (!selftest) {
            writeReports(result, outDir(args));
            String upload = valueOf(args, "--upload");
            if (upload != null) {
                var outcome = ru.moon.checker.report.Uploader.upload(
                        java.net.URI.create(upload), result);
                System.out.println("Upload: " + (outcome.ok() ? "accepted" : "FAILED")
                        + " (HTTP " + outcome.status() + ")");
            }
            if (link != null) {
                ReportUploader.Status st = ReportUploader.upload(api, link, result,
                        s -> System.out.println("Panel: " + s.text()));
                if (st.state() != ReportUploader.State.DELIVERED && st.state() != ReportUploader.State.MISMATCH) {
                    return EXIT_NOT_DELIVERED;
                }
            }
        }
        return selftest ? selftestExit(result) : 0;
    }

    /** Modules for this OS, narrowed to a comma-separated id list; null (after a message) if an id is unknown. */
    static java.util.List<CheckModule> selectModules(java.util.List<CheckModule> available, String only) {
        if (only == null || only.isBlank()) {
            return available;
        }
        java.util.List<String> ids = java.util.Arrays.stream(only.split(",")).map(String::trim)
                .filter(x -> !x.isEmpty()).toList();
        java.util.List<String> known = available.stream().map(CheckModule::id).toList();
        for (String id : ids) {
            if (!known.contains(id)) {
                System.err.println("unknown module id '" + id + "'; available: " + String.join(",", known));
                return null;
            }
        }
        return available.stream().filter(m -> ids.contains(m.id())).toList();
    }

    private static ScanListener both(ScanListener a, ScanListener b) {
        return new ScanListener() {
            @Override public void onScanStart(int t) { a.onScanStart(t); b.onScanStart(t); }
            @Override public void onModuleStart(CheckModule m) { a.onModuleStart(m); b.onModuleStart(m); }
            @Override public void onModuleDone(CheckModule m, ModuleStatus s, int n) {
                a.onModuleDone(m, s, n);
                b.onModuleDone(m, s, n);
            }
            @Override public void onFinding(Finding f) { a.onFinding(f); b.onFinding(f); }
            @Override public void onLog(String l) { a.onLog(l); b.onLog(l); }
            @Override public void onComplete(ScanResult r) { a.onComplete(r); b.onComplete(r); }
        };
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
        var cov = r.coverage();
        System.out.println("OUTCOME: " + r.verdict() + "   coverage " + cov.completed() + "/" + cov.required().size()
                + (cov.elevated() ? "" : " (not elevated)") + "   assurance " + r.assessment().assurance().level()
                + "   (" + r.duration().toSeconds() + "s)");
        System.out.println("  CRITICAL=" + r.countBySeverity(Severity.CRITICAL)
                + " HIGH=" + r.countBySeverity(Severity.HIGH)
                + " MEDIUM=" + r.countBySeverity(Severity.MEDIUM)
                + " LOW=" + r.countBySeverity(Severity.LOW)
                + " INFO=" + r.countBySeverity(Severity.INFO));
        System.out.println("  verification " + JsonReport.verificationCode(r));
        for (var reason : r.assessment().reasons()) {
            System.out.println("  - " + reason.text() + (reason.evidence().isEmpty() ? ""
                    : "  [" + String.join(",", reason.evidence().stream().map(i -> "E" + i).toList()) + "]"));
        }
        java.util.List<Finding> fs = r.findings();
        for (int i = 0; i < fs.size(); i++) {
            Finding f = fs.get(i);
            if (f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH) {
                System.out.println("  E" + (i + 1) + " [" + f.kind() + "/" + f.severity() + "] " + f.title()
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

    /** Verify a previously saved evidence bundle (offline, no server needed). */
    private static int verifyBundle(String path) {
        try {
            byte[] data = Files.readAllBytes(Path.of(path));
            var r = ru.moon.checker.report.EvidenceVerifier.verify(data);
            System.out.println("Evidence: " + path);
            System.out.println("  well-formed : " + r.wellFormed());
            System.out.println("  sha-256     : " + (r.hashOk() ? "OK" : "MISMATCH"));
            System.out.println("  hmac        : " + (r.hmacOk() ? "OK" : "MISMATCH"));
            System.out.println("  code        : " + r.code());
            System.out.println("  => " + r.detail());
            return r.authentic() ? 0 : 1;
        } catch (Exception e) {
            System.err.println("cannot read " + path + ": " + e.getMessage());
            return 1;
        }
    }

    private static String valueOf(String[] args, String flag) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) {
                return args[i + 1];
            }
        }
        return null;
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
                  --verify FILE.json verify a saved evidence bundle (offline):
                                     recomputes its hash + HMAC and reports
                                     whether it was modified
                  --upload URL       with --cli, also POST the evidence bundle
                                     to a collection endpoint (never automatic)
                  --code XXXX-XXXX   with --cli, connect to the Moon panel with the
                                     admin's check code, stream progress and deliver
                                     the results to that admin (exit 5 if not delivered)
                  --server URL       Moon panel URL (default: bundled, or server.url
                                     in moon.properties next to the exe)
                  --modules a,b      with --cli / --selftest: only these module ids
                  --offline          GUI: never contact the Moon panel
                  --version          print version and exit
                  --help             this text

                Run as administrator (Windows) or root (Linux) for full coverage.""");
    }
}

package ru.moon.checker.cli;

import ru.moon.checker.checks.ModuleRegistry;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanEngine;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.net.ApiException;
import ru.moon.checker.net.MoonApi;
import ru.moon.checker.net.ProgressReporter;
import ru.moon.checker.net.ReportUploader;
import ru.moon.checker.net.ServerConfig;
import ru.moon.checker.net.SessionLink;
import ru.moon.checker.report.HtmlReport;
import ru.moon.checker.report.JsonReport;
import ru.moon.checker.signatures.SignatureDb;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Runs the normal scan engine without any UI: live progress to the console,
 * the JSON evidence bundle and HTML report to {@code --out}. Used by the Windows
 * CI smoke job and for scripted test-machine runs. With {@code --code} it also
 * connects to the Moon panel, streams progress and uploads the evidence.
 */
public final class HeadlessScan {

    public static final int EXIT_OK = 0;
    public static final int EXIT_MODULE_FAILED = 3;
    public static final int EXIT_NOT_DELIVERED = 5;

    private HeadlessScan() {
    }

    /** Modules for this OS, narrowed to {@code only} when non-empty; null if an id is unknown. */
    static List<CheckModule> select(List<CheckModule> available, List<String> only, PrintStream err) {
        if (only.isEmpty()) {
            return available;
        }
        List<String> known = available.stream().map(CheckModule::id).toList();
        for (String id : only) {
            if (!known.contains(id)) {
                err.println("unknown module id '" + id + "'; available: " + String.join(",", known));
                return null;
            }
        }
        return available.stream().filter(m -> only.contains(m.id())).toList();
    }

    public static int run(CliArgs args, EnvironmentInfo env, SignatureDb db, ServerConfig server, PrintStream out)
            throws Exception {
        List<CheckModule> modules = select(ModuleRegistry.forCurrentOs(), args.moduleList(), out);
        if (modules == null) {
            return 2;
        }
        Files.createDirectories(args.out());

        MoonApi api = null;
        SessionLink link = null;
        if (args.code() != null) {
            api = new MoonApi(server.base(), env.appVersion());
            try {
                link = api.claim(args.code(), env);
            } catch (ApiException e) {
                out.println("panel refused the code: " + e.describe(server.host()));
                return EXIT_NOT_DELIVERED;
            }
            out.println("connected to " + server.host() + " — admin " + link.adminAlias()
                    + (link.playerName().isBlank() ? "" : ", player " + link.playerName()));
        }

        CheckId id = CheckId.generate();
        out.println("Moon Checker " + env.appVersion() + " headless scan " + id.value()
                + " | elevated=" + env.elevated() + " | " + env.osName() + " | signatures v" + db.version());

        ProgressReporter reporter = link == null ? null : new ProgressReporter(api, link, null);
        ScanListener listener = new ScanListener() {
            @Override
            public void onScanStart(int total) {
                if (reporter != null) reporter.onScanStart(total);
            }

            @Override
            public void onModuleStart(CheckModule m) {
                if (reporter != null) reporter.onModuleStart(m);
            }

            @Override
            public void onModuleDone(CheckModule m, ModuleStatus s, int n) {
                out.printf("  [%-8s] %-14s findings=%d%n", s.name(), m.id(), n);
                if (reporter != null) reporter.onModuleDone(m, s, n);
            }

            @Override
            public void onFinding(Finding f) {
                out.printf("    %-8s %s | %s%n", f.severity(), f.title(), f.evidence() == null ? "" : f.evidence());
                if (reporter != null) reporter.onFinding(f);
            }
        };
        if (reporter != null) {
            reporter.start(modules.size());
        }
        ScanResult r = new ScanEngine(modules, listener).run(db, id, env);
        if (reporter != null) {
            reporter.stop();
        }

        Path json = args.out().resolve("MoonCheck-" + id.value() + ".json");
        Path html = args.out().resolve("MoonCheck-" + id.value() + ".html");
        Files.write(json, JsonReport.renderBytes(r));
        Files.writeString(html, HtmlReport.render(r), StandardCharsets.UTF_8);

        String failed = r.moduleStatus().entrySet().stream()
                .filter(e -> e.getValue() == ModuleStatus.ERROR || e.getValue() == ModuleStatus.TIMEOUT)
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(", "));
        out.println("verdict=" + r.verdict() + " score=" + r.score() + " findings=" + r.findings().size()
                + " duration=" + r.duration().toSeconds() + "s code=" + JsonReport.verificationCode(r));
        out.println("reports: " + json.toAbsolutePath() + " , " + html.toAbsolutePath());
        if (link != null) {
            ReportUploader.Status st = ReportUploader.upload(api, link, r, s -> out.println("  upload: " + s.text()));
            if (st.state() != ReportUploader.State.DELIVERED && st.state() != ReportUploader.State.MISMATCH) {
                return EXIT_NOT_DELIVERED;
            }
        }
        if (!failed.isEmpty()) {
            out.println("modules not completed: " + failed);
            return EXIT_MODULE_FAILED;
        }
        return EXIT_OK;
    }
}

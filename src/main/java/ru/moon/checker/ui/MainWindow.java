package ru.moon.checker.ui;

import ru.moon.checker.checks.ModuleRegistry;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Log;
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
import ru.moon.checker.signatures.SignatureDb;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.CardLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Top-level window. Owns the persistent {@link HeaderBar} and a card stack of
 * the three screens (start → scan → results). With a panel configured it also
 * links the run to the admin's check code, streams live progress while the
 * scan runs and delivers the evidence bundle when it finishes.
 */
public final class MainWindow extends JFrame {

    private final EnvironmentInfo env;
    private final SignatureDb signatures;
    private final ServerConfig server;
    private final MoonApi api;
    private final List<CheckModule> modules = ModuleRegistry.forCurrentOs();

    private CheckId checkId;
    private HeaderBar header;
    private JPanel cards;
    private CardLayout cardLayout;
    private StartPanel startPanel;
    private ResultsPanel resultsPanel;
    private ScanResult lastResult;
    private SessionLink link;
    private volatile ReportUploader.Status uploadStatus;
    private volatile boolean busy;

    private final ru.moon.checker.core.RulesProvenance rules;

    public MainWindow(EnvironmentInfo env, SignatureDb signatures, ru.moon.checker.core.RulesProvenance rules,
                      ServerConfig server) {
        super("Moon Checker");
        this.env = env;
        this.signatures = signatures;
        this.rules = rules;
        this.server = server;
        this.api = server.online() ? new MoonApi(server.base(), env.appVersion()) : null;
        this.checkId = CheckId.generate();
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                confirmClose();
            }
        });
        WindowFit.Fit fit = WindowFit.fit(WindowFit.PREFERRED, WindowFit.MINIMUM, WindowFit.usableScreen());
        setMinimumSize(fit.minimum());
        setSize(fit.size());
        setLocationRelativeTo(null);
        if (fit.maximize()) {
            setExtendedState(getExtendedState() | MAXIMIZED_BOTH);
        }
        build();
    }

    private void build() {
        getContentPane().removeAll();
        header = new HeaderBar(env, checkId, this::onLanguageChange);
        cardLayout = new CardLayout();
        cards = new JPanel(cardLayout);
        cards.setBackground(MoonTheme.BG);

        startPanel = new StartPanel(env, api != null, new StartPanel.Actions() {
            @Override
            public void onStart() {
                startScan();
            }

            @Override
            public void onRelaunchElevated() {
                Elevation.relaunchElevated();
            }

            @Override
            public void onConnect(String code) {
                connect(code);
            }
        });
        cards.add(startPanel, "start");
        setLayout(new java.awt.BorderLayout());
        add(header, java.awt.BorderLayout.NORTH);
        add(cards, java.awt.BorderLayout.CENTER);
        cardLayout.show(cards, "start");
        revalidate();
        repaint();
    }

    private void connect(String code) {
        Thread t = new Thread(() -> {
            try {
                SessionLink l = api.claim(code, env);
                Log.info("connected to panel " + server.host() + ": " + l);
                SwingUtilities.invokeLater(() -> {
                    link = l;
                    startPanel.setConnected(l);
                });
            } catch (ApiException e) {
                Log.warn("code rejected / panel unreachable: " + e.getMessage());
                SwingUtilities.invokeLater(() -> startPanel.setConnectFailed(e.describe(server.host())));
            }
        }, "moon-connect");
        t.setDaemon(true);
        t.start();
    }

    private void startScan() {
        // pressing Start after the notice (start.privacy*) is the player's consent; it goes into the report
        final ru.moon.checker.core.Consent consent = ru.moon.checker.core.Consent.gui();
        if (api != null && link == null) {
            return; // the start button is disabled until connected; belt and braces
        }
        busy = true;
        AtomicReference<ScanEngine> engineRef = new AtomicReference<>();
        ScanPanel scanPanel = new ScanPanel(modules, () -> {
            ScanEngine e = engineRef.get();
            if (e != null) {
                e.cancel();
            }
        });
        cards.add(scanPanel, "scan");
        cardLayout.show(cards, "scan");

        ProgressReporter reporter = link == null ? null : new ProgressReporter(api, link, () -> {
            ScanEngine e = engineRef.get();
            if (e != null) {
                e.cancel();
            }
            scanPanel.onLog(I18n.t("scan.server.cancelled"));
        });

        ScanListener listener = new ScanListener() {
            @Override public void onScanStart(int t) {
                scanPanel.onScanStart(t);
                if (reporter != null) reporter.onScanStart(t);
            }
            @Override public void onModuleStart(CheckModule m) {
                scanPanel.onModuleStart(m);
                if (reporter != null) reporter.onModuleStart(m);
            }
            @Override public void onModuleDone(CheckModule m, ModuleStatus s, int n) {
                scanPanel.onModuleDone(m, s, n);
                if (reporter != null) reporter.onModuleDone(m, s, n);
            }
            @Override public void onLog(String l) { scanPanel.onLog(l); }
            @Override public void onFinding(Finding f) {
                scanPanel.onFinding(f);
                if (reporter != null) reporter.onFinding(f);
            }
            @Override public void onComplete(ScanResult r) {
                scanPanel.onComplete(r);
            }
        };

        ScanEngine engine = new ScanEngine(modules, listener).rules(rules);
        engineRef.set(engine);
        if (reporter != null) {
            reporter.start(modules.size());
        }
        Thread worker = new Thread(() -> {
            try {
                ScanResult r = engine.run(signatures, checkId, env, consent);
                if (reporter != null) {
                    reporter.stop();
                }
                uploadStatus = link == null ? ReportUploader.offline() : null;
                SwingUtilities.invokeLater(() -> showResults(r));
                if (link != null && (reporter == null || !reporter.cancelledByServer())) {
                    deliver(r);
                } else if (link != null) {
                    applyUpload(new ReportUploader.Status(ReportUploader.State.FAILED,
                            I18n.t("upload.failed", I18n.t("net.err.cancelled"))));
                }
            } catch (Throwable t) {
                Log.error("scan crashed", t);
            } finally {
                busy = false;
            }
        }, "moon-scan");
        worker.setDaemon(true);
        worker.start();
    }

    /** Blocking upload with retries; safe to call again from "Retry". */
    private void deliver(ScanResult r) {
        busy = true;
        try {
            ReportUploader.upload(api, link, r, this::applyUpload);
        } finally {
            busy = false;
        }
    }

    private void applyUpload(ReportUploader.Status s) {
        uploadStatus = s;
        SwingUtilities.invokeLater(() -> {
            if (resultsPanel != null) {
                resultsPanel.setUploadStatus(s);
            }
        });
    }

    private void retryUpload() {
        ScanResult r = lastResult;
        if (r == null || link == null) {
            return;
        }
        Thread t = new Thread(() -> deliver(r), "moon-upload");
        t.setDaemon(true);
        t.start();
    }

    private void showResults(ScanResult result) {
        this.lastResult = result;
        resultsPanel = new ResultsPanel(result, this::reset, this::retryUpload,
                link != null ? link.statusUrl() : null);
        if (uploadStatus != null) {
            resultsPanel.setUploadStatus(uploadStatus);
        }
        cards.add(resultsPanel, "results");
        cardLayout.show(cards, "results");
    }

    private void reset() {
        if (busy) {
            return;
        }
        this.checkId = CheckId.generate();
        this.lastResult = null;
        this.resultsPanel = null;
        this.uploadStatus = null;
        this.link = null; // a code is single-use: the next check needs a new one
        build();
    }

    private void confirmClose() {
        if (busy) {
            int answer = JOptionPane.showConfirmDialog(this, I18n.t("close.confirm"), "Moon Checker",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (answer != JOptionPane.YES_OPTION) {
                return;
            }
        }
        dispose();
        System.exit(0);
    }

    private void onLanguageChange() {
        setTitle("Moon Checker — " + I18n.t("app.subtitle"));
        header.refreshTexts();
        if (lastResult != null) {
            showResults(lastResult);
        } else if (startPanel != null) {
            startPanel.refreshTexts();
        }
        revalidate();
        repaint();
    }
}

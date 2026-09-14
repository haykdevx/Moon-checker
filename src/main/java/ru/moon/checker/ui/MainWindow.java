package ru.moon.checker.ui;

import ru.moon.checker.checks.ModuleRegistry;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanEngine;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Finding;
import ru.moon.checker.signatures.SignatureDb;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.CardLayout;
import java.util.List;

/**
 * Top-level window. Owns the persistent {@link HeaderBar} and a card stack of
 * the three screens (start → scan → results) and drives a scan on a background
 * thread, streaming progress to {@link ScanPanel} and switching to
 * {@link ResultsPanel} on completion.
 */
public final class MainWindow extends JFrame {

    private final EnvironmentInfo env;
    private final SignatureDb signatures;
    private final List<CheckModule> modules = ModuleRegistry.forCurrentOs();

    private CheckId checkId;
    private HeaderBar header;
    private JPanel cards;
    private CardLayout cardLayout;
    private StartPanel startPanel;
    private ScanResult lastResult;

    public MainWindow(EnvironmentInfo env, SignatureDb signatures) {
        super("Moon Checker");
        this.env = env;
        this.signatures = signatures;
        this.checkId = CheckId.generate();
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setMinimumSize(new java.awt.Dimension(1000, 680));
        setSize(1180, 780);
        setLocationRelativeTo(null);
        build();
    }

    private void build() {
        getContentPane().removeAll();
        header = new HeaderBar(env, checkId, this::onLanguageChange);
        cardLayout = new CardLayout();
        cards = new JPanel(cardLayout);
        cards.setBackground(MoonTheme.BG);

        startPanel = new StartPanel(env, new StartPanel.Actions() {
            @Override
            public void onStart() {
                startScan();
            }

            @Override
            public void onRelaunchElevated() {
                Elevation.relaunchElevated();
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

    private void startScan() {
        java.util.concurrent.atomic.AtomicReference<ScanEngine> engineRef = new java.util.concurrent.atomic.AtomicReference<>();
        ScanPanel scanPanel = new ScanPanel(modules, () -> {
            ScanEngine e = engineRef.get();
            if (e != null) {
                e.cancel();
            }
        });
        cards.add(scanPanel, "scan");
        cardLayout.show(cards, "scan");

        ScanListener listener = new ScanListener() {
            @Override public void onScanStart(int t) { scanPanel.onScanStart(t); }
            @Override public void onModuleStart(CheckModule m) { scanPanel.onModuleStart(m); }
            @Override public void onModuleDone(CheckModule m, ModuleStatus s, int n) { scanPanel.onModuleDone(m, s, n); }
            @Override public void onLog(String l) { scanPanel.onLog(l); }
            @Override public void onFinding(Finding f) { scanPanel.onFinding(f); }
            @Override public void onComplete(ScanResult r) {
                scanPanel.onComplete(r);
                SwingUtilities.invokeLater(() -> showResults(r));
            }
        };

        ScanEngine engine = new ScanEngine(modules, listener);
        engineRef.set(engine);
        Thread worker = new Thread(() -> {
            try {
                engine.run(signatures, checkId, env);
            } catch (Throwable t) {
                ru.moon.checker.core.Log.error("scan crashed", t);
            }
        }, "moon-scan");
        worker.setDaemon(true);
        worker.start();
    }

    private void showResults(ScanResult result) {
        this.lastResult = result;
        ResultsPanel resultsPanel = new ResultsPanel(result, this::reset);
        cards.add(resultsPanel, "results");
        cardLayout.show(cards, "results");
    }

    private void reset() {
        this.checkId = CheckId.generate();
        this.lastResult = null;
        build();
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

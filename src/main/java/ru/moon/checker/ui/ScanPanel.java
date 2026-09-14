package ru.moon.checker.ui;

import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.ScanResult;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The live scan screen: one row per module with a colour-coded status, an
 * overall progress bar, and a scrolling log of what is being inspected right
 * now — so the admin watching the screen share can see the tool working.
 * Implements {@link ScanListener}; every callback marshals onto the EDT.
 */
public final class ScanPanel extends JPanel implements ScanListener {

    private final Map<String, JLabel> statusLabels = new HashMap<>();
    private final Map<String, JLabel> findLabels = new HashMap<>();
    private final JProgressBar progress = new JProgressBar();
    private final JTextArea log = new JTextArea();
    private final JLabel heading = new JLabel();
    private final AtomicInteger done = new AtomicInteger();
    private final int total;
    private final javax.swing.JButton cancel = new javax.swing.JButton();

    public ScanPanel(List<CheckModule> modules, Runnable onCancel) {
        this.total = modules.size();
        setBackground(MoonTheme.BG);
        setLayout(new BorderLayout(0, 14));
        setBorder(BorderFactory.createEmptyBorder(22, 26, 22, 26));

        heading.setFont(MoonTheme.font(Font.BOLD, 18)); // body font: heading can be Cyrillic
        heading.setForeground(MoonTheme.TEXT);
        heading.setText(I18n.t("scan.running"));
        add(heading, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(16, 0));
        center.setOpaque(false);
        center.add(modulesPanel(modules), BorderLayout.WEST);
        center.add(logPanel(), BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);

        progress.setMinimum(0);
        progress.setMaximum(total);
        progress.setStringPainted(true);
        progress.setForeground(MoonTheme.ACCENT);
        progress.setPreferredSize(new Dimension(0, 22));

        cancel.setText(I18n.t("scan.cancel"));
        cancel.setFont(MoonTheme.font(Font.PLAIN, 12));
        cancel.addActionListener(e -> {
            cancel.setEnabled(false);
            if (onCancel != null) {
                onCancel.run();
            }
        });
        JPanel south = new JPanel(new BorderLayout(12, 0));
        south.setOpaque(false);
        south.add(progress, BorderLayout.CENTER);
        south.add(cancel, BorderLayout.EAST);
        add(south, BorderLayout.SOUTH);
    }

    private JScrollPane modulesPanel(List<CheckModule> modules) {
        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setBackground(MoonTheme.PANEL);
        list.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        for (CheckModule m : modules) {
            list.add(moduleRow(m));
        }
        JScrollPane sp = new JScrollPane(list);
        sp.setPreferredSize(new Dimension(430, 0));
        sp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));
        return sp;
    }

    private JPanel moduleRow(CheckModule m) {
        JPanel row = new JPanel(new BorderLayout(10, 0));
        row.setBackground(MoonTheme.PANEL);
        row.setBorder(BorderFactory.createEmptyBorder(9, 12, 9, 12));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));

        JLabel name = new JLabel(m.displayName());
        name.setForeground(MoonTheme.TEXT);
        name.setFont(MoonTheme.font(Font.PLAIN, 13));

        JLabel status = new JLabel(I18n.t(ModuleStatus.PENDING.key()));
        status.setForeground(MoonTheme.MUTED);
        status.setFont(MoonTheme.font(Font.BOLD, 12));

        JLabel finds = new JLabel("");
        finds.setForeground(MoonTheme.MUTED);
        finds.setFont(new Font("Consolas", Font.PLAIN, 12));

        JPanel right = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 10, 0));
        right.setOpaque(false);
        right.add(finds);
        right.add(status);

        row.add(name, BorderLayout.CENTER);
        row.add(right, BorderLayout.EAST);
        statusLabels.put(m.id(), status);
        findLabels.put(m.id(), finds);
        return row;
    }

    private JScrollPane logPanel() {
        log.setEditable(false);
        log.setBackground(MoonTheme.PANEL2);
        log.setForeground(new Color(0xc8, 0xcc, 0xd6));
        log.setFont(new Font("Consolas", Font.PLAIN, 12));
        log.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        JScrollPane sp = new JScrollPane(log);
        sp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));
        return sp;
    }

    // ---- ScanListener (worker threads) -----------------------------------

    @Override
    public void onModuleStart(CheckModule module) {
        setStatus(module.id(), ModuleStatus.RUNNING);
    }

    @Override
    public void onModuleDone(CheckModule module, ModuleStatus status, int findingCount) {
        SwingUtilities.invokeLater(() -> {
            applyStatus(module.id(), status);
            JLabel f = findLabels.get(module.id());
            if (f != null && findingCount > 0) {
                f.setText(findingCount + "⚑");
                f.setForeground(MoonTheme.CHEAT);
            }
            int d = done.incrementAndGet();
            progress.setValue(d);
            progress.setString(d + " / " + total);
        });
    }

    @Override
    public void onLog(String line) {
        SwingUtilities.invokeLater(() -> {
            log.append(line + "\n");
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    @Override
    public void onFinding(Finding finding) {
        // module counters + results table carry the detail; keep the log clean
    }

    @Override
    public void onComplete(ScanResult result) {
        SwingUtilities.invokeLater(() -> {
            progress.setValue(total);
            progress.setString(I18n.t("scan.done"));
        });
    }

    private void setStatus(String id, ModuleStatus s) {
        SwingUtilities.invokeLater(() -> applyStatus(id, s));
    }

    private void applyStatus(String id, ModuleStatus s) {
        JLabel l = statusLabels.get(id);
        if (l == null) {
            return;
        }
        l.setText(I18n.t(s.key()));
        l.setForeground(switch (s) {
            case OK -> MoonTheme.CLEAN;
            case RUNNING -> MoonTheme.ACCENT;
            case ERROR, TIMEOUT -> MoonTheme.CHEAT;
            case SKIPPED -> MoonTheme.MUTED;
            default -> MoonTheme.MUTED;
        });
    }
}

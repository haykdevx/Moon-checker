package ru.moon.checker.ui;

import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.ScanResult;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The live scan screen — what the admin watches over the screen share. A
 * progress ring, the module list with per-module status and duration, and a
 * colour-coded log of what is being inspected right now.
 */
public final class ScanPanel extends JPanel implements ScanListener {

    private final Map<String, ModuleRow> rows = new HashMap<>();
    private final Map<String, Long> moduleStart = new ConcurrentHashMap<>();
    /** Per collector: [0] findings that can change the outcome, [1] context and settings notes. */
    private final Map<String, java.util.concurrent.atomic.AtomicIntegerArray> counts = new ConcurrentHashMap<>();
    private final JTextPane log = new JTextPane();
    private final JLabel elapsed = new JLabel();
    private final JLabel current = new JLabel();
    private final ArcGauge ring;
    private final AtomicInteger done = new AtomicInteger();
    private final long startedAt = System.currentTimeMillis();
    private final int total;

    public ScanPanel(List<CheckModule> modules, Runnable onCancel) {
        this.total = modules.size();
        this.ring = new ArcGauge(104, 8, MoonTheme.ACCENT, MoonTheme.ACCENT2, 0, total, "/ " + total);
        setOpaque(true);
        setLayout(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(18, 24, 18, 24));

        add(hero(onCancel), BorderLayout.NORTH);
        add(body(modules), BorderLayout.CENTER);

        Timer clock = new Timer(500, e -> updateElapsed());
        clock.setInitialDelay(0);
        clock.start();
        updateElapsed();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        MoonBackground.paintQuiet(g2, getWidth(), getHeight());
        g2.dispose();
    }

    private JComponent hero(Runnable onCancel) {
        JPanel hero = new JPanel(new BorderLayout(22, 0));
        hero.setOpaque(false);
        hero.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        hero.add(ring, BorderLayout.WEST);

        JPanel mid = new JPanel();
        mid.setOpaque(false);
        mid.setLayout(new BoxLayout(mid, BoxLayout.Y_AXIS));
        JLabel heading = new JLabel(I18n.t("scan.running"));
        heading.setFont(MoonTheme.font(Font.BOLD, 22));
        heading.setForeground(MoonTheme.TEXT);
        heading.setAlignmentX(Component.LEFT_ALIGNMENT);
        current.setFont(MoonTheme.font(Font.PLAIN, 12));
        current.setForeground(MoonTheme.MUTED);
        current.setAlignmentX(Component.LEFT_ALIGNMENT);
        mid.add(javax.swing.Box.createVerticalGlue());
        mid.add(heading);
        mid.add(javax.swing.Box.createVerticalStrut(6));
        mid.add(current);
        mid.add(javax.swing.Box.createVerticalGlue());
        hero.add(mid, BorderLayout.CENTER);

        JPanel right = new JPanel();
        right.setOpaque(false);
        right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));
        elapsed.setFont(MoonTheme.mono(Font.BOLD, 22)); // Orbitron loses digits in JLabels
        elapsed.setForeground(MoonTheme.TEXT);
        elapsed.setAlignmentX(Component.RIGHT_ALIGNMENT);
        JLabel elapsedCaption = new JLabel(I18n.t("scan.elapsedCaption"));
        elapsedCaption.setFont(MoonTheme.font(Font.PLAIN, 10));
        elapsedCaption.setForeground(MoonTheme.MUTED2);
        elapsedCaption.setAlignmentX(Component.RIGHT_ALIGNMENT);
        MoonButton cancel = new MoonButton(I18n.t("scan.cancel"), false);
        cancel.setAlignmentX(Component.RIGHT_ALIGNMENT);
        cancel.addActionListener(e -> {
            cancel.setEnabled(false);
            if (onCancel != null) {
                onCancel.run();
            }
        });
        right.add(javax.swing.Box.createVerticalGlue());
        right.add(elapsed);
        right.add(elapsedCaption);
        right.add(javax.swing.Box.createVerticalStrut(8));
        right.add(cancel);
        right.add(javax.swing.Box.createVerticalGlue());
        hero.add(right, BorderLayout.EAST);
        return hero;
    }

    private JComponent body(List<CheckModule> modules) {
        JPanel list = new JPanel();
        list.setOpaque(false);
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        for (CheckModule m : modules) {
            ModuleRow row = new ModuleRow(m.displayName());
            rows.put(m.id(), row);
            list.add(row);
        }
        JPanel listCard = card();
        listCard.setLayout(new BorderLayout());
        listCard.add(scroll(list), BorderLayout.CENTER);
        listCard.setPreferredSize(new Dimension(470, 10));

        log.setEditable(false);
        log.setOpaque(false);
        log.setFont(MoonTheme.mono(Font.PLAIN, 11));
        log.setBorder(BorderFactory.createEmptyBorder(10, 14, 10, 14));

        JPanel logCard = card();
        logCard.setLayout(new BorderLayout());
        logCard.add(logHeader(), BorderLayout.NORTH);
        logCard.add(scroll(log), BorderLayout.CENTER);

        JPanel split = new JPanel(new BorderLayout(14, 0));
        split.setOpaque(false);
        split.add(listCard, BorderLayout.WEST);
        split.add(logCard, BorderLayout.CENTER);
        return split;
    }

    private JComponent logHeader() {
        JPanel h = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 9, 8));
        h.setOpaque(false);
        h.add(new LiveDot());
        JLabel label = new JLabel("LIVE LOG");
        label.setFont(MoonTheme.display(Font.PLAIN, 10));
        label.setForeground(MoonTheme.MUTED2);
        h.add(label);
        return h;
    }

    private static final class LiveDot extends JComponent {
        LiveDot() {
            setPreferredSize(new Dimension(9, 9));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(new Color(0x37, 0xd6, 0x7a, 70));
            g2.fillOval(0, 0, 9, 9);
            g2.setColor(MoonTheme.CLEAN);
            g2.fillOval(2, 2, 5, 5);
            g2.dispose();
        }
    }

    private JPanel card() {
        return new JPanel() {
            {
                setOpaque(false);
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(0x14, 0x17, 0x22, 205));
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 13, 13);
                g2.setColor(MoonTheme.LINE);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 13, 13);
                g2.dispose();
            }
        };
    }

    private JScrollPane scroll(Component view) {
        JScrollPane sp = new JScrollPane(view);
        sp.setOpaque(false);
        sp.getViewport().setOpaque(false);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getVerticalScrollBar().setUnitIncrement(18);
        return sp;
    }

    /** One module: status mark, name, finding count and duration. */
    private static final class ModuleRow extends JPanel {
        private ModuleStatus status = ModuleStatus.PENDING;
        private final JLabel name;
        private final JLabel meta = new JLabel();

        ModuleRow(String displayName) {
            setOpaque(false);
            setLayout(new BorderLayout(10, 0));
            setBorder(BorderFactory.createEmptyBorder(8, 40, 8, 14));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
            name = new JLabel(displayName);
            name.setFont(MoonTheme.font(Font.PLAIN, 12));
            name.setForeground(MoonTheme.FAINT);
            meta.setFont(MoonTheme.mono(Font.PLAIN, 10));
            meta.setForeground(MoonTheme.MUTED2);
            meta.setHorizontalAlignment(JLabel.RIGHT);
            add(name, BorderLayout.CENTER);
            add(meta, BorderLayout.EAST);
        }

        void set(ModuleStatus status, String metaText, boolean flagged) {
            this.status = status;
            name.setForeground(switch (status) {
                case OK -> MoonTheme.TEXT2;
                case RUNNING -> MoonTheme.TEXT;
                case ERROR, TIMEOUT -> MoonTheme.CHEAT;
                case SKIPPED -> MoonTheme.GHOST;
                default -> MoonTheme.FAINT;
            });
            name.setFont(MoonTheme.font(status == ModuleStatus.RUNNING ? Font.BOLD : Font.PLAIN, 12));
            meta.setText(metaText);
            meta.setForeground(flagged ? MoonTheme.CHEAT : MoonTheme.MUTED2);
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int cy = getHeight() / 2;
            if (status == ModuleStatus.RUNNING) {
                g2.setColor(new Color(0x6f, 0x78, 0xef, 32));
                g2.fillRoundRect(6, 3, getWidth() - 12, getHeight() - 6, 9, 9);
                g2.setColor(new Color(0x6f, 0x78, 0xef, 90));
                g2.drawRoundRect(6, 3, getWidth() - 12, getHeight() - 6, 9, 9);
            } else if (status == ModuleStatus.OK) {
                g2.setColor(new Color(0x37, 0xd6, 0x7a, 14));
                g2.fillRoundRect(6, 3, getWidth() - 12, getHeight() - 6, 9, 9);
            }
            int x = 18;
            switch (status) {
                case OK -> {
                    g2.setColor(MoonTheme.CLEAN);
                    g2.setStroke(new java.awt.BasicStroke(2.2f, java.awt.BasicStroke.CAP_ROUND,
                            java.awt.BasicStroke.JOIN_ROUND));
                    g2.drawPolyline(new int[]{x, x + 4, x + 11}, new int[]{cy, cy + 5, cy - 5}, 3);
                }
                case RUNNING -> {
                    g2.setColor(MoonTheme.ACCENT2);
                    g2.setStroke(new java.awt.BasicStroke(2.2f, java.awt.BasicStroke.CAP_ROUND,
                            java.awt.BasicStroke.JOIN_ROUND));
                    g2.drawArc(x, cy - 6, 12, 12, 40, 260);
                }
                case ERROR, TIMEOUT -> {
                    g2.setColor(MoonTheme.CHEAT);
                    g2.setStroke(new java.awt.BasicStroke(2.2f, java.awt.BasicStroke.CAP_ROUND,
                            java.awt.BasicStroke.JOIN_ROUND));
                    g2.drawLine(x + 1, cy - 5, x + 11, cy + 5);
                    g2.drawLine(x + 11, cy - 5, x + 1, cy + 5);
                }
                case SKIPPED -> {
                    g2.setColor(MoonTheme.GHOST);
                    g2.drawLine(x + 1, cy, x + 11, cy);
                }
                default -> {
                    g2.setColor(MoonTheme.LINE2);
                    g2.setStroke(new java.awt.BasicStroke(2f));
                    g2.drawOval(x, cy - 6, 12, 12);
                }
            }
            g2.dispose();
        }
    }

    // ---- ScanListener ----------------------------------------------------

    @Override
    public void onModuleStart(CheckModule module) {
        moduleStart.put(module.id(), System.currentTimeMillis());
        SwingUtilities.invokeLater(() -> {
            ModuleRow row = rows.get(module.id());
            if (row != null) {
                row.set(ModuleStatus.RUNNING, "", false);
                // at 150 % the list is taller than its pane: keep the running part in view
                row.scrollRectToVisible(new java.awt.Rectangle(0, 0, row.getWidth(), row.getHeight()));
            }
            current.setText(module.displayName());
        });
    }

    @Override
    public void onModuleDone(CheckModule module, ModuleStatus status, int findingCount) {
        Long began = moduleStart.get(module.id());
        long tookMs = began == null ? -1 : System.currentTimeMillis() - began;
        SwingUtilities.invokeLater(() -> {
            ModuleRow row = rows.get(module.id());
            if (row != null) {
                // red only for what can change the outcome; context notes ("CS2 is not running")
                // are counted separately in grey so the admin watching the screen is not misled
                var c = counts.getOrDefault(module.id(), new java.util.concurrent.atomic.AtomicIntegerArray(2));
                int evidence = c.get(0), notes = Math.max(c.get(1), findingCount - evidence);
                StringBuilder meta = new StringBuilder();
                if (evidence > 0) {
                    meta.append(I18n.plural("scan.evidence", evidence)).append("   ");
                } else if (notes > 0) {
                    meta.append(I18n.plural("scan.notes", notes)).append("   ");
                }
                if (tookMs >= 0) {
                    meta.append(tookMs >= 1000 ? String.format("%.1fs", tookMs / 1000.0) : tookMs + "ms");
                }
                row.set(status, meta.toString(), evidence > 0);
            }
            int d = done.incrementAndGet();
            ring.setValue(d, total, "/ " + total);
        });
    }

    @Override
    public void onLog(String line) {
        SwingUtilities.invokeLater(() -> {
            StyledDocument doc = log.getStyledDocument();
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, MoonTheme.MUTED2);
            try {
                doc.insertString(doc.getLength(), line + "\n", attrs);
                log.setCaretPosition(doc.getLength());
            } catch (Exception ignored) {
                // never let logging break the scan
            }
        });
    }

    @Override
    public void onFinding(Finding finding) {
        // per-collector counters; the results screen carries the detail
        if (finding.module() != null) {
            counts.computeIfAbsent(finding.module(), k -> new java.util.concurrent.atomic.AtomicIntegerArray(2))
                    .incrementAndGet(finding.movesOutcome() ? 0 : 1);
        }
    }

    @Override
    public void onComplete(ScanResult result) {
        SwingUtilities.invokeLater(() -> {
            ring.setValue(total, total, "/ " + total);
            current.setText(I18n.t("scan.done"));
        });
    }

    private void updateElapsed() {
        long s = (System.currentTimeMillis() - startedAt) / 1000;
        elapsed.setText(String.format("%d:%02d", s / 60, s % 60));
    }
}

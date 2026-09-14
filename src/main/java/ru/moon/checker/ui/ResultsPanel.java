package ru.moon.checker.ui;

import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Severity;
import ru.moon.checker.core.Verdict;
import ru.moon.checker.report.HtmlReport;

import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Final screen for the admin: the verdict and score, severity counts, and a
 * filterable table of every finding with a detail pane and quick actions
 * (reveal in Explorer, copy evidence, save the HTML report, start a new check).
 * The verdict and evidence are for the admin — the player only ever saw a
 * neutral "check complete" state.
 */
public final class ResultsPanel extends JPanel {

    public interface Actions {
        void onNewCheck();
    }

    private final ScanResult result;
    private final FindingTableModel model;
    private final JTable table;
    private final JTextArea detail = new JTextArea();

    public ResultsPanel(ScanResult result, Actions actions) {
        this.result = result;
        this.model = new FindingTableModel(result.findings());
        this.table = new JTable(model);
        setBackground(MoonTheme.BG);
        setLayout(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(18, 22, 18, 22));

        add(verdictHeader(), BorderLayout.NORTH);
        add(centerSplit(), BorderLayout.CENTER);
        add(buttons(actions), BorderLayout.SOUTH);

        // With nothing selected the detail pane would sit empty; show the
        // verdict explanation there instead so the admin reads *why* first.
        showDetail();
    }

    private JPanel verdictHeader() {
        JPanel p = new JPanel(new BorderLayout(20, 0));
        p.setBackground(MoonTheme.PANEL);
        Color vc = verdictColor(result.verdict());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 4, 0, 0, vc),
                BorderFactory.createEmptyBorder(16, 20, 16, 20)));

        JLabel label = new JLabel(verdictText(result.verdict()));
        label.setFont(MoonTheme.font(Font.BOLD, 24)); // body font: verdict is bilingual (Cyrillic)
        label.setForeground(vc);

        JLabel score = new JLabel(result.score() + " / 100");
        score.setFont(MoonTheme.display(Font.BOLD, 26)); // digits only: Orbitron is fine
        score.setForeground(MoonTheme.TEXT);

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        left.setOpaque(false);
        left.add(label);

        p.add(left, BorderLayout.WEST);
        p.add(chips(), BorderLayout.CENTER);
        p.add(score, BorderLayout.EAST);
        return p;
    }

    private JPanel chips() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        p.setOpaque(false);
        for (Severity s : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
            long n = result.countBySeverity(s);
            JLabel chip = new JLabel(n + " " + s.name());
            chip.setOpaque(true);
            chip.setBackground(MoonTheme.PANEL2);
            chip.setForeground(MoonTheme.severityColor(s.name()));
            chip.setFont(MoonTheme.font(Font.BOLD, 12));
            chip.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(MoonTheme.LINE),
                    BorderFactory.createEmptyBorder(5, 10, 5, 10)));
            p.add(chip);
        }
        return p;
    }

    private JPanel centerSplit() {
        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setOpaque(false);
        p.add(filterBar(), BorderLayout.NORTH);

        table.setRowHeight(26);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);
        table.setAutoCreateRowSorter(true); // click a header to sort
        table.getColumnModel().getColumn(0).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(420);
        table.setDefaultRenderer(Object.class, new SeverityRowRenderer());
        table.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        table.getSelectionModel().addListSelectionListener(e -> showDetail());

        JScrollPane tsp = new JScrollPane(table);
        tsp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab(I18n.t("tab.findings") + "  (" + result.findings().size() + ")", tsp);
        tabs.addTab(I18n.t("tab.summary"), buildSummary());
        var timeline = ru.moon.checker.core.Analysis.timeline(result.findings());
        tabs.addTab(I18n.t("tab.timeline") + "  (" + timeline.size() + ")", buildTimeline(timeline));

        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        detail.setBackground(MoonTheme.PANEL2);
        detail.setForeground(MoonTheme.TEXT);
        detail.setFont(new Font("Consolas", Font.PLAIN, 12));
        detail.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        JScrollPane dsp = new JScrollPane(detail);
        dsp.setPreferredSize(new Dimension(0, 130));
        dsp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));

        JPanel stack = new JPanel(new BorderLayout(0, 10));
        stack.setOpaque(false);
        stack.add(tabs, BorderLayout.CENTER);
        stack.add(dsp, BorderLayout.SOUTH);
        p.add(stack, BorderLayout.CENTER);
        return p;
    }

    private JPanel filterBar() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.setOpaque(false);

        JComboBox<String> sev = new JComboBox<>(new String[]{
                I18n.t("filter.all"), "INFO+", "LOW+", "MEDIUM+", "HIGH+", "CRITICAL"});
        sev.addActionListener(e -> refilter(sev, moduleCombo, search));

        Set<String> modules = new LinkedHashSet<>();
        modules.add(I18n.t("filter.all"));
        for (Finding f : result.findings()) {
            modules.add(f.module());
        }
        moduleCombo = new JComboBox<>(new DefaultComboBoxModel<>(modules.toArray(new String[0])));
        moduleCombo.addActionListener(e -> refilter(sev, moduleCombo, search));

        search = new JTextField(22);
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refilter(sev, moduleCombo, search); }
            public void removeUpdate(DocumentEvent e) { refilter(sev, moduleCombo, search); }
            public void changedUpdate(DocumentEvent e) { refilter(sev, moduleCombo, search); }
        });

        p.add(label(I18n.t("filter.severity")));
        p.add(sev);
        p.add(label(I18n.t("filter.module")));
        p.add(moduleCombo);
        p.add(label(I18n.t("filter.search")));
        p.add(search);
        return p;
    }

    private JComboBox<String> moduleCombo;
    private JTextField search;

    private void refilter(JComboBox<String> sev, JComboBox<String> mod, JTextField text) {
        Severity min = switch (sev.getSelectedIndex()) {
            case 1 -> Severity.INFO;
            case 2 -> Severity.LOW;
            case 3 -> Severity.MEDIUM;
            case 4 -> Severity.HIGH;
            case 5 -> Severity.CRITICAL;
            default -> null;
        };
        String module = mod.getSelectedIndex() == 0 ? null : (String) mod.getSelectedItem();
        model.setFilter(min, module, text.getText());
    }

    private JLabel label(String t) {
        JLabel l = new JLabel(t);
        l.setForeground(MoonTheme.MUTED);
        return l;
    }

    /** Correlated evidence: one card per subject (usually one cheat). */
    private JScrollPane buildSummary() {
        JPanel list = new JPanel();
        list.setLayout(new javax.swing.BoxLayout(list, javax.swing.BoxLayout.Y_AXIS));
        list.setBackground(MoonTheme.PANEL);
        list.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        var groups = ru.moon.checker.core.Analysis.group(result.findings());
        if (groups.isEmpty()) {
            JLabel none = new JLabel(I18n.t("summary.none"));
            none.setForeground(MoonTheme.MUTED);
            list.add(none);
        }
        for (var g : groups) {
            JPanel card = new JPanel(new BorderLayout(12, 0));
            card.setBackground(MoonTheme.PANEL2);
            card.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 3, 0, 0,
                            MoonTheme.severityColor(g.topSeverity().name())),
                    BorderFactory.createEmptyBorder(10, 12, 10, 12)));
            card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 68));

            JLabel subject = new JLabel(g.subject());
            subject.setForeground(MoonTheme.TEXT);
            subject.setFont(MoonTheme.font(Font.BOLD, 13));

            JLabel meta = new JLabel(I18n.t("summary.meta",
                    g.count(), g.weight(), String.join(", ", g.modules())));
            meta.setForeground(MoonTheme.MUTED);
            meta.setFont(MoonTheme.font(Font.PLAIN, 11));

            JPanel text = new JPanel();
            text.setOpaque(false);
            text.setLayout(new javax.swing.BoxLayout(text, javax.swing.BoxLayout.Y_AXIS));
            subject.setAlignmentX(Component.LEFT_ALIGNMENT);
            meta.setAlignmentX(Component.LEFT_ALIGNMENT);
            text.add(subject);
            text.add(meta);

            JLabel sev = new JLabel(g.topSeverity().name());
            sev.setForeground(MoonTheme.severityColor(g.topSeverity().name()));
            sev.setFont(MoonTheme.font(Font.BOLD, 12));

            card.add(text, BorderLayout.CENTER);
            card.add(sev, BorderLayout.EAST);
            list.add(card);
            list.add(javax.swing.Box.createVerticalStrut(8));
        }
        JScrollPane sp = new JScrollPane(list);
        sp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    /** Chronological view — what happened and when, most recent first. */
    private JScrollPane buildTimeline(java.util.List<Finding> timeline) {
        String[] cols = {I18n.t("col.time"), I18n.t("col.severity"), I18n.t("col.finding"), I18n.t("col.source")};
        Object[][] rows = new Object[timeline.size()][4];
        var fmt = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault());
        for (int i = 0; i < timeline.size(); i++) {
            Finding f = timeline.get(i);
            rows[i] = new Object[]{fmt.format(f.when()), f.severity().name(), f.title(),
                    f.source() == null ? "" : f.source()};
        }
        JTable t = new JTable(new javax.swing.table.DefaultTableModel(rows, cols) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        });
        t.setRowHeight(24);
        t.setFillsViewportHeight(true);
        t.getTableHeader().setReorderingAllowed(false);
        t.setDefaultRenderer(Object.class, new SeverityRowRenderer());
        t.getColumnModel().getColumn(0).setPreferredWidth(150);
        t.getColumnModel().getColumn(1).setPreferredWidth(80);
        t.getColumnModel().getColumn(2).setPreferredWidth(430);
        JScrollPane sp = new JScrollPane(t);
        sp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));
        return sp;
    }

    private void showDetail() {
        Finding f = model.at(table.getSelectedRow());
        if (f == null) {
            detail.setText(ru.moon.checker.core.Analysis.explain(result));
            detail.setCaretPosition(0);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(f.severity()).append("  •  ").append(I18n.t(f.category().key())).append("\n");
        sb.append(f.title()).append("\n\n");
        if (f.detail() != null) sb.append(I18n.t("detail.detail")).append(": ").append(f.detail()).append("\n");
        if (f.evidence() != null) sb.append(I18n.t("detail.evidence")).append(": ").append(f.evidence()).append("\n");
        if (f.source() != null) sb.append(I18n.t("detail.source")).append(": ").append(f.source()).append("\n");
        if (f.when() != null) sb.append(I18n.t("detail.time")).append(": ").append(f.when()).append("\n");
        detail.setText(sb.toString());
        detail.setCaretPosition(0);
    }

    private JPanel buttons(Actions actions) {
        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);

        JLabel code = new JLabel("🔒 " + ru.moon.checker.report.JsonReport.verificationCode(result));
        code.setForeground(MoonTheme.MUTED);
        code.setFont(new Font("Consolas", Font.PLAIN, 12));
        code.setToolTipText("Verification code — must match the saved report / server");
        p.add(code, BorderLayout.WEST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.setOpaque(false);

        JButton reveal = new JButton(I18n.t("btn.reveal"));
        reveal.addActionListener(e -> revealSelected());
        JButton copy = new JButton(I18n.t("btn.copy"));
        copy.addActionListener(e -> copySelected());
        JButton save = new JButton(I18n.t("btn.save"));
        save.addActionListener(e -> saveReport());
        JButton json = new JButton(I18n.t("btn.savejson"));
        json.addActionListener(e -> saveEvidence());
        JButton neu = new JButton(I18n.t("btn.newcheck"));
        neu.addActionListener(e -> actions.onNewCheck());

        right.add(reveal);
        right.add(copy);
        right.add(save);
        right.add(json);
        right.add(neu);
        p.add(right, BorderLayout.EAST);
        return p;
    }

    private void revealSelected() {
        Finding f = model.at(table.getSelectedRow());
        if (f == null) {
            return;
        }
        // Prefer the evidence itself (the actual file) over openPath (its
        // parent), so Explorer highlights the file rather than its folder.
        File file = null;
        if (f.evidence() != null && new File(f.evidence()).exists()) {
            file = new File(f.evidence());
        } else if (f.openPath() != null && new File(f.openPath()).exists()) {
            file = new File(f.openPath());
        }
        if (file == null) {
            JOptionPane.showMessageDialog(this, I18n.t("reveal.gone"));
            return;
        }
        try {
            if (ru.moon.checker.core.Platform.isWindows() && !file.isDirectory()) {
                // "/select," and the path MUST be one argument — passing them
                // separately makes Explorer ignore the path entirely.
                new ProcessBuilder("explorer.exe", "/select," + file.getAbsolutePath()).start();
            } else {
                File dir = file.isDirectory() ? file : file.getParentFile();
                if (dir != null && dir.exists() && Desktop.isDesktopSupported()) {
                    Desktop.getDesktop().open(dir);
                }
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage());
        }
    }

    private void copySelected() {
        Finding f = model.at(table.getSelectedRow());
        if (f == null) {
            return;
        }
        String text = f.title() + "\n" + (f.detail() == null ? "" : f.detail() + "\n")
                + (f.evidence() == null ? "" : f.evidence());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private void saveReport() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("MoonCheck-" + result.checkId().value() + ".html"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            File out = fc.getSelectedFile();
            Files.write(out.toPath(), HtmlReport.render(result).getBytes(StandardCharsets.UTF_8));
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(out);
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage());
        }
    }

    private void saveEvidence() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("MoonCheck-" + result.checkId().value() + ".json"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            File out = fc.getSelectedFile();
            Files.write(out.toPath(), ru.moon.checker.report.JsonReport.renderBytes(result));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage());
        }
    }

    private static String verdictText(Verdict v) {
        return switch (v) {
            case CLEAN -> I18n.t("verdict.clean");
            case SUSPICIOUS -> I18n.t("verdict.suspicious");
            case CHEAT -> I18n.t("verdict.cheat");
            case INCONCLUSIVE -> I18n.t("verdict.inconclusive");
        };
    }

    private static Color verdictColor(Verdict v) {
        return switch (v) {
            case CLEAN -> MoonTheme.CLEAN;
            case SUSPICIOUS -> MoonTheme.SUSPICIOUS;
            case CHEAT -> MoonTheme.CHEAT;
            case INCONCLUSIVE -> MoonTheme.INFO;
        };
    }

    /** Tints whole rows by severity so CRITICAL/HIGH stand out at a glance. */
    private static final class SeverityRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
            String severity = severityOfRow(t, row);
            if (!sel) {
                c.setBackground(switch (severity) {
                    case "CRITICAL" -> new Color(0x3a, 0x1f, 0x27);
                    case "HIGH" -> new Color(0x36, 0x25, 0x1f);
                    case "MEDIUM" -> new Color(0x31, 0x2c, 0x1e);
                    default -> MoonTheme.PANEL;
                });
                c.setForeground(MoonTheme.TEXT);
            }
            return c;
        }

        /** Severity lives in column 0 (findings table) or 1 (timeline table). */
        private String severityOfRow(JTable t, int row) {
            for (int col : new int[]{0, 1}) {
                if (col < t.getColumnCount()) {
                    Object v = t.getValueAt(row, col);
                    if (v != null) {
                        String s = v.toString();
                        if (s.equals("CRITICAL") || s.equals("HIGH") || s.equals("MEDIUM")
                                || s.equals("LOW") || s.equals("INFO")) {
                            return s;
                        }
                    }
                }
            }
            return "";
        }
    }

    /** Colours the severity column by level. */
    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
            c.setForeground(MoonTheme.severityColor(String.valueOf(value)));
            c.setFont(MoonTheme.font(Font.BOLD, 12));
            return c;
        }
    }
}

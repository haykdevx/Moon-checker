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
    private final JLabel upload = new JLabel();
    private final JButton retry = new JButton();

    public ResultsPanel(ScanResult result, Actions actions, Runnable onRetry) {
        this.result = result;
        this.model = new FindingTableModel(result.findings());
        this.table = new JTable(model);
        setBackground(MoonTheme.BG);
        setLayout(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(18, 22, 18, 22));

        add(verdictHeader(), BorderLayout.NORTH);
        add(centerSplit(), BorderLayout.CENTER);
        add(buttons(actions, onRetry), BorderLayout.SOUTH);
    }

    /** Shows whether the evidence reached the admin's panel (called on the EDT). */
    public void setUploadStatus(ru.moon.checker.net.ReportUploader.Status status) {
        upload.setText(status.text());
        upload.setForeground(switch (status.state()) {
            case DELIVERED -> MoonTheme.CLEAN;
            case SENDING -> MoonTheme.ACCENT2;
            case MISMATCH, OFFLINE -> MoonTheme.SUSPICIOUS;
            case FAILED -> MoonTheme.CHEAT;
        });
        retry.setVisible(status.retryAllowed());
        retry.setEnabled(true);
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
        table.getColumnModel().getColumn(0).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(420);
        table.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        table.getSelectionModel().addListSelectionListener(e -> showDetail());

        JScrollPane tsp = new JScrollPane(table);
        tsp.setBorder(BorderFactory.createLineBorder(MoonTheme.LINE));

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
        stack.add(tsp, BorderLayout.CENTER);
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

    private void showDetail() {
        Finding f = model.at(table.getSelectedRow());
        if (f == null) {
            detail.setText("");
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

    private JPanel buttons(Actions actions, Runnable onRetry) {
        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setOpaque(false);

        JLabel code = new JLabel("🔒 " + ru.moon.checker.report.JsonReport.verificationCode(result));
        code.setForeground(MoonTheme.TEXT);
        code.setFont(new Font("Consolas", Font.BOLD, 14));
        code.setToolTipText("Verification code — must match the code on the admin's panel");

        upload.setFont(MoonTheme.font(Font.BOLD, 13));
        retry.setText(I18n.t("upload.retry"));
        retry.setVisible(false);
        retry.addActionListener(e -> {
            retry.setEnabled(false);
            if (onRetry != null) {
                onRetry.run();
            }
        });
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        left.setOpaque(false);
        left.add(code);
        left.add(upload);
        left.add(retry);
        p.add(left, BorderLayout.NORTH); // own row: the delivery line can be long

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
        String target = f.openPath() != null ? f.openPath() : f.evidence();
        if (target == null) {
            return;
        }
        try {
            File file = new File(target);
            if (ru.moon.checker.core.Platform.isWindows() && file.exists()) {
                new ProcessBuilder("explorer.exe", "/select,", target).start();
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

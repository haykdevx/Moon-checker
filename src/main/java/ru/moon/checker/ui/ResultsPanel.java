package ru.moon.checker.ui;

import ru.moon.checker.core.Analysis;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Severity;
import ru.moon.checker.core.Verdict;
import ru.moon.checker.report.HtmlReport;
import ru.moon.checker.report.JsonReport;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The admin's screen: verdict, score, and every piece of evidence — as a
 * filterable card list, a correlated summary, and a timeline.
 */
public final class ResultsPanel extends JPanel {

    public interface Actions {
        void onNewCheck();
    }

    private final ScanResult result;
    private final FindingTableModel model;
    private final JTable table;
    private final JTextArea detail = new JTextArea();
    private JComboBox<String> moduleCombo;
    private JTextField search;

    public ResultsPanel(ScanResult result, Actions actions) {
        this.result = result;
        this.model = new FindingTableModel(result.findings());
        this.table = new JTable(model);
        setOpaque(true);
        setLayout(new BorderLayout(0, 0));
        setBorder(BorderFactory.createEmptyBorder(16, 22, 14, 22));

        add(verdictHero(), BorderLayout.NORTH);
        add(centre(), BorderLayout.CENTER);
        add(actionBar(actions), BorderLayout.SOUTH);
        showDetail();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        MoonBackground.paintQuiet(g2, getWidth(), getHeight());
        g2.dispose();
    }

    // ---- verdict ---------------------------------------------------------

    private JComponent verdictHero() {
        Color vc = verdictColor(result.verdict());

        JPanel hero = new JPanel(new BorderLayout(24, 0));
        hero.setOpaque(false);
        hero.setBorder(BorderFactory.createEmptyBorder(6, 0, 16, 0));

        // left: glow bar + verdict + reason + chips
        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));

        JPanel titleRow = new JPanel(new BorderLayout(14, 0));
        titleRow.setOpaque(false);
        titleRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleRow.add(new GlowBar(vc), BorderLayout.WEST);

        JPanel titleText = new JPanel();
        titleText.setOpaque(false);
        titleText.setLayout(new BoxLayout(titleText, BoxLayout.Y_AXIS));
        JLabel verdict = new JLabel(verdictText(result.verdict()));
        verdict.setFont(MoonTheme.font(Font.BOLD, 30));
        verdict.setForeground(vc);
        verdict.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel sub = new JLabel(verdictLatin(result.verdict()));
        sub.setFont(MoonTheme.display(Font.PLAIN, 11));
        sub.setForeground(MoonTheme.MUTED);
        sub.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleText.add(verdict);
        titleText.add(Box.createVerticalStrut(4));
        titleText.add(sub);
        titleRow.add(titleText, BorderLayout.CENTER);

        left.add(titleRow);
        left.add(Box.createVerticalStrut(10));
        left.add(chips());

        hero.add(left, BorderLayout.CENTER);

        ArcGauge gauge = new ArcGauge(132, 10,
                vc, vc == MoonTheme.CHEAT ? MoonTheme.HIGH : vc,
                result.score(), 100, "/ 100");
        JPanel gaugeWrap = new JPanel(new BorderLayout());
        gaugeWrap.setOpaque(false);
        gaugeWrap.add(gauge, BorderLayout.CENTER);
        gaugeWrap.setPreferredSize(new Dimension(140, 132));
        hero.add(gaugeWrap, BorderLayout.EAST);
        return hero;
    }

    /** The glowing severity bar beside the verdict. */
    private static final class GlowBar extends JComponent {
        private final Color color;

        GlowBar(Color color) {
            this.color = color;
            setPreferredSize(new Dimension(5, 52));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            for (int i = 6; i >= 1; i--) {
                g2.setColor(new Color(color.getRed(), color.getGreen(), color.getBlue(), 14));
                g2.fillRoundRect(-i, 2 - i, 4 + i * 2, getHeight() - 4 + i * 2, 6, 6);
            }
            g2.setColor(color);
            g2.fillRoundRect(0, 2, 4, getHeight() - 4, 3, 3);
            g2.dispose();
        }
    }

    private JComponent chips() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 7, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        for (Severity s : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO}) {
            row.add(new Chip(s.name(), result.countBySeverity(s)));
        }
        return row;
    }

    /** Count + label pill, tinted when non-zero. */
    private static final class Chip extends JComponent {
        private final String label;
        private final long count;

        Chip(String label, long count) {
            this.label = label;
            this.count = count;
            setPreferredSize(new Dimension(label.length() * 7 + 46, 28));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            Color c = MoonTheme.severityColor(label);
            boolean on = count > 0;
            g2.setColor(on ? MoonTheme.severityWash(label, 28) : new Color(0xff, 0xff, 0xff, 8));
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 9, 9);
            g2.setColor(on ? MoonTheme.severityWash(label, 88) : MoonTheme.LINE2);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 9, 9);

            g2.setFont(MoonTheme.font(Font.BOLD, 13));
            g2.setColor(on ? c : MoonTheme.FAINT);
            g2.drawString(String.valueOf(count), 11, 19);
            int numW = g2.getFontMetrics().stringWidth(String.valueOf(count));
            g2.setFont(MoonTheme.font(Font.PLAIN, 10));
            g2.setColor(on ? c.brighter() : MoonTheme.FAINT);
            g2.drawString(label, 11 + numW + 6, 18);
            g2.dispose();
        }
    }

    // ---- centre ----------------------------------------------------------

    private JComponent centre() {
        table.setModel(model);
        table.setRowHeight(46);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 5));
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setTableHeader(null); // the cards carry their own structure
        table.setOpaque(false);
        table.setBackground(new Color(0, 0, 0, 0));
        table.getColumnModel().getColumn(0).setCellRenderer(new FindingRowRenderer(model));
        table.getSelectionModel().addListSelectionListener(e -> showDetail());

        JScrollPane list = transparentScroll(table);

        JTabbedPane tabs = new JTabbedPane();
        tabs.setOpaque(false);
        tabs.addTab(I18n.t("tab.findings") + "  " + result.findings().size(), list);
        tabs.addTab(I18n.t("tab.summary"), buildSummary());
        List<Finding> timeline = Analysis.timeline(result.findings());
        tabs.addTab(I18n.t("tab.timeline") + "  " + timeline.size(), buildTimeline(timeline));

        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        detail.setOpaque(false);
        detail.setForeground(MoonTheme.TEXT2);
        detail.setFont(MoonTheme.font(Font.PLAIN, 12));
        detail.setBorder(BorderFactory.createEmptyBorder(10, 14, 10, 14));
        JScrollPane detailScroll = transparentScroll(detail);
        detailScroll.setPreferredSize(new Dimension(0, 116));

        JPanel detailCard = new CardPanel();
        detailCard.setLayout(new BorderLayout());
        detailCard.add(detailScroll, BorderLayout.CENTER);
        detailCard.setPreferredSize(new Dimension(0, 116));

        JPanel stack = new JPanel(new BorderLayout(0, 10));
        stack.setOpaque(false);
        stack.add(filterBar(), BorderLayout.NORTH);
        stack.add(tabs, BorderLayout.CENTER);
        stack.add(detailCard, BorderLayout.SOUTH);
        return stack;
    }

    /** Rounded translucent container used for panes and cards. */
    private static class CardPanel extends JPanel {
        CardPanel() {
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(new Color(0x14, 0x17, 0x22, 210));
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 13, 13);
            g2.setColor(MoonTheme.LINE);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 13, 13);
            g2.dispose();
        }
    }

    private static JScrollPane transparentScroll(Component view) {
        JScrollPane sp = new JScrollPane(view);
        sp.setOpaque(false);
        sp.getViewport().setOpaque(false);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getVerticalScrollBar().setUnitIncrement(18);
        return sp;
    }

    private JComponent filterBar() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        p.setOpaque(false);

        JComboBox<String> sev = new JComboBox<>(new String[]{
                I18n.t("filter.all"), "INFO+", "LOW+", "MEDIUM+", "HIGH+", "CRITICAL"});

        Set<String> modules = new LinkedHashSet<>();
        modules.add(I18n.t("filter.all"));
        for (Finding f : result.findings()) {
            modules.add(f.module());
        }
        moduleCombo = new JComboBox<>(new DefaultComboBoxModel<>(modules.toArray(new String[0])));

        search = new JTextField(20);
        search.putClientProperty("JTextField.placeholderText", I18n.t("filter.searchHint"));

        JComboBox<FindingTableModel.Sort> sortBox =
                new JComboBox<>(FindingTableModel.Sort.values());
        sortBox.addActionListener(e ->
                model.setSort((FindingTableModel.Sort) sortBox.getSelectedItem()));

        Runnable refilter = () -> {
            Severity min = switch (sev.getSelectedIndex()) {
                case 1 -> Severity.INFO;
                case 2 -> Severity.LOW;
                case 3 -> Severity.MEDIUM;
                case 4 -> Severity.HIGH;
                case 5 -> Severity.CRITICAL;
                default -> null;
            };
            String module = moduleCombo.getSelectedIndex() == 0 ? null
                    : (String) moduleCombo.getSelectedItem();
            model.setFilter(min, module, search.getText());
        };
        sev.addActionListener(e -> refilter.run());
        moduleCombo.addActionListener(e -> refilter.run());
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refilter.run(); }
            public void removeUpdate(DocumentEvent e) { refilter.run(); }
            public void changedUpdate(DocumentEvent e) { refilter.run(); }
        });

        p.add(muted(I18n.t("filter.severity")));
        p.add(sev);
        p.add(muted(I18n.t("filter.module")));
        p.add(moduleCombo);
        p.add(muted(I18n.t("filter.sort")));
        p.add(sortBox);
        p.add(muted(I18n.t("filter.search")));
        p.add(search);
        return p;
    }

    private JLabel muted(String t) {
        JLabel l = new JLabel(t);
        l.setForeground(MoonTheme.MUTED);
        l.setFont(MoonTheme.font(Font.PLAIN, 12));
        return l;
    }

    // ---- summary + timeline ---------------------------------------------

    private JScrollPane buildSummary() {
        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setOpaque(false);
        list.setBorder(BorderFactory.createEmptyBorder(8, 2, 8, 2));

        List<Analysis.Group> groups = Analysis.group(result.findings());
        if (groups.isEmpty()) {
            JLabel none = new JLabel(I18n.t("summary.none"));
            none.setForeground(MoonTheme.MUTED);
            list.add(none);
        }
        for (Analysis.Group g : groups) {
            list.add(new GroupCard(g));
            list.add(Box.createVerticalStrut(8));
        }
        return transparentScroll(list);
    }

    /** One correlated case: subject, severity spine, counts and modules. */
    private static final class GroupCard extends JPanel {
        private final Analysis.Group group;

        GroupCard(Analysis.Group group) {
            this.group = group;
            setOpaque(false);
            setLayout(new BorderLayout(12, 0));
            setBorder(BorderFactory.createEmptyBorder(11, 15, 11, 15));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 66));

            JPanel text = new JPanel();
            text.setOpaque(false);
            text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
            JLabel subject = new JLabel(group.subject());
            subject.setFont(MoonTheme.font(Font.BOLD, 14));
            subject.setForeground(MoonTheme.TEXT);
            subject.setAlignmentX(Component.LEFT_ALIGNMENT);
            JLabel meta = new JLabel(I18n.t("summary.meta",
                    group.count(), group.weight(), String.join(", ", group.modules())));
            meta.setFont(MoonTheme.font(Font.PLAIN, 11));
            meta.setForeground(MoonTheme.MUTED);
            meta.setAlignmentX(Component.LEFT_ALIGNMENT);
            text.add(subject);
            text.add(Box.createVerticalStrut(3));
            text.add(meta);

            JLabel sev = new JLabel(group.topSeverity().name());
            sev.setFont(MoonTheme.display(Font.BOLD, 10));
            sev.setForeground(MoonTheme.severityColor(group.topSeverity().name()));

            add(text, BorderLayout.CENTER);
            add(sev, BorderLayout.EAST);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            String sev = group.topSeverity().name();
            boolean strong = sev.equals("CRITICAL") || sev.equals("HIGH");
            g2.setColor(strong ? MoonTheme.severityWash(sev, 26) : new Color(0xff, 0xff, 0xff, 7));
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 13, 13);
            g2.setColor(strong ? MoonTheme.severityWash(sev, 70) : MoonTheme.LINE);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 13, 13);
            g2.setColor(MoonTheme.severityColor(sev));
            g2.fillRoundRect(0, 12, 3, getHeight() - 24, 2, 2);
            g2.dispose();
        }
    }

    private JScrollPane buildTimeline(List<Finding> timeline) {
        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setOpaque(false);
        list.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        var fmt = java.time.format.DateTimeFormatter.ofPattern("dd MMM · HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault());

        if (timeline.isEmpty()) {
            JLabel none = new JLabel(I18n.t("summary.none"));
            none.setForeground(MoonTheme.MUTED);
            list.add(none);
        }
        for (int i = 0; i < timeline.size(); i++) {
            list.add(new TimelineRow(timeline.get(i), fmt.format(timeline.get(i).when()),
                    i < timeline.size() - 1));
        }
        return transparentScroll(list);
    }

    /** A dot on a connecting line, with the time, what happened and where. */
    private static final class TimelineRow extends JPanel {
        private final Severity severity;
        private final boolean connect;

        TimelineRow(Finding f, String time, boolean connect) {
            this.severity = f.severity();
            this.connect = connect;
            setOpaque(false);
            setLayout(new BorderLayout());
            setBorder(BorderFactory.createEmptyBorder(4, 34, 14, 6));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 62));

            JPanel text = new JPanel();
            text.setOpaque(false);
            text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
            JLabel t = new JLabel(time);
            t.setFont(MoonTheme.mono(Font.PLAIN, 11));
            t.setForeground(MoonTheme.ACCENT2);
            t.setAlignmentX(Component.LEFT_ALIGNMENT);
            JLabel title = new JLabel(f.title());
            title.setFont(MoonTheme.font(Font.BOLD, 13));
            title.setForeground(MoonTheme.TEXT);
            title.setAlignmentX(Component.LEFT_ALIGNMENT);
            JLabel where = new JLabel(f.evidence() != null ? f.evidence()
                    : (f.source() == null ? "" : f.source()));
            where.setFont(MoonTheme.font(Font.PLAIN, 11));
            where.setForeground(MoonTheme.MUTED2);
            where.setAlignmentX(Component.LEFT_ALIGNMENT);
            text.add(t);
            text.add(title);
            text.add(where);
            add(text, BorderLayout.CENTER);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            Color c = MoonTheme.severityColor(severity.name());
            int x = 14;
            int y = 10;
            if (connect) {
                g2.setColor(MoonTheme.LINE2);
                g2.fillRect(x + 4, y + 12, 2, getHeight());
            }
            g2.setColor(new Color(c.getRed(), c.getGreen(), c.getBlue(), 46));
            g2.fillOval(x - 3, y - 3, 17, 17);
            g2.setColor(c);
            g2.fillOval(x, y, 11, 11);
            g2.dispose();
        }
    }

    // ---- detail + actions -------------------------------------------------

    private void showDetail() {
        Finding f = model.at(table.getSelectedRow());
        if (f == null) {
            detail.setText(Analysis.explain(result));
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

    private JComponent actionBar(Actions actions) {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);
        bar.setBorder(BorderFactory.createEmptyBorder(12, 0, 0, 0));

        JLabel code = new JLabel("●  " + JsonReport.verificationCode(result)
                + "   " + I18n.t("verify.label"));
        code.setFont(MoonTheme.mono(Font.PLAIN, 11));
        code.setForeground(MoonTheme.ACCENT2);
        bar.add(code, BorderLayout.WEST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.setOpaque(false);
        MoonButton reveal = new MoonButton(I18n.t("btn.reveal"), false);
        reveal.addActionListener(e -> revealSelected());
        MoonButton copy = new MoonButton(I18n.t("btn.copy"), false);
        copy.addActionListener(e -> copySelected());
        MoonButton html = new MoonButton(I18n.t("btn.save"), false);
        html.addActionListener(e -> saveReport());
        MoonButton neu = new MoonButton(I18n.t("btn.newcheck"), false);
        neu.addActionListener(e -> actions.onNewCheck());
        MoonButton json = new MoonButton(I18n.t("btn.savejson"), true);
        json.addActionListener(e -> saveEvidence());

        right.add(reveal);
        right.add(copy);
        right.add(html);
        right.add(neu);
        right.add(json);
        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    private void revealSelected() {
        Finding f = model.at(table.getSelectedRow());
        if (f == null) {
            return;
        }
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
                // "/select," and the path MUST be one argument
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
        String text = f == null ? Analysis.explain(result)
                : f.title() + "\n" + (f.detail() == null ? "" : f.detail() + "\n")
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
            Files.write(fc.getSelectedFile().toPath(), JsonReport.renderBytes(result));
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

    /** Latin sub-line under the verdict (Orbitron has no Cyrillic). */
    private static String verdictLatin(Verdict v) {
        return switch (v) {
            case CLEAN -> "CLEAN";
            case SUSPICIOUS -> "SUSPICIOUS";
            case CHEAT -> "CHEAT DETECTED";
            case INCONCLUSIVE -> "INCONCLUSIVE";
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
}

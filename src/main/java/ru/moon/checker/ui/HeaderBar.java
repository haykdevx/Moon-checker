package ru.moon.checker.ui;

import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Always-visible top bar: the MOON brand, the run's identity (check id, PC,
 * user, app version + self-hash) and a live ticking clock. The clock is
 * deliberate — on a Discord screen share it proves the admin is watching a
 * live app, not a recording or a spoofed window. Includes the RU/EN toggle.
 */
public final class HeaderBar extends JPanel {

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final JLabel clock = new JLabel();
    private final JLabel metaLine = new JLabel();
    private final EnvironmentInfo env;
    private final CheckId checkId;

    public HeaderBar(EnvironmentInfo env, CheckId checkId, Runnable onLanguageChange) {
        this.env = env;
        this.checkId = checkId;
        setLayout(new BorderLayout());
        setBackground(MoonTheme.PANEL);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, MoonTheme.LINE),
                BorderFactory.createEmptyBorder(12, 18, 12, 18)));

        add(brand(), BorderLayout.WEST);
        add(center(), BorderLayout.CENTER);
        add(languageToggle(onLanguageChange), BorderLayout.EAST);

        Timer t = new Timer(1000, e -> tick());
        t.setInitialDelay(0);
        t.start();
        tick();
        refreshTexts();
    }

    @Override
    protected void paintComponent(java.awt.Graphics g) {
        java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
        g2.setPaint(new java.awt.GradientPaint(0, 0, new java.awt.Color(0x1c, 0x20, 0x33),
                getWidth(), 0, new java.awt.Color(0x16, 0x18, 0x26)));
        g2.fillRect(0, 0, getWidth(), getHeight());
        g2.dispose();
    }

    private JPanel brand() {
        JLabel logo = new JLabel("MOON");
        logo.setFont(MoonTheme.display(Font.BOLD, 22));
        logo.setForeground(MoonTheme.TEXT);
        JLabel sub = new JLabel("CHECK");
        sub.setFont(MoonTheme.display(Font.PLAIN, 22));
        sub.setForeground(MoonTheme.ACCENT);
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        p.setOpaque(false);
        p.add(new MoonGlyph());
        p.add(logo);
        p.add(sub);
        return p;
    }

    /** Small glowing crescent drawn next to the brand. */
    private static final class MoonGlyph extends javax.swing.JComponent {
        MoonGlyph() {
            setPreferredSize(new Dimension(26, 26));
        }

        @Override
        protected void paintComponent(java.awt.Graphics g) {
            java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
            g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                    java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
            int d = 20, x = 3, y = 3;
            g2.setColor(new java.awt.Color(0x6f, 0x78, 0xef, 90));
            g2.fillOval(x - 2, y - 2, d + 4, d + 4);
            g2.setColor(MoonTheme.MOON);
            g2.fillOval(x, y, d, d);
            g2.setColor(new java.awt.Color(0x1c, 0x20, 0x33));
            g2.fillOval(x + 6, y - 2, d, d);
            g2.dispose();
        }
    }

    private JPanel center() {
        JPanel p = new JPanel();
        p.setOpaque(false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(0, 24, 0, 24));

        JPanel line1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        line1.setOpaque(false);
        JLabel id = new JLabel(checkId.value());
        id.setFont(MoonTheme.font(Font.BOLD, 15));
        id.setForeground(MoonTheme.ACCENT);
        line1.add(id);
        clock.setFont(MoonTheme.mono(Font.PLAIN, 15));
        clock.setForeground(MoonTheme.TEXT);
        line1.add(clock);

        metaLine.setForeground(MoonTheme.MUTED);
        metaLine.setFont(MoonTheme.font(Font.PLAIN, 12));
        metaLine.setAlignmentX(Component.LEFT_ALIGNMENT);
        line1.setAlignmentX(Component.LEFT_ALIGNMENT);

        p.add(line1);
        p.add(metaLine);
        return p;
    }

    private JPanel languageToggle(Runnable onChange) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        p.setOpaque(false);
        JButton ru = smallBtn("RU");
        JButton en = smallBtn("EN");
        ru.addActionListener(e -> {
            I18n.setLocale(I18n.RUSSIAN);
            refreshTexts();
            if (onChange != null) onChange.run();
        });
        en.addActionListener(e -> {
            I18n.setLocale(I18n.ENGLISH);
            refreshTexts();
            if (onChange != null) onChange.run();
        });
        p.add(ru);
        p.add(en);

        JLabel credit = new CreditBadge();
        JPanel creditRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 4));
        creditRow.setOpaque(false);
        creditRow.add(credit);

        JPanel stack = new JPanel();
        stack.setOpaque(false);
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        p.setAlignmentX(Component.RIGHT_ALIGNMENT);
        creditRow.setAlignmentX(Component.RIGHT_ALIGNMENT);
        stack.add(p);
        stack.add(creditRow);
        return stack;
    }

    private JButton smallBtn(String text) {
        JButton b = new JButton(text);
        b.setFont(MoonTheme.font(Font.BOLD, 11));
        b.setMargin(new java.awt.Insets(4, 6, 4, 6));
        b.putClientProperty("JButton.minimumWidth", 0);
        b.setPreferredSize(new Dimension(52, 28));
        b.setFocusable(false);
        return b;
    }

    private void tick() {
        clock.setText(LocalTime.now().format(CLOCK));
    }

    public void refreshTexts() {
        metaLine.setText(I18n.t("header.meta",
                env.hostname(), env.userName(),
                env.elevated() ? I18n.t("header.admin.yes") : I18n.t("header.admin.no"),
                env.appVersion(), env.selfHash()));
    }
}

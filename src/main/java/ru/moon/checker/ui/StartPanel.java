package ru.moon.checker.ui;

import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * First screen: what the check will do, the elevation state, and the button
 * that starts it. Laid out over the full space backdrop with the moon, so the
 * player sees the server's identity before anything else happens.
 */
public final class StartPanel extends JPanel {

    public interface Actions {
        void onStart();

        void onRelaunchElevated();
    }

    private final EnvironmentInfo env;
    private final Actions actions;

    private final JLabel eyebrow = new JLabel();
    private final JLabel title = new JLabel();
    private final JLabel intro = new JLabel();
    private final JPanel checklist = new JPanel(new GridLayout(3, 2, 18, 2));
    private final JLabel privacy = new JLabel();
    private final JLabel adminWarn = new JLabel();
    private final MoonButton start = new MoonButton("", true);
    private final MoonButton relaunch = new MoonButton("", false);
    private final JLabel hint = new JLabel();

    public StartPanel(EnvironmentInfo env, Actions actions) {
        this.env = env;
        this.actions = actions;
        setOpaque(true);
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(0, 40, 0, 40));
        add(content(), BorderLayout.WEST);
        refreshTexts();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        MoonBackground.paint(g2, getWidth(), getHeight(), true);
        g2.dispose();
    }

    private JComponent content() {
        JPanel col = new JPanel();
        col.setOpaque(false);
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        col.setPreferredSize(new Dimension(620, 10));

        eyebrow.setFont(MoonTheme.display(Font.PLAIN, 11));
        eyebrow.setForeground(MoonTheme.ACCENT);

        title.setFont(MoonTheme.font(Font.BOLD, 40));
        title.setForeground(MoonTheme.TEXT);

        intro.setForeground(MoonTheme.MUTED);
        intro.setFont(MoonTheme.font(Font.PLAIN, 13));

        checklist.setOpaque(false);
        checklist.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
        checklist.setMaximumSize(new Dimension(600, 108));

        privacy.setFont(MoonTheme.font(Font.PLAIN, 11));
        privacy.setForeground(MoonTheme.MUTED);

        adminWarn.setFont(MoonTheme.font(Font.BOLD, 12));
        adminWarn.setForeground(MoonTheme.SUSPICIOUS);

        hint.setFont(MoonTheme.font(Font.PLAIN, 11));
        hint.setForeground(MoonTheme.FAINT);

        start.addActionListener(e -> actions.onStart());
        relaunch.addActionListener(e -> actions.onRelaunchElevated());

        for (JComponent c : new JComponent[]{eyebrow, title, intro, checklist, privacy, adminWarn}) {
            c.setAlignmentX(Component.LEFT_ALIGNMENT);
        }

        col.add(Box.createVerticalGlue());
        col.add(eyebrow);
        col.add(Box.createVerticalStrut(10));
        col.add(title);
        col.add(Box.createVerticalStrut(10));
        col.add(intro);
        col.add(Box.createVerticalStrut(14));
        col.add(checklist);
        col.add(Box.createVerticalStrut(10));
        col.add(privacyCard());
        col.add(Box.createVerticalStrut(14));
        col.add(adminWarn);
        col.add(relaunchRow());
        col.add(Box.createVerticalStrut(6));
        col.add(ctaRow());
        col.add(Box.createVerticalStrut(18));
        col.add(credit());
        col.add(Box.createVerticalGlue());
        return col;
    }

    private JComponent privacyCard() {
        JPanel card = new JPanel(new BorderLayout(10, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(0x6f, 0x78, 0xef, 20));
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g2.setColor(new Color(0x6f, 0x78, 0xef, 70));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(BorderFactory.createEmptyBorder(11, 14, 11, 14));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setMaximumSize(new Dimension(545, 86));
        card.add(privacy, BorderLayout.CENTER);
        return card;
    }

    private JComponent relaunchRow() {
        JPanel row = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 4));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(600, 40));
        row.add(relaunch);
        return row;
    }

    private JComponent ctaRow() {
        JPanel row = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 16, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(600, 54));
        row.add(start);
        row.add(hint);
        return row;
    }

    private JComponent credit() {
        JLabel credit = new JLabel("developed by shadow");
        credit.setFont(MoonTheme.font(Font.ITALIC, 10));
        credit.setForeground(MoonTheme.GHOST);
        credit.setAlignmentX(Component.LEFT_ALIGNMENT);
        return credit;
    }

    /** One checklist entry: a small drawn glyph plus a line of text. */
    private JComponent bullet(String text, int glyph) {
        JPanel row = new JPanel(new BorderLayout(9, 0));
        row.setOpaque(false);
        row.add(new Glyph(glyph), BorderLayout.WEST);
        JLabel l = new JLabel(text);
        l.setFont(MoonTheme.font(Font.PLAIN, 12));
        l.setForeground(MoonTheme.TEXT2);
        row.add(l, BorderLayout.CENTER);
        return row;
    }

    /** Small indigo line-art marks, drawn so they scale and recolour cleanly. */
    private static final class Glyph extends JComponent {
        private final int kind;

        Glyph(int kind) {
            this.kind = kind;
            setPreferredSize(new Dimension(16, 16));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            // WEST stretches us to the row height; draw the 16px art centred
            g2.translate(0, Math.max(0, (getHeight() - 16) / 2));
            g2.setColor(MoonTheme.ACCENT);
            g2.setStroke(new java.awt.BasicStroke(1.9f, java.awt.BasicStroke.CAP_ROUND,
                    java.awt.BasicStroke.JOIN_ROUND));
            switch (kind) {
                case 0 -> { // disk / lines
                    g2.drawLine(2, 4, 14, 4);
                    g2.drawLine(2, 8, 14, 8);
                    g2.drawLine(2, 12, 10, 12);
                }
                case 1 -> { // trend / recovered
                    g2.drawPolyline(new int[]{2, 3, 14}, new int[]{3, 13, 13}, 3);
                    g2.drawPolyline(new int[]{5, 8, 10, 14}, new int[]{10, 7, 9, 4}, 4);
                }
                case 2 -> { // clock
                    g2.drawOval(2, 2, 12, 12);
                    g2.drawLine(8, 5, 8, 8);
                    g2.drawLine(8, 8, 11, 10);
                }
                case 3 -> { // monitor
                    g2.drawRoundRect(2, 3, 12, 9, 2, 2);
                    g2.drawLine(6, 14, 10, 14);
                }
                case 4 -> { // globe
                    g2.drawOval(2, 2, 12, 12);
                    g2.drawLine(2, 8, 14, 8);
                    g2.drawOval(5, 2, 6, 12);
                }
                default -> { // shield
                    g2.drawPolyline(new int[]{8, 14, 14, 8, 2, 2, 8},
                            new int[]{2, 5, 9, 14, 9, 5, 2}, 7);
                }
            }
            g2.dispose();
        }
    }

    public void refreshTexts() {
        eyebrow.setText(I18n.t("start.eyebrow"));
        title.setText(I18n.t("start.title"));
        intro.setText(html(I18n.t("start.intro"), 520));
        privacy.setText(html(I18n.t("start.privacy"), 490));
        start.setText(I18n.t("start.button"));
        relaunch.setText(I18n.t("start.relaunch"));
        hint.setText(html(I18n.t("start.hint"), 200));

        checklist.removeAll();
        String[] items = {
                I18n.t("start.item.files"), I18n.t("start.item.deleted"),
                I18n.t("start.item.exec"), I18n.t("start.item.system"),
                I18n.t("start.item.sites"), I18n.t("start.item.steam")
        };
        for (int i = 0; i < items.length; i++) {
            checklist.add(bullet(items[i], i));
        }

        boolean elevated = env.elevated();
        relaunch.setVisible(!elevated);
        adminWarn.setVisible(!elevated);
        if (!elevated) {
            adminWarn.setText("⚠  " + I18n.t("start.noadmin"));
        }
        revalidate();
        repaint();
    }

    private static String html(String text, int width) {
        return "<html><div style='width:" + width + "px'>" + text + "</div></html>";
    }
}

package ru.moon.checker.ui;

import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

/**
 * First screen: what the checker will do (consent notice), the elevation state,
 * and the big "Start check" button. If not running as administrator it warns
 * and offers to relaunch elevated.
 */
public final class StartPanel extends JPanel {

    public interface Actions {
        void onStart();

        void onRelaunchElevated();
    }

    private final EnvironmentInfo env;
    private final Actions actions;

    private final JLabel title = new JLabel();
    private final JLabel intro = new JLabel();
    private final JLabel bullets = new JLabel();
    private final JLabel adminWarn = new JLabel();
    private final JButton start = new JButton();
    private final JButton relaunch = new JButton();

    public StartPanel(EnvironmentInfo env, Actions actions) {
        this.env = env;
        this.actions = actions;
        setOpaque(true);
        setBackground(MoonTheme.BG);
        setLayout(new GridBagLayout());
        add(card());
        refreshTexts();
    }

    @Override
    protected void paintComponent(java.awt.Graphics g) {
        java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
        MoonBackground.paint(g2, getWidth(), getHeight(), true);
        g2.dispose();
    }

    private JPanel card() {
        JPanel card = new JPanel() {
            @Override
            protected void paintComponent(java.awt.Graphics g) {
                java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                        java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new java.awt.Color(0x1b, 0x1e, 0x2b, 234));
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 20, 20);
                g2.setColor(MoonTheme.LINE);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 20, 20);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createEmptyBorder(30, 34, 30, 34));
        card.setMaximumSize(new Dimension(720, 580));

        title.setFont(MoonTheme.font(Font.BOLD, 24)); // body font: title can be Cyrillic
        title.setForeground(MoonTheme.TEXT);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);

        intro.setForeground(MoonTheme.MUTED);
        intro.setFont(MoonTheme.font(Font.PLAIN, 13));
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);

        bullets.setForeground(MoonTheme.TEXT);
        bullets.setFont(MoonTheme.font(Font.PLAIN, 13));
        bullets.setAlignmentX(Component.LEFT_ALIGNMENT);
        bullets.setBorder(BorderFactory.createEmptyBorder(14, 0, 14, 0));

        adminWarn.setFont(MoonTheme.font(Font.BOLD, 13));
        adminWarn.setAlignmentX(Component.LEFT_ALIGNMENT);
        adminWarn.setBorder(BorderFactory.createEmptyBorder(4, 0, 12, 0));

        start.setFont(MoonTheme.font(Font.BOLD, 15));
        start.setBackground(MoonTheme.ACCENT);
        start.setForeground(java.awt.Color.WHITE);
        start.setPreferredSize(new Dimension(260, 46));
        start.setMaximumSize(new Dimension(260, 46));
        start.setAlignmentX(Component.LEFT_ALIGNMENT);
        start.addActionListener(e -> actions.onStart());

        relaunch.setFont(MoonTheme.font(Font.PLAIN, 12));
        relaunch.setAlignmentX(Component.LEFT_ALIGNMENT);
        relaunch.setMaximumSize(new Dimension(260, 34));
        relaunch.addActionListener(e -> actions.onRelaunchElevated());

        card.add(title);
        card.add(intro);
        card.add(bullets);
        card.add(adminWarn);
        card.add(relaunch);
        card.add(javax.swing.Box.createVerticalStrut(10));
        card.add(start);
        card.add(javax.swing.Box.createVerticalStrut(16));

        JLabel credit = new JLabel("developed by shadow");
        credit.setFont(MoonTheme.font(Font.ITALIC, 11));
        credit.setForeground(MoonTheme.MUTED);
        credit.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(credit);
        return card;
    }

    public void refreshTexts() {
        title.setText(I18n.t("start.title"));
        intro.setText("<html><div style='width:640px'>" + I18n.t("start.intro") + "</div></html>");
        bullets.setText("<html><div style='width:640px'>" + I18n.t("start.bullets") + "</div></html>");
        start.setText(I18n.t("start.button"));
        relaunch.setText(I18n.t("start.relaunch"));

        boolean elevated = env.elevated();
        relaunch.setVisible(!elevated);
        adminWarn.setVisible(!elevated);
        if (!elevated) {
            adminWarn.setText("⚠ " + I18n.t("start.noadmin"));
            adminWarn.setForeground(MoonTheme.SUSPICIOUS);
        }
    }
}

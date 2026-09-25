package ru.moon.checker.ui;

import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;
import ru.moon.checker.net.SessionLink;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagLayout;

/**
 * First screen: what the checker will do (consent notice), the elevation state,
 * the admin's check code, and the big "Start check" button. When a panel is
 * configured the player must connect with a valid code first; the screen then
 * shows the admin's alias so the player knows who receives the results.
 */
public final class StartPanel extends JPanel {

    public interface Actions {
        void onStart();

        void onRelaunchElevated();

        void onConnect(String code);
    }

    private enum LinkState { OFFLINE, IDLE, CONNECTING, CONNECTED, FAILED }

    private final EnvironmentInfo env;
    private final Actions actions;
    private final boolean online;

    private final JLabel title = new JLabel();
    private final JLabel intro = new JLabel();
    private final JLabel bullets = new JLabel();
    private final JLabel adminWarn = new JLabel();
    private final JLabel codeLabel = new JLabel();
    private final JTextField codeField = new JTextField(10);
    private final JButton connect = new JButton();
    private final JLabel linkStatus = new JLabel();
    private final JButton start = new JButton();
    private final JButton relaunch = new JButton();

    private LinkState state;
    private SessionLink link;
    private String failure;

    public StartPanel(EnvironmentInfo env, boolean online, Actions actions) {
        this.env = env;
        this.online = online;
        this.actions = actions;
        this.state = online ? LinkState.IDLE : LinkState.OFFLINE;
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
        card.setBorder(BorderFactory.createEmptyBorder(26, 34, 26, 34));
        card.setMaximumSize(new Dimension(720, 660));

        title.setFont(MoonTheme.font(Font.BOLD, 24)); // body font: title can be Cyrillic
        title.setForeground(MoonTheme.TEXT);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);

        intro.setForeground(MoonTheme.MUTED);
        intro.setFont(MoonTheme.font(Font.PLAIN, 13));
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);

        bullets.setForeground(MoonTheme.TEXT);
        bullets.setFont(MoonTheme.font(Font.PLAIN, 13));
        bullets.setAlignmentX(Component.LEFT_ALIGNMENT);
        bullets.setBorder(BorderFactory.createEmptyBorder(12, 0, 12, 0));

        adminWarn.setFont(MoonTheme.font(Font.BOLD, 13));
        adminWarn.setAlignmentX(Component.LEFT_ALIGNMENT);
        adminWarn.setBorder(BorderFactory.createEmptyBorder(4, 0, 8, 0));

        codeLabel.setFont(MoonTheme.font(Font.BOLD, 13));
        codeLabel.setForeground(MoonTheme.TEXT);
        codeLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        codeField.setFont(new Font("Consolas", Font.BOLD, 22));
        codeField.setHorizontalAlignment(JTextField.CENTER);
        codeField.setMaximumSize(new Dimension(200, 42));
        codeField.setPreferredSize(new Dimension(200, 42));
        codeField.putClientProperty("JTextField.placeholderText", "XXXX-XXXX");
        ((AbstractDocument) codeField.getDocument()).setDocumentFilter(new CodeFilter());
        codeField.addActionListener(e -> requestConnect());

        connect.setFont(MoonTheme.font(Font.BOLD, 13));
        connect.setPreferredSize(new Dimension(170, 42));
        connect.addActionListener(e -> requestConnect());

        JPanel codeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        codeRow.setOpaque(false);
        codeRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        codeRow.add(codeField);
        codeRow.add(javax.swing.Box.createHorizontalStrut(10));
        codeRow.add(connect);
        codeRow.setMaximumSize(new Dimension(640, 46));

        linkStatus.setFont(MoonTheme.font(Font.BOLD, 13));
        linkStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
        linkStatus.setBorder(BorderFactory.createEmptyBorder(8, 0, 10, 0));

        start.setFont(MoonTheme.font(Font.BOLD, 15));
        start.setBackground(MoonTheme.ACCENT);
        start.setForeground(java.awt.Color.WHITE);
        start.setPreferredSize(new Dimension(260, 46));
        start.setMaximumSize(new Dimension(260, 46));
        start.setAlignmentX(Component.LEFT_ALIGNMENT);
        start.addActionListener(e -> {
            if (state == LinkState.CONNECTED || state == LinkState.OFFLINE) {
                start.setEnabled(false);
                actions.onStart();
            }
        });

        relaunch.setFont(MoonTheme.font(Font.PLAIN, 12));
        relaunch.setAlignmentX(Component.LEFT_ALIGNMENT);
        relaunch.setMaximumSize(new Dimension(300, 34));
        relaunch.addActionListener(e -> actions.onRelaunchElevated());

        card.add(title);
        card.add(intro);
        card.add(bullets);
        card.add(adminWarn);
        card.add(relaunch);
        card.add(javax.swing.Box.createVerticalStrut(12));
        if (online) {
            card.add(codeLabel);
            card.add(javax.swing.Box.createVerticalStrut(6));
            card.add(codeRow);
        }
        card.add(linkStatus);
        card.add(start);
        card.add(javax.swing.Box.createVerticalStrut(14));

        JLabel credit = new JLabel("developed by shadow");
        credit.setFont(MoonTheme.font(Font.ITALIC, 11));
        credit.setForeground(MoonTheme.MUTED);
        credit.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(credit);
        return card;
    }

    private void requestConnect() {
        if (state == LinkState.CONNECTING || state == LinkState.CONNECTED || state == LinkState.OFFLINE) {
            return;
        }
        String code = codeField.getText().trim();
        if (code.replace("-", "").length() != 8) {
            failure = I18n.t("start.needcode");
            state = LinkState.FAILED;
            refreshTexts();
            codeField.requestFocusInWindow();
            return;
        }
        state = LinkState.CONNECTING;
        refreshTexts();
        actions.onConnect(code);
    }

    /** Called on the EDT once the panel accepted the code. */
    public void setConnected(SessionLink l) {
        this.link = l;
        this.state = LinkState.CONNECTED;
        refreshTexts();
        start.requestFocusInWindow();
    }

    /** Called on the EDT when the code was refused or the panel was unreachable. */
    public void setConnectFailed(String message) {
        this.failure = message;
        this.state = LinkState.FAILED;
        refreshTexts();
        codeField.requestFocusInWindow();
        codeField.selectAll();
    }

    public void refreshTexts() {
        title.setText(I18n.t("start.title"));
        String introText = I18n.t("start.intro") + (online ? " " + I18n.t("start.consent") : "");
        intro.setText("<html><div style='width:640px'>" + introText + "</div></html>");
        bullets.setText("<html><div style='width:640px'>" + I18n.t("start.bullets") + "</div></html>");
        start.setText(I18n.t("start.button"));
        relaunch.setText(I18n.t("start.relaunch"));
        codeLabel.setText(I18n.t("start.code.label"));
        codeField.setToolTipText(I18n.t("start.code.hint"));

        boolean elevated = env.elevated();
        relaunch.setVisible(!elevated);
        adminWarn.setVisible(!elevated);
        if (!elevated) {
            adminWarn.setText("⚠ " + I18n.t("start.noadmin"));
            adminWarn.setForeground(MoonTheme.SUSPICIOUS);
        }

        boolean editable = state == LinkState.IDLE || state == LinkState.FAILED;
        codeField.setEditable(editable);
        connect.setEnabled(editable);
        connect.setText(state == LinkState.CONNECTING ? I18n.t("start.connecting") : I18n.t("start.connect"));
        start.setEnabled(state == LinkState.CONNECTED || state == LinkState.OFFLINE);

        switch (state) {
            case OFFLINE -> status(I18n.t("start.offline"), MoonTheme.SUSPICIOUS);
            case IDLE -> status("<html><div style='width:640px'>" + I18n.t("start.code.hint") + "</div></html>",
                    MoonTheme.MUTED);
            case CONNECTING -> status(I18n.t("start.connecting"), MoonTheme.MUTED);
            case CONNECTED -> status(I18n.t("start.connected", link.adminAlias(),
                    link.playerName().isBlank() ? "—" : link.playerName()), MoonTheme.CLEAN);
            case FAILED -> status("<html><div style='width:640px'>✗ " + escape(failure) + "</div></html>",
                    MoonTheme.CHEAT);
        }
    }

    private void status(String text, java.awt.Color color) {
        linkStatus.setText(text);
        linkStatus.setForeground(color);
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Upper-cases input, keeps only code characters and inserts the dash: XXXX-XXXX. */
    static final class CodeFilter extends DocumentFilter {
        static String format(String raw) {
            StringBuilder sb = new StringBuilder();
            for (char c : raw.toUpperCase(java.util.Locale.ROOT).toCharArray()) {
                if (Character.isLetterOrDigit(c) && c < 128 && sb.length() < 8) {
                    sb.append(c);
                }
            }
            if (sb.length() > 4) {
                sb.insert(4, '-');
            }
            return sb.toString();
        }

        private void replaceAll(FilterBypass fb, String next) throws BadLocationException {
            fb.replace(0, fb.getDocument().getLength(), format(next), null);
        }

        @Override
        public void insertString(FilterBypass fb, int offset, String text, AttributeSet attr)
                throws BadLocationException {
            String cur = fb.getDocument().getText(0, fb.getDocument().getLength());
            replaceAll(fb, cur.substring(0, offset) + text + cur.substring(offset));
        }

        @Override
        public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                throws BadLocationException {
            String cur = fb.getDocument().getText(0, fb.getDocument().getLength());
            replaceAll(fb, cur.substring(0, offset) + (text == null ? "" : text) + cur.substring(offset + length));
        }

        @Override
        public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
            String cur = fb.getDocument().getText(0, fb.getDocument().getLength());
            replaceAll(fb, cur.substring(0, offset) + cur.substring(offset + length));
        }
    }
}

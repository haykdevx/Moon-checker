package ru.moon.checker.ui;

import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.I18n;
import ru.moon.checker.net.SessionLink;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import javax.swing.text.View;
import javax.swing.plaf.basic.BasicHTML;
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
 *
 * <p>With a Moon panel configured the player must first enter the admin's check
 * code; once the panel accepts it the screen shows that admin's alias, so the
 * player knows exactly who receives the results, and only then enables Start.
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

    private final JLabel eyebrow = new JLabel();
    private final JLabel title = new JLabel();
    private final JLabel intro = new JLabel();
    private final JPanel checklist = new JPanel(new GridLayout(3, 2, 18, 2));
    private final JLabel privacy = new JLabel();
    private final JLabel adminWarn = new JLabel();
    private final MoonButton start = new MoonButton("", true);
    private final MoonButton relaunch = new MoonButton("", false);
    private final JLabel hint = new JLabel();
    private final JLabel codeLabel = new JLabel();
    private final JTextField codeField = new JTextField(10);
    private final MoonButton connect = new MoonButton("", false);
    private final JLabel linkStatus = new JLabel();

    private LinkState state;
    private SessionLink link;
    private String failure;

    public StartPanel(EnvironmentInfo env, boolean online, Actions actions) {
        this.env = env;
        this.online = online;
        this.actions = actions;
        this.state = online ? LinkState.IDLE : LinkState.OFFLINE;
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

        start.addActionListener(e -> {
            if (state == LinkState.CONNECTED || state == LinkState.OFFLINE) {
                start.setEnabled(false);
                actions.onStart();
            }
        });
        relaunch.addActionListener(e -> actions.onRelaunchElevated());

        codeLabel.setFont(MoonTheme.font(Font.BOLD, 12));
        codeLabel.setForeground(MoonTheme.TEXT2);
        codeField.setFont(MoonTheme.mono(Font.BOLD, 20));
        codeField.setHorizontalAlignment(JTextField.CENTER);
        codeField.setBackground(MoonTheme.PANEL2);
        codeField.setForeground(MoonTheme.TEXT);
        codeField.setCaretColor(MoonTheme.ACCENT2);
        codeField.setPreferredSize(new Dimension(190, 40));
        codeField.setMaximumSize(new Dimension(190, 40));
        codeField.putClientProperty("JTextField.placeholderText", "XXXX-XXXX");
        ((AbstractDocument) codeField.getDocument()).setDocumentFilter(new CodeFilter());
        codeField.addActionListener(e -> requestConnect());
        connect.addActionListener(e -> requestConnect());
        linkStatus.setFont(MoonTheme.font(Font.BOLD, 12));

        for (JComponent c : new JComponent[]{eyebrow, title, intro, checklist, privacy, adminWarn, codeLabel,
                linkStatus}) {
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
        if (online) {
            col.add(codeLabel);
            col.add(Box.createVerticalStrut(6));
            col.add(codeRow());
        }
        col.add(Box.createVerticalStrut(6));
        col.add(linkStatus);
        col.add(Box.createVerticalStrut(10));
        col.add(ctaRow());
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

    private JComponent codeRow() {
        JPanel row = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(600, 44));
        row.add(codeField);
        row.add(Box.createHorizontalStrut(10));
        row.add(connect);
        return row;
    }

    private void requestConnect() {
        if (state != LinkState.IDLE && state != LinkState.FAILED) {
            return;
        }
        if (codeField.getText().replace("-", "").length() != 8) {
            failure = I18n.t("start.needcode");
            state = LinkState.FAILED;
            refreshTexts();
            codeField.requestFocusInWindow();
            return;
        }
        state = LinkState.CONNECTING;
        refreshTexts();
        actions.onConnect(codeField.getText());
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

    private JComponent ctaRow() {
        JPanel row = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(600, 54));
        row.add(start);  // flush with the text above: FlowLayout's gap would indent it
        row.add(Box.createHorizontalStrut(16));
        row.add(hint);
        return row;
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
        wrap(intro, I18n.t("start.intro"), 600);
        wrap(privacy, I18n.t(online ? "start.privacy.online" : "start.privacy"), 515);
        codeLabel.setText(I18n.t("start.code.label"));
        codeField.setToolTipText(I18n.t("start.code.hint"));
        start.setText(I18n.t("start.button"));
        relaunch.setText(I18n.t("start.relaunch"));
        wrap(hint, I18n.t("start.hint"), 230);

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

        boolean editable = state == LinkState.IDLE || state == LinkState.FAILED;
        codeField.setEditable(editable);
        connect.setEnabled(editable);
        connect.setText(I18n.t(state == LinkState.CONNECTING ? "start.connecting" : "start.connect"));
        start.setEnabled(state == LinkState.CONNECTED || state == LinkState.OFFLINE);
        switch (state) {
            case OFFLINE -> status(escape(I18n.t("start.offline")), MoonTheme.SUSPICIOUS);
            case IDLE -> status(I18n.t("start.code.hint"), MoonTheme.FAINT);
            case CONNECTING -> status(escape(I18n.t("start.connecting")), MoonTheme.MUTED);
            case CONNECTED -> status(escape(I18n.t("start.connected", link.adminAlias(),
                    link.playerName().isBlank() ? "—" : link.playerName())), MoonTheme.CLEAN);
            case FAILED -> status("✗ " + escape(failure), MoonTheme.CHEAT);
        }
        revalidate();
        repaint();
    }

    private void status(String html, Color color) {
        wrap(linkStatus, html, 600);
        linkStatus.setForeground(color);
    }

    /**
     * Sets HTML text that wraps at {@code width} real pixels. A CSS width does not do this:
     * Swing counts a CSS "px" as 1.3 screen pixels, so a 520px div overflowed the 620-pixel
     * column and Windows cut the Russian lines off at the right edge.
     */
    static void wrap(JLabel label, String html, int width) {
        label.setText("<html>" + html + "</html>");
        View view = (View) label.getClientProperty(BasicHTML.propertyKey);
        if (view == null) {
            return;
        }
        int w = (int) Math.ceil(Math.min(view.getPreferredSpan(View.X_AXIS), width)); // unwrapped, if shorter
        view.setSize(w, 0);
        Dimension size = new Dimension(w, (int) Math.ceil(view.getPreferredSpan(View.Y_AXIS)));
        label.setPreferredSize(size);
        label.setMaximumSize(size);
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

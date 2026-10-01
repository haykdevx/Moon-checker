package ru.moon.checker.ui;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/** The author's credit: small, but in the accent colour inside a thin rounded outline so it is seen. */
public final class CreditBadge extends JLabel {

    public static final String TEXT = "Developed by shadow";

    public CreditBadge() {
        super(TEXT);
        setFont(MoonTheme.font(Font.BOLD, 11));
        setForeground(MoonTheme.ACCENT2);
        setBorder(BorderFactory.createEmptyBorder(2, 9, 3, 9));
        setOpaque(false);
        setToolTipText(TEXT);
    }

    @Override
    public java.awt.Dimension getMaximumSize() {
        return getPreferredSize();   // never squeezed into "Developed by sha…"
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(new Color(0x6f, 0x78, 0xef, 28));
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, getHeight(), getHeight());
        g2.setColor(new Color(0x6f, 0x78, 0xef, 120));
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, getHeight(), getHeight());
        g2.dispose();
        super.paintComponent(g);
    }
}

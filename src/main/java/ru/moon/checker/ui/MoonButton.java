package ru.moon.checker.ui;

import javax.swing.JButton;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * Flat, painted button in the Moon style. Two weights: {@code primary} is the
 * indigo gradient call-to-action, otherwise it is a quiet card-coloured button.
 * Painted rather than themed so it looks identical on every Windows version.
 */
public final class MoonButton extends JButton {

    private final boolean primary;
    private boolean hover;

    public MoonButton(String text, boolean primary) {
        super(text);
        this.primary = primary;
        setFocusPainted(false);
        setBorderPainted(false);
        setContentAreaFilled(false);
        setRolloverEnabled(true);
        setFont(MoonTheme.font(primary ? Font.BOLD : Font.PLAIN, primary ? 14 : 12));
        setForeground(primary ? new Color(0x0a, 0x0c, 0x18) : MoonTheme.TEXT2);
        setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        addChangeListener(e -> {
            boolean h = getModel().isRollover();
            if (h != hover) {
                hover = h;
                repaint();
            }
        });
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension d = super.getPreferredSize();
        return new Dimension(d.width + (primary ? 40 : 18), primary ? 42 : 31);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        int arc = primary ? 12 : 10;
        boolean pressed = getModel().isPressed();

        if (primary) {
            // soft glow under the CTA
            g2.setColor(new Color(0x6f, 0x78, 0xef, hover ? 70 : 46));
            g2.fillRoundRect(2, 4, w - 4, h - 3, arc + 2, arc + 2);
            Color top = hover ? new Color(0x92, 0x99, 0xff) : MoonTheme.ACCENT_HI;
            Color bottom = hover ? MoonTheme.ACCENT_HI : MoonTheme.ACCENT;
            if (pressed) {
                top = MoonTheme.ACCENT;
                bottom = new Color(0x5f, 0x68, 0xdf);
            }
            g2.setPaint(new GradientPaint(0, 0, top, 0, h, bottom));
            g2.fillRoundRect(0, 0, w, h - 2, arc, arc);
        } else {
            g2.setColor(hover ? new Color(0x24, 0x29, 0x3c) : MoonTheme.CARD);
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(hover ? MoonTheme.ACCENT : MoonTheme.LINE2);
            g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);
        }
        g2.dispose();
        super.paintComponent(g);
    }
}

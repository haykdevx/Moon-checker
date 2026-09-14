package ru.moon.checker.ui;

import javax.swing.JComponent;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Arc2D;

/**
 * Circular gauge used for the verdict score and for scan progress: a track ring
 * with a coloured arc over it and figures in the middle. The numerals use the
 * display font (digits only, so Orbitron is safe there).
 */
public final class ArcGauge extends JComponent {

    private final int diameter;
    private final int stroke;
    private final Color arcColor;
    private final Color arcColor2;
    private int value;
    private int max;
    private String caption;

    public ArcGauge(int diameter, int stroke, Color arcColor, Color arcColor2,
                    int value, int max, String caption) {
        this.diameter = diameter;
        this.stroke = stroke;
        this.arcColor = arcColor;
        this.arcColor2 = arcColor2;
        this.value = value;
        this.max = max;
        this.caption = caption;
        setOpaque(false);
        setPreferredSize(new Dimension(diameter, diameter));
        setMinimumSize(new Dimension(diameter, diameter));
        setMaximumSize(new Dimension(diameter, diameter));
    }

    public void setValue(int value, int max, String caption) {
        this.value = value;
        this.max = max;
        this.caption = caption;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        int pad = stroke / 2 + 2;
        int d = Math.min(getWidth(), getHeight()) - pad * 2;
        int x = (getWidth() - d) / 2;
        int y = (getHeight() - d) / 2;

        // track
        g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.setColor(MoonTheme.PANEL2);
        g2.draw(new Arc2D.Double(x, y, d, d, 90, -360, Arc2D.OPEN));

        // value arc
        double fraction = max <= 0 ? 0 : Math.min(1.0, (double) value / max);
        if (fraction > 0) {
            g2.setPaint(new GradientPaint(x, y, arcColor2, x + d, y + d, arcColor));
            g2.draw(new Arc2D.Double(x, y, d, d, 90, -360 * fraction, Arc2D.OPEN));
        }

        // figures
        String main = String.valueOf(value);
        Font mainFont = MoonTheme.display(Font.BOLD, Math.max(16, d / 3));
        g2.setFont(mainFont);
        FontMetrics fm = g2.getFontMetrics();
        int mainW = fm.stringWidth(main);
        int cy = getHeight() / 2;
        g2.setColor(MoonTheme.TEXT);
        g2.drawString(main, (getWidth() - mainW) / 2, cy + fm.getAscent() / 2 - 4);

        if (caption != null && !caption.isEmpty()) {
            Font capFont = MoonTheme.mono(Font.PLAIN, Math.max(9, d / 12));
            g2.setFont(capFont);
            FontMetrics cfm = g2.getFontMetrics();
            int capW = cfm.stringWidth(caption);
            g2.setColor(MoonTheme.MUTED);
            g2.drawString(caption, (getWidth() - capW) / 2, cy + fm.getAscent() / 2 + cfm.getHeight());
        }
        g2.dispose();
    }
}

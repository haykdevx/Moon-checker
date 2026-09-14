package ru.moon.checker.ui;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.util.Random;

/**
 * Paints the Moon backdrop: a deep-space vertical gradient, a fixed starfield,
 * and a glowing crescent moon. Static so any panel can render it inside
 * {@code paintComponent}. The star layout is seeded, so it stays stable across
 * repaints instead of shimmering.
 */
public final class MoonBackground {

    private MoonBackground() {
    }

    /**
     * @param g        target graphics
     * @param w        width
     * @param h        height
     * @param bigMoon  large glowing moon (start screen) vs. a small corner motif
     */
    public static void paint(Graphics2D g, int w, int h, boolean bigMoon) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        // space gradient
        g.setPaint(new java.awt.GradientPaint(0, 0, MoonTheme.SPACE_TOP, 0, h, MoonTheme.SPACE_BOT));
        g.fillRect(0, 0, w, h);

        // starfield (seeded so it's stable)
        Random rnd = new Random(M00N_SEED());
        int stars = Math.max(60, (w * h) / 9000);
        for (int i = 0; i < stars; i++) {
            int x = rnd.nextInt(Math.max(1, w));
            int y = rnd.nextInt(Math.max(1, h));
            float b = 0.25f + rnd.nextFloat() * 0.75f;
            int size = rnd.nextInt(100) < 88 ? 1 : 2;
            g.setColor(new Color(
                    MoonTheme.STAR.getRed() / 255f,
                    MoonTheme.STAR.getGreen() / 255f,
                    MoonTheme.STAR.getBlue() / 255f, b));
            g.fillRect(x, y, size, size);
        }

        // moon with glow
        double d = bigMoon ? Math.min(w, h) * 0.42 : 120;
        double cx = bigMoon ? w * 0.80 : w - 70;
        double cy = bigMoon ? h * 0.30 : 34;
        drawMoon(g, cx, cy, d);
    }

    private static void drawMoon(Graphics2D g, double cx, double cy, double d) {
        double r = d / 2;
        // glow
        float[] fractions = {0f, 0.6f, 1f};
        Color[] colors = {
                new Color(MoonTheme.MOON_GLOW.getRed(), MoonTheme.MOON_GLOW.getGreen(), MoonTheme.MOON_GLOW.getBlue(), 70),
                new Color(MoonTheme.MOON_GLOW.getRed(), MoonTheme.MOON_GLOW.getGreen(), MoonTheme.MOON_GLOW.getBlue(), 20),
                new Color(0, 0, 0, 0)
        };
        RadialGradientPaint glow = new RadialGradientPaint(
                new Point2D.Double(cx, cy), (float) (r * 1.9), fractions, colors);
        g.setPaint(glow);
        g.fill(new Ellipse2D.Double(cx - r * 1.9, cy - r * 1.9, r * 3.8, r * 3.8));

        // moon disc
        g.setColor(MoonTheme.MOON);
        g.fill(new Ellipse2D.Double(cx - r, cy - r, d, d));
        // subtle shading to crescent — overlay a space-coloured disc offset
        g.setColor(new Color(MoonTheme.SPACE_TOP.getRed(), MoonTheme.SPACE_TOP.getGreen(),
                MoonTheme.SPACE_TOP.getBlue(), 235));
        g.fill(new Ellipse2D.Double(cx - r + d * 0.28, cy - r - d * 0.06, d, d));
        // a couple of craters on the lit part
        g.setColor(new Color(0xcf, 0xcb, 0xbd));
        g.fill(new Ellipse2D.Double(cx - r * 0.55, cy - r * 0.15, r * 0.28, r * 0.28));
        g.fill(new Ellipse2D.Double(cx - r * 0.15, cy + r * 0.30, r * 0.18, r * 0.18));
        g.fill(new Ellipse2D.Double(cx - r * 0.30, cy - r * 0.55, r * 0.14, r * 0.14));
    }

    private static long M00N_SEED() {
        return 0x6f78efL;
    }
}

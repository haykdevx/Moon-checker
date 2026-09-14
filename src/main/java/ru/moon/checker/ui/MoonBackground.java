package ru.moon.checker.ui;

import java.awt.Color;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.MultipleGradientPaint;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.util.Random;

/**
 * The Moon backdrop: a layered space gradient, a seeded starfield and a lit
 * crescent. Static so any panel can paint it from {@code paintComponent}.
 *
 * <p>The star layout is seeded, so it stays put across repaints instead of
 * shimmering, and the moon is drawn with a real terminator (a shadow disc
 * offset over the lit disc) rather than a flat circle.
 */
public final class MoonBackground {

    private static final long SEED = 0x6f78efL;

    private MoonBackground() {
    }

    /** Full atmospheric treatment — the start screen. */
    public static void paint(Graphics2D g, int w, int h, boolean bigMoon) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        sky(g, w, h);
        stars(g, w, h, bigMoon ? 16 : 10);
        if (bigMoon) {
            double d = Math.min(w, h) * 0.38;
            drawMoon(g, w * 0.83, h * 0.34, d);
        }
    }

    /** Quiet treatment for content screens: gradient + a few stars, no moon. */
    public static void paintQuiet(Graphics2D g, int w, int h) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        sky(g, w, h);
        stars(g, w, h, 8);
    }

    private static void sky(Graphics2D g, int w, int h) {
        g.setPaint(new GradientPaint(0, 0, MoonTheme.SPACE_TOP, w * 0.3f, h, MoonTheme.SPACE_BOT));
        g.fillRect(0, 0, w, h);

        // indigo bloom, upper right
        radial(g, w * 0.86, -h * 0.12, Math.max(w, h) * 0.95,
                new Color(0x6f, 0x78, 0xef, 46), new Color(0x6f, 0x78, 0xef, 0));
        // faint warm counterweight, lower left
        radial(g, w * 0.06, h * 1.08, Math.max(w, h) * 0.75,
                new Color(0x8a, 0x5a, 0xff, 26), new Color(0x8a, 0x5a, 0xff, 0));
    }

    private static void radial(Graphics2D g, double cx, double cy, double r, Color inner, Color outer) {
        if (r <= 0) {
            return;
        }
        g.setPaint(new RadialGradientPaint(
                new Point2D.Double(cx, cy), (float) r,
                new float[]{0f, 1f}, new Color[]{inner, outer},
                MultipleGradientPaint.CycleMethod.NO_CYCLE));
        g.fill(new Ellipse2D.Double(cx - r, cy - r, r * 2, r * 2));
    }

    private static void stars(Graphics2D g, int w, int h, int density) {
        Random rnd = new Random(SEED);
        int count = Math.max(40, (w * h) / (1400 * (18 - density)));
        for (int i = 0; i < count; i++) {
            int x = rnd.nextInt(Math.max(1, w));
            int y = rnd.nextInt(Math.max(1, h));
            float b = 0.22f + rnd.nextFloat() * 0.68f;
            int size = rnd.nextInt(100) < 88 ? 1 : 2;
            g.setColor(new Color(MoonTheme.STAR.getRed() / 255f, MoonTheme.STAR.getGreen() / 255f,
                    MoonTheme.STAR.getBlue() / 255f, b));
            g.fillRect(x, y, size, size);
        }
    }

    /** Lit disc + craters + terminator shadow, with an indigo halo. */
    public static void drawMoon(Graphics2D g, double cx, double cy, double d) {
        double r = d / 2;

        // halo
        g.setPaint(new RadialGradientPaint(
                new Point2D.Double(cx, cy), (float) (r * 1.85),
                new float[]{0f, 0.52f, 1f},
                new Color[]{new Color(0x6f, 0x78, 0xef, 82),
                        new Color(0x6f, 0x78, 0xef, 26),
                        new Color(0x6f, 0x78, 0xef, 0)},
                MultipleGradientPaint.CycleMethod.NO_CYCLE));
        g.fill(new Ellipse2D.Double(cx - r * 1.85, cy - r * 1.85, r * 3.7, r * 3.7));

        // The crescent is a real shape (disc minus an offset disc), not a dark
        // disc painted on top: an opaque "shadow" circle reads as a hard black
        // blob wherever the backdrop behind it is not pure black.
        java.awt.geom.Area crescent = new java.awt.geom.Area(
                new Ellipse2D.Double(cx - r, cy - r, d, d));
        crescent.subtract(new java.awt.geom.Area(
                new Ellipse2D.Double(cx - r + d * 0.32, cy - r - d * 0.09, d, d)));

        java.awt.Shape oldClip = g.getClip();
        g.clip(crescent);

        g.setPaint(new RadialGradientPaint(
                new Point2D.Double(cx - r * 0.24, cy - r * 0.34), (float) (r * 1.45),
                new float[]{0f, 0.68f, 1f},
                new Color[]{MoonTheme.MOON_LIT, MoonTheme.MOON, MoonTheme.MOON_DARK},
                MultipleGradientPaint.CycleMethod.NO_CYCLE));
        g.fill(crescent);

        // craters, clipped to the lit crescent
        g.setColor(new Color(MoonTheme.MOON_CRATER.getRed(), MoonTheme.MOON_CRATER.getGreen(),
                MoonTheme.MOON_CRATER.getBlue(), 170));
        crater(g, cx - r * 0.42, cy - r * 0.30, r * 0.30);
        crater(g, cx - r * 0.20, cy + r * 0.42, r * 0.16);
        crater(g, cx - r * 0.58, cy + r * 0.16, r * 0.12);
        crater(g, cx - r * 0.12, cy - r * 0.62, r * 0.10);

        g.setClip(oldClip);
    }

    private static void crater(Graphics2D g, double cx, double cy, double r) {
        g.fill(new Ellipse2D.Double(cx - r, cy - r, r * 2, r * 2));
    }
}

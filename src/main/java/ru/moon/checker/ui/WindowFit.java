package ru.moon.checker.ui;

import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;

/**
 * Fits the main window on the player's screen. The design size (1180x800,
 * minimum 1000x700) is taller than the usable area of a 1366x768 laptop, and of
 * a 1920x1080 laptop at the default 150% scaling (1280x720 logical, minus the
 * taskbar): the bottom — where the buttons are — ended up under the taskbar and
 * the minimum size did not let the player shrink the window. Java works in
 * logical (scaled) pixels, so the usable screen bounds are compared directly.
 */
final class WindowFit {

    static final Dimension PREFERRED = new Dimension(1180, 800);
    static final Dimension MINIMUM = new Dimension(1000, 700);

    private WindowFit() {
    }

    /**
     * @param size     the window size to set
     * @param minimum  the minimum size, never larger than the screen
     * @param maximize the design size does not fit: open maximized
     */
    record Fit(Dimension size, Dimension minimum, boolean maximize) {
    }

    static Fit fit(Dimension preferred, Dimension minimum, Rectangle usable) {
        if (usable == null || usable.width <= 0 || usable.height <= 0) {
            return new Fit(preferred, minimum, false);
        }
        Dimension size = new Dimension(Math.min(preferred.width, usable.width), Math.min(preferred.height, usable.height));
        Dimension min = new Dimension(Math.min(minimum.width, usable.width), Math.min(minimum.height, usable.height));
        boolean maximize = preferred.width > usable.width || preferred.height > usable.height;
        return new Fit(size, min, maximize);
    }

    /** The screen area not covered by the taskbar, in Java's logical pixels; null if unknown. */
    static Rectangle usableScreen() {
        try {
            return GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        } catch (Exception | Error e) {
            return null;
        }
    }
}

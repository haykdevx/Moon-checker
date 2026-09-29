package ru.moon.checker.ui;

import org.junit.jupiter.api.Test;

import java.awt.Dimension;
import java.awt.Rectangle;

import static org.junit.jupiter.api.Assertions.*;

class WindowFitTest {

    @Test
    void aFullHdScreenGetsTheDesignSize() {
        WindowFit.Fit f = WindowFit.fit(WindowFit.PREFERRED, WindowFit.MINIMUM, new Rectangle(0, 0, 1920, 1040));
        assertEquals(WindowFit.PREFERRED, f.size());
        assertFalse(f.maximize());
    }

    @Test
    void aLaptopAt150PercentOpensMaximizedAndCanShrink() {
        // 1920x1080 at 150% = 1280x720 logical, minus a 48 px taskbar
        WindowFit.Fit f = WindowFit.fit(WindowFit.PREFERRED, WindowFit.MINIMUM, new Rectangle(0, 0, 1280, 672));
        assertTrue(f.maximize());
        assertTrue(f.size().height <= 672 && f.minimum().height <= 672, "buttons stay above the taskbar");
        assertEquals(new Dimension(1000, 672), f.minimum());
    }

    @Test
    void unknownScreenKeepsTheDesign() {
        WindowFit.Fit f = WindowFit.fit(WindowFit.PREFERRED, WindowFit.MINIMUM, null);
        assertEquals(WindowFit.PREFERRED, f.size());
    }
}

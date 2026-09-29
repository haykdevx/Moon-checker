package ru.moon.checker.ui;

import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.io.InputStream;

/**
 * The cs2-moon.ru visual identity. Values match the design canvas 1:1 so the
 * app and the mockups cannot drift apart.
 *
 * <p>Type rule that matters: <b>Orbitron has no Cyrillic glyphs</b>, so
 * {@link #display} is only for Latin text and numerals (the brand, the score).
 * Anything that can be Russian must use {@link #font}.
 */
public final class MoonTheme {

    // surfaces
    public static final Color BG = new Color(0x12, 0x14, 0x1f);
    public static final Color PANEL = new Color(0x1b, 0x1e, 0x2b);
    public static final Color PANEL2 = new Color(0x23, 0x27, 0x38);
    public static final Color CARD = new Color(0x1c, 0x20, 0x30);
    public static final Color LINE = new Color(0x26, 0x2b, 0x3d);
    public static final Color LINE2 = new Color(0x2c, 0x31, 0x45);

    // brand
    public static final Color ACCENT = new Color(0x6f, 0x78, 0xef);
    public static final Color ACCENT2 = new Color(0x9a, 0xa0, 0xff);
    public static final Color ACCENT_HI = new Color(0x81, 0x89, 0xf5);

    // text ramp
    public static final Color TEXT = new Color(0xec, 0xee, 0xf6);
    public static final Color TEXT2 = new Color(0xc2, 0xc7, 0xda);
    public static final Color MUTED = new Color(0x9a, 0xa0, 0xb8);
    public static final Color MUTED2 = new Color(0x8b, 0x90, 0xab);
    public static final Color FAINT = new Color(0x6a, 0x70, 0x91);
    public static final Color GHOST = new Color(0x4e, 0x54, 0x70);

    // space backdrop
    public static final Color SPACE_TOP = new Color(0x0a, 0x0c, 0x18);
    public static final Color SPACE_MID = new Color(0x12, 0x14, 0x1f);
    public static final Color SPACE_BOT = new Color(0x15, 0x12, 0x24);
    public static final Color STAR = new Color(0xd8, 0xdc, 0xf0);
    public static final Color MOON = new Color(0xe9, 0xe6, 0xda);
    public static final Color MOON_LIT = new Color(0xf6, 0xf4, 0xec);
    public static final Color MOON_DARK = new Color(0xbd, 0xb9, 0xab);
    public static final Color MOON_CRATER = new Color(0xcd, 0xc8, 0xba);
    public static final Color MOON_GLOW = new Color(0x6f, 0x78, 0xef);

    // verdict / severity
    public static final Color CLEAN = new Color(0x37, 0xd6, 0x7a);
    public static final Color SUSPICIOUS = new Color(0xf6, 0xb9, 0x49);
    public static final Color CHEAT = new Color(0xff, 0x5a, 0x5a);
    public static final Color HIGH = new Color(0xff, 0x8a, 0x5a);
    public static final Color INFO = new Color(0xb6, 0xb6, 0xc6);

    private static Font displayBase;
    private static final javax.swing.text.StyleContext FONTS = javax.swing.text.StyleContext.getDefaultStyleContext();

    private MoonTheme() {
    }

    public static void install() {
        try {
            loadDisplayFont();
            UIManager.put("Component.focusWidth", 1);
            UIManager.put("Button.arc", 12);
            UIManager.put("Component.arc", 12);
            UIManager.put("ProgressBar.arc", 10);
            UIManager.put("TextComponent.arc", 10);
            UIManager.put("ScrollBar.thumbArc", 10);
            UIManager.put("ScrollBar.width", 11);
            FlatDarkLaf.setup();
            UIManager.put("@background", BG);
            UIManager.put("@accentColor", ACCENT);
            UIManager.put("Panel.background", BG);
            UIManager.put("Table.background", PANEL);
            UIManager.put("Table.alternateRowColor", null);
            UIManager.put("Table.gridColor", new Color(0, 0, 0, 0));
            UIManager.put("Table.foreground", TEXT);
            UIManager.put("Table.showHorizontalLines", false);
            UIManager.put("Table.showVerticalLines", false);
            UIManager.put("Table.intercellSpacing", new java.awt.Dimension(0, 4));
            UIManager.put("Table.selectionBackground", new Color(0x2c, 0x33, 0x52));
            UIManager.put("Table.selectionForeground", TEXT);
            UIManager.put("TableHeader.background", BG);
            UIManager.put("TableHeader.foreground", FAINT);
            UIManager.put("TableHeader.separatorColor", LINE);
            UIManager.put("TableHeader.bottomSeparatorColor", LINE);
            UIManager.put("Component.accentColor", ACCENT);
            UIManager.put("ComboBox.background", CARD);
            UIManager.put("TextField.background", CARD);
            UIManager.put("ScrollPane.background", BG);
            UIManager.put("TabbedPane.background", BG);
            UIManager.put("TabbedPane.underlineColor", ACCENT);
            UIManager.put("TabbedPane.selectedForeground", TEXT);
            UIManager.put("TabbedPane.foreground", MUTED);
            UIManager.put("TabbedPane.contentSeparatorHeight", 0);
            UIManager.put("TabbedPane.tabSeparatorsFullHeight", false);
        } catch (Throwable t) {
            // fall back to whatever L&F is available
        }
    }

    private static void loadDisplayFont() {
        if (displayBase != null) {
            return;
        }
        try (InputStream in = MoonTheme.class.getResourceAsStream("/fonts/Orbitron.ttf")) {
            if (in != null) {
                displayBase = Font.createFont(Font.TRUETYPE_FONT, in);
                GraphicsEnvironment.getLocalGraphicsEnvironment().registerFont(displayBase);
            }
        } catch (Throwable t) {
            displayBase = null;
        }
    }

    /**
     * Body font — use for anything that can contain Cyrillic. Taken through StyleContext so
     * characters Segoe UI lacks (✓ ✗ ⚠) fall back to another Windows font instead of a box.
     */
    public static Font font(int style, int size) {
        return FONTS.getFont("Segoe UI", style, size);
    }

    /** Monospace, for paths, hashes and timestamps. */
    public static Font mono(int style, int size) {
        return FONTS.getFont("Consolas", style, size);
    }


    /** Brand / numeral font. Latin and digits ONLY — Orbitron lacks Cyrillic. */
    public static Font display(int style, int size) {
        if (displayBase != null) {
            return displayBase.deriveFont(style, (float) size);
        }
        return new Font("Segoe UI", style | Font.BOLD, size);
    }

    public static Color severityColor(String sev) {
        return switch (sev) {
            case "CRITICAL" -> CHEAT;
            case "HIGH" -> HIGH;
            case "MEDIUM" -> SUSPICIOUS;
            case "LOW" -> ACCENT2;
            default -> INFO;
        };
    }

    /** Translucent wash of a severity colour, for row backgrounds. */
    public static Color severityWash(String sev, int alpha) {
        Color c = severityColor(sev);
        return new Color(c.getRed(), c.getGreen(), c.getBlue(), alpha);
    }
}

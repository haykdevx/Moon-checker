package ru.moon.checker.ui;

import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.io.InputStream;

/**
 * The cs2-moon.ru visual identity: an indigo accent on deep space, with the
 * Orbitron display font for the brand and headings. All panels pull colours
 * and fonts from here so the app reads as one "Moon" system.
 */
public final class MoonTheme {

    // core surfaces
    public static final Color BG = new Color(0x12, 0x14, 0x1f);
    public static final Color PANEL = new Color(0x1b, 0x1e, 0x2b);
    public static final Color PANEL2 = new Color(0x23, 0x27, 0x38);
    public static final Color LINE = new Color(0x33, 0x38, 0x4d);
    public static final Color ACCENT = new Color(0x6f, 0x78, 0xef);
    public static final Color ACCENT2 = new Color(0x9a, 0xa0, 0xff);
    public static final Color TEXT = new Color(0xec, 0xee, 0xf6);
    public static final Color MUTED = new Color(0x9a, 0xa0, 0xb8);

    // space backdrop
    public static final Color SPACE_TOP = new Color(0x0a, 0x0c, 0x18);
    public static final Color SPACE_BOT = new Color(0x15, 0x12, 0x24);
    public static final Color STAR = new Color(0xd8, 0xdc, 0xf0);
    public static final Color MOON = new Color(0xe9, 0xe6, 0xda);
    public static final Color MOON_GLOW = new Color(0x6f, 0x78, 0xef);

    // verdict colours
    public static final Color CLEAN = new Color(0x37, 0xd6, 0x7a);
    public static final Color SUSPICIOUS = new Color(0xf6, 0xb9, 0x49);
    public static final Color CHEAT = new Color(0xff, 0x5a, 0x5a);
    public static final Color INFO = new Color(0xb6, 0xb6, 0xc6);

    private static Font displayBase;

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
            UIManager.put("ScrollBar.width", 12);
            FlatDarkLaf.setup();
            UIManager.put("@background", BG);
            UIManager.put("@accentColor", ACCENT);
            UIManager.put("Panel.background", BG);
            UIManager.put("Table.background", PANEL);
            UIManager.put("Table.alternateRowColor", PANEL2);
            UIManager.put("Table.gridColor", LINE);
            UIManager.put("Table.foreground", TEXT);
            UIManager.put("TableHeader.background", PANEL2);
            UIManager.put("TableHeader.foreground", MUTED);
            UIManager.put("Component.accentColor", ACCENT);
            UIManager.put("ComboBox.background", PANEL2);
            UIManager.put("TextField.background", PANEL2);
            UIManager.put("ScrollPane.background", BG);
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

    /** Body font (system sans). */
    public static Font font(int style, int size) {
        return new Font("Segoe UI", style, size);
    }

    /** Brand / heading font (Orbitron if available, else a bold sans). */
    public static Font display(int style, int size) {
        if (displayBase != null) {
            return displayBase.deriveFont(style, (float) size);
        }
        return new Font("Segoe UI", style | Font.BOLD, size);
    }

    public static Color severityColor(String sev) {
        return switch (sev) {
            case "CRITICAL" -> CHEAT;
            case "HIGH" -> new Color(0xff, 0x8a, 0x5a);
            case "MEDIUM" -> SUSPICIOUS;
            case "LOW" -> ACCENT2;
            default -> INFO;
        };
    }
}

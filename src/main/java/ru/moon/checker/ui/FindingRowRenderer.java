package ru.moon.checker.ui;

import ru.moon.checker.core.Finding;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * Paints each finding as a card: a severity spine, the severity label, the
 * title with its evidence path underneath, then source and time. Keeping it a
 * {@code JTable} renderer rather than a list of panels means sorting, filtering
 * and keyboard navigation still work while it looks like the design.
 */
public final class FindingRowRenderer extends JComponent implements TableCellRenderer {

    /** Column layout, as fractions of the table width. */
    private static final int SEV_W = 74;
    private static final int RIGHT_SOURCE_W = 130;
    private static final int RIGHT_TIME_W = 92;

    private Finding finding;
    private boolean selected;
    private String timeText = "";
    private String categoryText = "";

    public interface Source {
        Finding findingAt(int modelRow);

        String timeAt(int modelRow);

        String categoryAt(int modelRow);
    }

    private final Source source;

    public FindingRowRenderer(Source source) {
        this.source = source;
        setOpaque(false);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        int modelRow = table.convertRowIndexToModel(row);
        this.finding = source.findingAt(modelRow);
        this.timeText = source.timeAt(modelRow);
        this.categoryText = source.categoryAt(modelRow);
        this.selected = isSelected;
        return this;
    }

    @Override
    protected void paintComponent(Graphics g) {
        if (finding == null) {
            return;
        }
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();
        String sev = finding.severity().name();
        Color sevColor = MoonTheme.severityColor(sev);
        boolean strong = sev.equals("CRITICAL") || sev.equals("HIGH");

        // card background: a wash of the severity colour for strong findings
        if (selected) {
            g2.setColor(new Color(0x2c, 0x33, 0x52));
            g2.fillRoundRect(0, 0, w - 1, h - 1, 11, 11);
            g2.setColor(MoonTheme.ACCENT);
            g2.drawRoundRect(0, 0, w - 1, h - 1, 11, 11);
        } else if (strong) {
            g2.setPaint(new GradientPaint(0, 0, MoonTheme.severityWash(sev, 30),
                    w, 0, MoonTheme.severityWash(sev, 8)));
            g2.fillRoundRect(0, 0, w - 1, h - 1, 11, 11);
            g2.setColor(MoonTheme.severityWash(sev, 62));
            g2.drawRoundRect(0, 0, w - 1, h - 1, 11, 11);
        } else {
            g2.setColor(new Color(0xff, 0xff, 0xff, 6));
            g2.fillRoundRect(0, 0, w - 1, h - 1, 11, 11);
            g2.setColor(MoonTheme.LINE);
            g2.drawRoundRect(0, 0, w - 1, h - 1, 11, 11);
        }

        // severity spine
        g2.setColor(sevColor);
        g2.fillRoundRect(9, 9, 3, h - 18, 2, 2);

        // severity label
        g2.setFont(MoonTheme.display(Font.BOLD, 9));
        g2.setColor(sevColor);
        g2.drawString(sev, 20, h / 2 + 3);

        int textX = 20 + SEV_W;
        int rightEdge = w - 14;
        int timeX = rightEdge - RIGHT_TIME_W;
        int sourceX = timeX - RIGHT_SOURCE_W;

        // title + evidence
        g2.setFont(MoonTheme.font(Font.BOLD, 13));
        g2.setColor(selected || strong ? MoonTheme.TEXT : MoonTheme.TEXT2);
        g2.drawString(clip(g2.getFontMetrics(), finding.title(), sourceX - textX - 12), textX, h / 2 - 2);

        String evidence = finding.evidence() != null ? finding.evidence()
                : (finding.detail() != null ? finding.detail() : "");
        if (!evidence.isEmpty()) {
            g2.setFont(MoonTheme.mono(Font.PLAIN, 10));
            g2.setColor(MoonTheme.MUTED2);
            g2.drawString(clip(g2.getFontMetrics(), evidence, sourceX - textX - 12), textX, h / 2 + 13);
        }

        // category (small, above source column)
        g2.setFont(MoonTheme.font(Font.PLAIN, 10));
        g2.setColor(MoonTheme.FAINT);
        g2.drawString(clip(g2.getFontMetrics(), categoryText, RIGHT_SOURCE_W - 8), sourceX, h / 2 - 2);

        // source
        String src = finding.source() == null ? "" : finding.source();
        g2.setColor(MoonTheme.MUTED2);
        g2.drawString(clip(g2.getFontMetrics(), src, RIGHT_SOURCE_W - 8), sourceX, h / 2 + 13);

        // time, right aligned
        g2.setFont(MoonTheme.mono(Font.PLAIN, 10));
        FontMetrics tfm = g2.getFontMetrics();
        String t = timeText == null || timeText.isEmpty() ? "—" : timeText;
        g2.setColor(t.equals("—") ? MoonTheme.GHOST : MoonTheme.MUTED);
        g2.drawString(t, rightEdge - tfm.stringWidth(t), h / 2 + 5);

        g2.dispose();
    }

    private static String clip(FontMetrics fm, String text, int maxWidth) {
        if (text == null) {
            return "";
        }
        if (maxWidth <= 0 || fm.stringWidth(text) <= maxWidth) {
            return text;
        }
        String ellipsis = "…";
        int w = fm.stringWidth(ellipsis);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            int cw = fm.charWidth(text.charAt(i));
            if (w + cw > maxWidth) {
                break;
            }
            w += cw;
            sb.append(text.charAt(i));
        }
        return sb + ellipsis;
    }
}

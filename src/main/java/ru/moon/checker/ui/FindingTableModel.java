package ru.moon.checker.ui;

import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Severity;

import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Filterable table model backing the results table. */
public final class FindingTableModel extends AbstractTableModel {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final List<Finding> all;
    private List<Finding> view;

    private Severity minSeverity = null;
    private String moduleFilter = null;
    private String textFilter = "";

    public FindingTableModel(List<Finding> findings) {
        this.all = new ArrayList<>(findings);
        this.view = new ArrayList<>(findings);
    }

    public void setFilter(Severity minSeverity, String moduleFilter, String text) {
        this.minSeverity = minSeverity;
        this.moduleFilter = moduleFilter;
        this.textFilter = text == null ? "" : text.toLowerCase(Locale.ROOT);
        apply();
    }

    private void apply() {
        List<Finding> next = new ArrayList<>();
        for (Finding f : all) {
            if (minSeverity != null && f.severity().rank() < minSeverity.rank()) {
                continue;
            }
            if (moduleFilter != null && !moduleFilter.equals(f.module())) {
                continue;
            }
            if (!textFilter.isEmpty() && !matchesText(f)) {
                continue;
            }
            next.add(f);
        }
        this.view = next;
        fireTableDataChanged();
    }

    private boolean matchesText(Finding f) {
        return contains(f.title()) || contains(f.detail()) || contains(f.evidence()) || contains(f.source());
    }

    private boolean contains(String s) {
        return s != null && s.toLowerCase(Locale.ROOT).contains(textFilter);
    }

    public Finding at(int row) {
        return row >= 0 && row < view.size() ? view.get(row) : null;
    }

    @Override
    public int getRowCount() {
        return view.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int c) {
        return switch (c) {
            case 0 -> I18n.t("col.severity");
            case 1 -> I18n.t("col.category");
            case 2 -> I18n.t("col.finding");
            case 3 -> I18n.t("col.source");
            default -> I18n.t("col.time");
        };
    }

    @Override
    public Object getValueAt(int r, int c) {
        Finding f = view.get(r);
        return switch (c) {
            case 0 -> f.severity().name();
            case 1 -> I18n.t(f.category().key());
            case 2 -> f.title();
            case 3 -> f.source() == null ? "" : f.source();
            default -> f.when() == null ? "—" : TS.format(f.when());
        };
    }
}

package ru.moon.checker.ui;

import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Severity;

import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Backs the findings list. One column: each row is a whole card painted by
 * {@link FindingRowRenderer}. Filtering and sorting live here rather than in a
 * table row-sorter, because the card layout has no per-column headers to click.
 */
public final class FindingTableModel extends AbstractTableModel implements FindingRowRenderer.Source {

    /** Sort orders offered in the toolbar. */
    public enum Sort {
        SEVERITY("sort.severity"),
        NEWEST("sort.newest"),
        MODULE("sort.module");

        private final String key;

        Sort(String key) {
            this.key = key;
        }

        @Override
        public String toString() {
            return I18n.t(key);
        }
    }

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final List<Finding> all;
    private List<Finding> view;

    private Severity minSeverity;
    private String moduleFilter;
    private String textFilter = "";
    private Sort sort = Sort.SEVERITY;

    public FindingTableModel(List<Finding> findings) {
        this.all = new ArrayList<>(findings);
        this.view = new ArrayList<>(findings);
        apply();
    }

    public void setFilter(Severity minSeverity, String moduleFilter, String text) {
        this.minSeverity = minSeverity;
        this.moduleFilter = moduleFilter;
        this.textFilter = text == null ? "" : text.toLowerCase(Locale.ROOT);
        apply();
    }

    public void setSort(Sort sort) {
        this.sort = sort == null ? Sort.SEVERITY : sort;
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
        next.sort(comparator());
        this.view = next;
        fireTableDataChanged();
    }

    private Comparator<Finding> comparator() {
        return switch (sort) {
            case NEWEST -> Comparator
                    .comparing((Finding f) -> f.when() == null ? java.time.Instant.EPOCH : f.when())
                    .reversed()
                    .thenComparing(f -> -f.severity().rank());
            case MODULE -> Comparator.comparing(Finding::module)
                    .thenComparing(f -> -f.severity().rank());
            default -> Comparator.comparingInt((Finding f) -> f.severity().rank()).reversed()
                    .thenComparing(Finding::module);
        };
    }

    private boolean matchesText(Finding f) {
        return contains(f.title()) || contains(f.detail())
                || contains(f.evidence()) || contains(f.source());
    }

    private boolean contains(String s) {
        return s != null && s.toLowerCase(Locale.ROOT).contains(textFilter);
    }

    public Finding at(int row) {
        return row >= 0 && row < view.size() ? view.get(row) : null;
    }

    // ---- table model -----------------------------------------------------

    @Override
    public int getRowCount() {
        return view.size();
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public String getColumnName(int c) {
        return I18n.t("col.finding");
    }

    @Override
    public Object getValueAt(int r, int c) {
        return view.get(r);
    }

    // ---- renderer source -------------------------------------------------

    @Override
    public Finding findingAt(int modelRow) {
        return at(modelRow);
    }

    @Override
    public String timeAt(int modelRow) {
        Finding f = at(modelRow);
        return f == null || f.when() == null ? "" : TS.format(f.when());
    }

    @Override
    public String categoryAt(int modelRow) {
        Finding f = at(modelRow);
        return f == null ? "" : I18n.t(f.category().key());
    }
}

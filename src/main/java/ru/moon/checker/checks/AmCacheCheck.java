package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.win.AmCache;
import ru.moon.checker.win.AmCacheRecords;

import java.util.Locale;

/**
 * Matches AmCache entries (path + SHA-1 of every executable Windows has seen,
 * kept even after deletion) against the cheat signatures, and the AmCache driver
 * inventory against the vulnerable-driver list. Because AmCache outlives the
 * file, this catches cheats and BYOVD drivers that were removed before the
 * inspection.
 */
public final class AmCacheCheck implements CheckModule {

    public static final String ID = "amcache";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.amcache");
    }

    @Override
    public Category category() {
        return Category.EXECUTION;
    }

    @Override
    public void run(ScanContext ctx) {
        ctx.log(I18n.t("log.amcache"));
        AmCache.Snapshot snap = AmCache.readAll();
        if (snap.error() != null && ctx.isElevated()) {
            ctx.emit(Finding.builder(Category.EXECUTION, Severity.INFO,
                            "AmCache недоступен / AmCache could not be read")
                    .module(ID).detail(snap.error()).source("AmCache").build());
        }
        for (AmCache.Entry e : snap.files()) {
            if (ctx.isCancelled()) {
                return;
            }
            String haystack = ((e.path() == null ? "" : e.path()) + " "
                    + (e.name() == null ? "" : e.name())).toLowerCase(Locale.ROOT);
            ctx.signatures().matchCheatName(haystack).ifPresent(rule ->
                    ctx.emit(Finding.builder(Category.EXECUTION, rule.severity(),
                                    "Чит в AmCache (запускался ранее) / Cheat in AmCache (previously run)")
                            .module(ID)
                            .detail(rule.label()
                                    + (e.sha1() != null ? "  [sha1=" + e.sha1() + "]" : ""))
                            .evidence(e.path() != null ? e.path() : e.name())
                            .source("AmCache")
                            .build()));
        }
        for (AmCacheRecords.Driver d : snap.drivers()) {
            if (ctx.isCancelled()) {
                return;
            }
            reportDriver(ctx, d);
        }
    }

    /**
     * The driver inventory proves the binary was present on this Windows install
     * at some point, not that it is loaded now (KernelCheck reports that at full
     * severity), so matches here are capped at HIGH.
     */
    static void reportDriver(ScanContext ctx, AmCacheRecords.Driver d) {
        String detailTail = (d.sha1() != null ? "  [sha1=" + d.sha1() + "]" : "")
                + (d.signed() ? ", signed" : ", UNSIGNED")
                + (d.company() != null ? ", " + d.company() : "")
                + (d.service() != null ? ", service " + d.service() : "")
                + (d.lastWrite() != null ? ", file time " + d.lastWrite() : "");
        ctx.signatures().matchDriver(d.name()).ifPresent(rule ->
                ctx.emit(Finding.builder(Category.KERNEL, cap(rule.severity()),
                                "Уязвимый драйвер в истории AmCache / Vulnerable driver recorded in AmCache")
                        .module(ID)
                        .detail(rule.label() + detailTail)
                        .evidence(d.path() != null ? d.path() : d.name())
                        .source("AmCache InventoryDriverBinary")
                        .build()));
        ctx.signatures().matchCheatName(d.name()).ifPresent(rule ->
                ctx.emit(Finding.builder(Category.KERNEL, cap(rule.severity()),
                                "Драйвер чита в истории AmCache / Cheat driver recorded in AmCache")
                        .module(ID)
                        .detail(rule.label() + detailTail)
                        .evidence(d.path() != null ? d.path() : d.name())
                        .source("AmCache InventoryDriverBinary")
                        .build()));
    }

    private static Severity cap(Severity s) {
        return s == Severity.CRITICAL ? Severity.HIGH : s;
    }
}

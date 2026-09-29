package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.win.AmCache;

import java.util.Locale;

/**
 * Matches AmCache entries (path + SHA-1 of every executable Windows has seen,
 * kept even after deletion) against the cheat signatures. Because AmCache
 * outlives the file, this catches cheats that were run and then removed before
 * the inspection.
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
        AmCache.Snapshot snapshot = AmCache.readAll();
        if (snapshot.problem() != null) {
            // the inventory could not be read: say so (incomplete scan), never "nothing found"
            throw new IllegalStateException(snapshot.problem());
        }
        drivers(ctx, snapshot);
        for (AmCache.Entry e : snapshot.files()) {
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
    }

    /**
     * Driver binaries Windows has recorded. Catches a vulnerable/mapper driver
     * (BYOVD) that was loaded once and then deleted from disk.
     */
    private void drivers(ScanContext ctx, AmCache.Snapshot snapshot) {
        for (AmCache.Driver d : snapshot.drivers()) {
            if (ctx.isCancelled()) {
                return;
            }
            if (d.path() == null) {
                continue;
            }
            String low = d.path().toLowerCase(Locale.ROOT);
            ctx.signatures().matchDriver(low).ifPresent(rule ->
                    ctx.emit(DriverPlacement.finding(rule, d.path(), ID,
                            "AmCache (drivers)" + (d.signed() != null ? ", signed=" + d.signed() : ""))));
            ctx.signatures().matchCheatName(low).ifPresent(rule ->
                    ctx.emit(Finding.builder(ru.moon.checker.core.Category.KERNEL,
                                    ru.moon.checker.core.Severity.CRITICAL,
                                    "Драйвер чита в AmCache / Cheat driver recorded in AmCache")
                            .module(ID)
                            .detail(rule.label())
                            .evidence(d.path())
                            .source("AmCache (drivers)")
                            .build()));
        }
    }
}

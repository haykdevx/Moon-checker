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
        for (AmCache.Entry e : AmCache.read()) {
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
}

package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Windows' DNS cache against the cheat-site rules: names the PC looked up recently, whichever
 * program did it and even when browser history was cleared. The cache keeps a name from minutes
 * to about a day (the record's lifetime), and is emptied by a restart or ipconfig /flushdns —
 * an empty cache is not evidence of anything.
 */
public final class DnsCacheCheck implements CheckModule {

    public static final String ID = "dns";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.dns");
    }

    @Override
    public Category category() {
        return Category.BROWSER;
    }

    @Override
    public boolean windowsOnly() {
        return true;
    }

    @Override
    public boolean required() {
        return false; // the cache is short-lived; useful context, not coverage the outcome depends on
    }

    @Override
    public void run(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        ctx.log(I18n.t("log.dns"));
        ru.moon.checker.win.WinCommand.Result r = ru.moon.checker.win.WinCommand.powershell(30,
                "Get-DnsClientCache | ForEach-Object { $_.Entry }");
        if (r.timedOut() || r.exitCode() < 0) {
            throw new IllegalStateException("the DNS cache could not be read");
        }
        Set<String> names = names(r.output());
        int hits = 0;
        for (String name : names) {
            var rule = ctx.signatures().matchDomain(name);
            if (rule.isPresent()) {
                hits++;
                ctx.emit(Finding.builder(Category.BROWSER, rule.get().severity(),
                                "Сайт читов в DNS-кэше / Cheat site in the DNS cache")
                        .module(ID).rule("dns:cheat-domain-cached")
                        .detail(rule.get().label() + " — looked up by this PC recently (any program, browser history "
                                + "not needed)")
                        .evidence(name).source("DNS client cache").build());
            }
        }
        ctx.emit(Finding.builder(Category.BROWSER, Severity.INFO,
                        "Проверка DNS-кэша / DNS cache checked")
                .module(ID).kind(EvidenceKind.CONTEXT).rule("dns:cache-checked")
                .detail(names.size() + " cached name(s), " + hits + " matching cheat sites. The cache only holds recent "
                        + "lookups and is emptied by a restart or ipconfig /flushdns.")
                .source("DNS client cache").build());
    }

    /** Host names from the cache listing, lower-case, without duplicates or junk. */
    static Set<String> names(String output) {
        Set<String> out = new LinkedHashSet<>();
        if (output == null) {
            return out;
        }
        for (String line : output.split("\\R")) {
            String n = line.strip().toLowerCase(Locale.ROOT);
            if (n.endsWith(".")) {
                n = n.substring(0, n.length() - 1);
            }
            if (n.matches("[a-z0-9_.-]+\\.[a-z0-9-]{2,}")) {
                out.add(n);
            }
        }
        return out;
    }
}

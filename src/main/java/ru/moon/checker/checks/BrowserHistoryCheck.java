package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.parse.BrowserHistory;
import ru.moon.checker.signatures.SignatureRule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reads browser history from every installed Chromium-family browser and
 * Firefox, and reports only visits to cheat-related domains from the signature
 * list. The player's full history is never displayed or stored — matches only.
 * Results are aggregated to one finding per domain (count + most recent visit).
 */
public final class BrowserHistoryCheck implements CheckModule {

    public static final String ID = "browser";

    private record Agg(SignatureRule rule, int count, Instant last, String example) {
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public boolean required() {
        return false; // context for the reviewer, not coverage the verdict depends on
    }

    @Override
    public String displayName() {
        return I18n.t("module.browser");
    }

    @Override
    public Category category() {
        return Category.BROWSER;
    }

    @Override
    public void run(ScanContext ctx) throws Exception {
        Map<String, Agg> byRule = new LinkedHashMap<>();
        java.util.Set<String> reportedDownloads = new java.util.HashSet<>();
        Path tmp = Files.createTempDirectory("moon-hist");
        try {
            for (Path db : chromiumHistories()) {
                ctx.log(I18n.t("log.browser", shortName(db)));
                Path localCopy = copy(db, tmp);
                match(ctx, BrowserHistory.readChromium(localCopy), byRule);
                matchDownloads(ctx, BrowserHistory.readChromiumDownloads(localCopy), byRule, reportedDownloads);
                Path bookmarks = db.getParent() == null ? null : db.getParent().resolve("Bookmarks");
                if (bookmarks != null) {
                    matchUrls(BrowserHistory.readChromiumBookmarkUrls(bookmarks), ctx, byRule);
                }
            }
            for (Path db : firefoxHistories()) {
                ctx.log(I18n.t("log.browser", shortName(db)));
                Path localCopy = copy(db, tmp);
                match(ctx, BrowserHistory.readFirefox(localCopy), byRule);
                matchUrls(BrowserHistory.readFirefoxBookmarkUrls(localCopy), ctx, byRule);
            }
        } finally {
            deleteTree(tmp);
        }

        for (Agg a : byRule.values()) {
            ctx.emit(Finding.builder(Category.BROWSER, a.rule.severity(),
                            "Посещён сайт читов / Cheat-related site visited")
                    .module(ID)
                    .detail(a.rule.label() + "  (посещений/visits: " + a.count + ")")
                    .evidence(a.example)
                    .source("browser history")
                    .when(a.last)
                    .build());
        }
    }

    private void match(ScanContext ctx, List<BrowserHistory.Visit> visits, Map<String, Agg> byRule) {
        for (BrowserHistory.Visit v : visits) {
            aggregateUrl(ctx, v.url(), v.lastVisit(), byRule);
        }
    }

    private void matchUrls(List<String> urls, ScanContext ctx, Map<String, Agg> byRule) {
        for (String url : urls) {
            aggregateUrl(ctx, url, null, byRule);
        }
    }

    private void aggregateUrl(ScanContext ctx, String url, Instant when, Map<String, Agg> byRule) {
        if (url == null) {
            return;
        }
        ctx.signatures().matchDomain(url).ifPresent(rule -> {
            Agg prev = byRule.get(rule.label());
            int count = prev == null ? 1 : prev.count + 1;
            Instant last = prev == null ? when : laterOf(prev.last, when);
            String example = prev == null ? url : prev.example;
            byRule.put(rule.label(), new Agg(rule, count, last, example));
        });
    }

    /** Downloaded files matching a cheat name are strong evidence. */
    private void matchDownloads(ScanContext ctx, List<BrowserHistory.Download> downloads,
                                Map<String, Agg> byRule, java.util.Set<String> reported) {
        for (BrowserHistory.Download d : downloads) {
            aggregateUrl(ctx, d.url(), d.when(), byRule);
            String path = d.targetPath();
            if (path == null) {
                continue;
            }
            String base = path.replace('/', '\\');
            int slash = base.lastIndexOf('\\');
            String name = slash >= 0 ? base.substring(slash + 1) : base;
            ctx.signatures().matchCheatName(name.toLowerCase(Locale.ROOT)).ifPresent(rule -> {
                if (reported.add(path)) {
                    ctx.emit(Finding.builder(Category.BROWSER, rule.severity(),
                                    "Скачан файл чита / Cheat file downloaded")
                            .module(ID)
                            .detail(rule.label())
                            .evidence(path + (d.url() != null ? "  ← " + d.url() : ""))
                            .source("browser downloads")
                            .when(d.when())
                            .build());
                }
            });
        }
    }

    private List<Path> chromiumHistories() {
        List<Path> out = new ArrayList<>();
        for (Path profile : Platform.userProfiles()) {
            Path local = Platform.localAppData(profile);
            Path roaming = Platform.roamingAppData(profile);
            addProfileHistories(out, local.resolve("Google").resolve("Chrome").resolve("User Data"));
            addProfileHistories(out, local.resolve("Microsoft").resolve("Edge").resolve("User Data"));
            addProfileHistories(out, local.resolve("BraveSoftware").resolve("Brave-Browser").resolve("User Data"));
            addProfileHistories(out, local.resolve("Yandex").resolve("YandexBrowser").resolve("User Data"));
            addProfileHistories(out, roaming.resolve("Opera Software").resolve("Opera Stable"));
            addProfileHistories(out, roaming.resolve("Opera Software").resolve("Opera GX Stable"));
        }
        return out;
    }

    private void addProfileHistories(List<Path> out, Path userDataDir) {
        if (!Files.isDirectory(userDataDir)) {
            return;
        }
        // History directly (Opera) or under each profile subfolder (Chrome/Edge)
        Path direct = userDataDir.resolve("History");
        if (Files.isRegularFile(direct)) {
            out.add(direct);
        }
        try (var stream = Files.list(userDataDir)) {
            stream.filter(Files::isDirectory).forEach(p -> {
                Path h = p.resolve("History");
                if (Files.isRegularFile(h)) {
                    out.add(h);
                }
            });
        } catch (Exception ignored) {
        }
    }

    private List<Path> firefoxHistories() {
        List<Path> out = new ArrayList<>();
        for (Path profile : Platform.userProfiles()) {
            Path profiles = Platform.roamingAppData(profile)
                    .resolve("Mozilla").resolve("Firefox").resolve("Profiles");
            if (!Files.isDirectory(profiles)) {
                continue;
            }
            try (var stream = Files.list(profiles)) {
                stream.filter(Files::isDirectory).forEach(p -> {
                    Path places = p.resolve("places.sqlite");
                    if (Files.isRegularFile(places)) {
                        out.add(places);
                    }
                });
            } catch (Exception ignored) {
            }
        }
        return out;
    }

    private Path copy(Path db, Path tmpDir) {
        try {
            Path dest = tmpDir.resolve(db.getParent().getFileName() + "-" + db.getFileName());
            Files.copy(db, dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            return dest;
        } catch (Exception e) {
            return db; // fall back to reading the original (immutable mode)
        }
    }

    private static Instant laterOf(Instant a, Instant b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.isAfter(b) ? a : b;
    }

    private static String shortName(Path db) {
        Path parent = db.getParent();
        return parent != null ? parent.getFileName().toString() : db.getFileName().toString();
    }

    private void deleteTree(Path dir) {
        try (var walk = Files.walk(dir)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                }
            });
        } catch (Exception ignored) {
        }
    }
}

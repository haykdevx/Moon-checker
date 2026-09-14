package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.parse.BrowserHistory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Linux browsing and shell history. Reads Chromium-family and Firefox history,
 * downloads and bookmarks (Linux profile paths) and matches URLs / downloaded
 * filenames against the cheat-site and cheat-name signatures. Also scans shell
 * history ({@code .bash_history}, {@code .zsh_history}) for cheat sites and for
 * {@code curl|wget|git} of a cheat, or a cheat run from the shell. Matches only.
 */
public final class LinuxHistoryCheck implements CheckModule {

    public static final String ID = "linuxhist";

    private final Set<String> reported = new HashSet<>();

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.linuxhist");
    }

    @Override
    public Category category() {
        return Category.BROWSER;
    }

    @Override
    public boolean windowsOnly() {
        return false;
    }

    @Override
    public void run(ScanContext ctx) throws Exception {
        if (!Platform.isLinux()) {
            return;
        }
        Path tmp = Files.createTempDirectory("moon-lhist");
        try {
            for (Path db : chromiumHistories()) {
                ctx.log(I18n.t("log.browser", db.getParent() != null ? db.getParent().getFileName().toString() : "chrome"));
                Path copy = copy(db, tmp);
                for (var v : BrowserHistory.readChromium(copy)) {
                    matchUrl(ctx, v.url(), "browser history");
                }
                for (var d : BrowserHistory.readChromiumDownloads(copy)) {
                    matchUrl(ctx, d.url(), "browser downloads");
                    matchName(ctx, d.targetPath(), "browser downloads");
                }
                Path bm = db.getParent() == null ? null : db.getParent().resolve("Bookmarks");
                if (bm != null) {
                    for (String u : BrowserHistory.readChromiumBookmarkUrls(bm)) {
                        matchUrl(ctx, u, "bookmarks");
                    }
                }
            }
            for (Path db : firefoxHistories()) {
                ctx.log(I18n.t("log.browser", "firefox"));
                Path copy = copy(db, tmp);
                for (var v : BrowserHistory.readFirefox(copy)) {
                    matchUrl(ctx, v.url(), "browser history");
                }
                for (String u : BrowserHistory.readFirefoxBookmarkUrls(copy)) {
                    matchUrl(ctx, u, "bookmarks");
                }
            }
        } finally {
            deleteTree(tmp);
        }
        shellHistory(ctx);
    }

    private void matchUrl(ScanContext ctx, String url, String source) {
        if (url == null) {
            return;
        }
        ctx.signatures().matchDomain(url).ifPresent(rule -> {
            if (reported.add(rule.label() + "|" + source)) {
                ctx.emit(Finding.builder(Category.BROWSER, rule.severity(),
                                "Посещён сайт читов / Cheat-related site")
                        .module(ID).detail(rule.label() + " — " + source)
                        .evidence(url).source(source).build());
            }
        });
    }

    private void matchName(ScanContext ctx, String path, String source) {
        if (path == null) {
            return;
        }
        String base = path.substring(path.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
        ctx.signatures().matchCheatName(base).ifPresent(rule ->
                ctx.emit(Finding.builder(Category.BROWSER, rule.severity(),
                                "Скачан файл чита / Cheat file downloaded")
                        .module(ID).detail(rule.label()).evidence(path).source(source).build()));
    }

    private void shellHistory(ScanContext ctx) {
        for (Path home : Platform.userProfiles()) {
            for (String rc : new String[]{".bash_history", ".zsh_history",
                    ".local/share/fish/fish_history", ".python_history"}) {
                Path h = home.resolve(rc);
                if (!Files.isRegularFile(h)) {
                    continue;
                }
                try {
                    for (String line : Files.readAllLines(h)) {
                        String low = line.toLowerCase(Locale.ROOT);
                        ctx.signatures().matchDomain(low).ifPresent(rule -> emitShell(ctx, rule.label(), line, h));
                        ctx.signatures().matchCheatName(low).ifPresent(rule -> emitShell(ctx, rule.label(), line, h));
                    }
                } catch (Exception ignored) {
                    // unreadable
                }
            }
        }
    }

    private void emitShell(ScanContext ctx, String label, String line, Path file) {
        if (reported.add("shell|" + label + "|" + line)) {
            ctx.emit(Finding.builder(Category.BROWSER, ru.moon.checker.core.Severity.HIGH,
                            "Чит в истории команд / Cheat reference in shell history")
                    .module(ID).detail(label + "  —  " + line.strip())
                    .evidence(file.toString()).source("shell history").build());
        }
    }

    private List<Path> chromiumHistories() {
        List<Path> out = new ArrayList<>();
        String[] browsers = {
                ".config/google-chrome", ".config/chromium",
                ".config/BraveSoftware/Brave-Browser", ".config/opera",
                ".config/microsoft-edge", ".config/yandex-browser/yandex-browser",
                ".var/app/com.google.Chrome/config/google-chrome"
        };
        for (Path home : Platform.userProfiles()) {
            for (String b : browsers) {
                Path base = home.resolve(b);
                if (!Files.isDirectory(base)) {
                    continue;
                }
                try (var s = Files.list(base)) {
                    s.filter(Files::isDirectory).forEach(profile -> {
                        Path h = profile.resolve("History");
                        if (Files.isRegularFile(h)) {
                            out.add(h);
                        }
                    });
                } catch (Exception ignored) {
                }
            }
        }
        return out;
    }

    private List<Path> firefoxHistories() {
        List<Path> out = new ArrayList<>();
        for (Path home : Platform.userProfiles()) {
            for (String b : new String[]{".mozilla/firefox",
                    ".var/app/org.mozilla.firefox/.mozilla/firefox"}) {
                Path base = home.resolve(b);
                if (!Files.isDirectory(base)) {
                    continue;
                }
                try (var s = Files.list(base)) {
                    s.filter(Files::isDirectory).forEach(profile -> {
                        Path places = profile.resolve("places.sqlite");
                        if (Files.isRegularFile(places)) {
                            out.add(places);
                        }
                    });
                } catch (Exception ignored) {
                }
            }
        }
        return out;
    }

    private Path copy(Path db, Path tmpDir) {
        try {
            Path dest = tmpDir.resolve(System.nanoTime() + "-" + db.getFileName());
            Files.copy(db, dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            return dest;
        } catch (Exception e) {
            return db;
        }
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

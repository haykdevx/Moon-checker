package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Linux file scan. Every regular file in the required folders is offered to the shared
 * {@link FileInspection}, which recognises executables by content (ELF or PE, any name —
 * extensionless programs and versioned libraries such as {@code libx.so.1} included).
 *
 * <p>Required, per user: Downloads, Desktop, Documents, {@code .local/share}, {@code .config},
 * {@code .steam} (the Steam client folder); for the machine: {@code /tmp}, {@code /var/tmp},
 * {@code /dev/shm}. Declared exclusions from the required part: Steam game libraries and
 * Proton prefixes ({@code steamapps}) and Flatpak stores ({@code flatpak}) — hundreds of
 * thousands of vendor files; they are walked afterwards with the time that is left. A required
 * folder that exists but could not be read completely (permissions, limits, time) makes this
 * collector {@code PARTIAL}, so "nothing found" is never concluded from a partial walk.
 */
public final class LinuxFileScanCheck implements CheckModule {

    public static final String ID = "linuxfiles";
    static final Duration BUDGET = Duration.ofMinutes(4).plusSeconds(20);
    static final int FILES_PER_FOLDER = 100_000;
    static final Set<String> EXCLUDED_DIRS = Set.of("steamapps", "flatpak");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.linuxfiles");
    }

    @Override
    public Category category() {
        return Category.FILES;
    }

    @Override
    public boolean windowsOnly() {
        return false;
    }

    @Override
    public void run(ScanContext ctx) {
        if (!Platform.isLinux()) {
            return;
        }
        Instant stopAt = FileScanCheck.stopAt(Instant.now(), ctx.deadline());
        if (stopAt.isAfter(Instant.now().plus(BUDGET))) {
            stopAt = Instant.now().plus(BUDGET);
        }
        EnumMap<FileInspection.Outcome, Integer> outcomes = new EnumMap<>(FileInspection.Outcome.class);
        List<Path> excluded = new ArrayList<>();
        int files = 0;
        for (Path root : requiredRoots()) {
            if (ctx.isCancelled()) {
                return;
            }
            ctx.log(I18n.t("log.scanning", root.toString()));
            FileInspection.Walk walk = FileInspection.scan(root, FILES_PER_FOLDER, 8, stopAt,
                    dir -> {
                        if (isExcluded(dir)) {
                            excluded.add(dir);
                            return true;
                        }
                        return false;
                    },
                    f -> outcomes.merge(FileInspection.inspect(f, ctx, ID, Category.FILES), 1, Integer::sum), ctx);
            files += walk.files();
            if (!walk.rootMissing() && !walk.complete()) {
                ctx.partial(walk.shortfall());
            }
        }
        // extra, best effort: the excluded vendor stores, with the time that is left
        int extra = 0;
        boolean extraCut = false;
        for (Path dir : excluded) {
            if (ctx.isCancelled() || Instant.now().isAfter(stopAt)) {
                extraCut = true;
                break;
            }
            FileInspection.Walk w = FileInspection.scan(dir, FILES_PER_FOLDER, 8, stopAt,
                    f -> outcomes.merge(FileInspection.inspect(f, ctx, ID, Category.FILES), 1, Integer::sum), ctx);
            extra += w.files();
            extraCut |= !w.complete();
        }
        ctx.emit(Finding.builder(Category.FILES, Severity.INFO,
                        "Что охватила проверка файлов / What the file scan covered")
                .module(ID).kind(EvidenceKind.CONTEXT).rule("linuxfiles:scan-scope")
                .detail("required folders: " + files + " files; outcomes: " + outcomes
                        + "; excluded from the required part: " + excluded.size() + " Steam library / Flatpak folder(s)"
                        + ", walked afterwards: " + extra + " files" + (extraCut ? " (stopped at the time limit)" : "")
                        + ". Executables are recognised by content (ELF/PE), not by name; programs over "
                        + FileInspection.STRING_SCAN_MAX / (1024 * 1024) + " MiB get name and hash checks only.")
                .source("file scan").build());
    }

    static boolean isExcluded(Path dir) {
        Path name = dir.getFileName();
        return name != null && EXCLUDED_DIRS.contains(name.toString().toLowerCase(Locale.ROOT));
    }

    static List<Path> requiredRoots() {
        List<Path> roots = new ArrayList<>();
        for (Path home : Platform.userProfiles()) {
            roots.add(home.resolve("Downloads"));
            roots.add(home.resolve("Desktop"));
            roots.add(home.resolve("Documents"));
            roots.add(home.resolve(".local").resolve("share"));
            roots.add(home.resolve(".config"));
            roots.add(home.resolve(".steam"));
        }
        roots.add(Path.of("/tmp"));
        roots.add(Path.of("/var/tmp"));
        roots.add(Path.of("/dev/shm"));
        return roots;
    }
}

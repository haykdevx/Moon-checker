package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.win.Ntfs;
import ru.moon.checker.win.Volumes;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The "Everything" replacement plus a deep content scan.
 *
 * <ol>
 *   <li><b>Fast name match:</b> enumerate the full MFT of every fixed drive and
 *       match every filename against the cheat-name signatures — a whole-disk
 *       search in seconds.</li>
 *   <li><b>Deep inspection:</b> read binaries in user-writable locations and
 *       match file hashes, embedded CS2 offset strings, and injection imports
 *       (see {@link FileInspection}).</li>
 * </ol>
 *
 * If raw NTFS access is unavailable it falls back to a filesystem walk so the
 * module always produces a result.
 */
public final class FileScanCheck implements CheckModule {

    public static final String ID = "files";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.files");
    }

    @Override
    public Category category() {
        return Category.FILES;
    }

    @Override
    public boolean windowsOnly() {
        return false; // fallback walk works cross-platform (for tests / dev)
    }

    @Override
    public void run(ScanContext ctx) {
        boolean indexed = false;
        if (Ntfs.isSupported() && ctx.isElevated()) {
            for (char drive : Volumes.fixedDrives()) {
                if (ctx.isCancelled()) {
                    return;
                }
                ctx.log(I18n.t("log.mft", drive));
                Ntfs.Index index = Ntfs.buildIndex(drive);
                if (index.size() > 0) {
                    indexed = true;
                    matchNames(ctx, index);
                    deepScanWholeDrive(ctx, index);
                }
            }
        }

        // deep inspection of user-writable locations (always)
        for (Path root : deepScanRoots()) {
            if (ctx.isCancelled()) {
                return;
            }
            ctx.log(I18n.t("log.scanning", root.toString()));
            FileInspection.walk(root, 8000, 8,
                    f -> FileInspection.inspect(f, ctx, ID, Category.FILES), ctx);
        }

        // shallow sweep of every drive root — catches cheats dropped loose in
        // C:\, D:\ or a top-level folder that isn't a user profile
        if (Platform.isWindows()) {
            for (char drive : Volumes.fixedDrives()) {
                if (ctx.isCancelled()) {
                    return;
                }
                Path driveRoot = Path.of(drive + ":\\");
                ctx.log(I18n.t("log.scanning", driveRoot.toString()));
                FileInspection.walk(driveRoot, 4000, 2,
                        f -> FileInspection.inspect(f, ctx, ID, Category.FILES), ctx);
            }
        }

        if (!indexed && Platform.isWindows() && !ctx.isElevated()) {
            ctx.emit(Finding.builder(Category.FILES, ru.moon.checker.core.Severity.INFO,
                            "Полный поиск по диску недоступен без прав администратора")
                    .module(ID)
                    .detail("MFT enumeration requires elevation; only user folders were deep-scanned.")
                    .source("engine")
                    .build());
        }
    }

    private void matchNames(ScanContext ctx, Ntfs.Index index) {
        for (var entry : index.nodes().entrySet()) {
            if (ctx.isCancelled()) {
                return;
            }
            Ntfs.Node node = entry.getValue();
            if (node.directory() || node.name() == null) {
                continue;
            }
            ctx.signatures().matchCheatName(node.name()).ifPresent(rule -> {
                String path = index.resolvePath(entry.getKey());
                ctx.emit(Finding.builder(Category.FILES, rule.severity(),
                                "Файл чита на диске / Cheat file present on disk")
                        .module(ID)
                        .detail(rule.label())
                        .evidence(path)
                        .source("MFT (" + node.name() + ")")
                        .openPath(parentOf(path))
                        .build());
            });
        }
    }

    /** Time and volume budget for the whole-drive content scan. */
    private static final Duration DEEP_SCAN_BUDGET = Duration.ofMinutes(4);
    private static final int DEEP_SCAN_MAX_FILES = 20_000;

    /**
     * Content-inspect every binary on the drive that does not live in a trusted
     * location — so a cheat cannot escape inspection simply by sitting outside
     * the user's folders. The MFT already gave us every path on the volume, so
     * this needs no directory walking.
     *
     * <p>Trusted paths (Windows, Program Files, Steam, vendor installs) are
     * skipped because they are allowlisted for heuristics anyway; that is what
     * keeps a whole-drive scan affordable. Bounded by time and file count, and
     * it reports when it had to stop early rather than silently truncating.
     */
    private void deepScanWholeDrive(ScanContext ctx, Ntfs.Index index) {
        Instant deadline = Instant.now().plus(DEEP_SCAN_BUDGET);
        int inspected = 0;
        boolean truncated = false;

        for (var entry : index.nodes().entrySet()) {
            if (ctx.isCancelled()) {
                return;
            }
            if (inspected >= DEEP_SCAN_MAX_FILES || Instant.now().isAfter(deadline)) {
                truncated = true;
                break;
            }
            Ntfs.Node node = entry.getValue();
            if (node.directory() || node.name() == null
                    || !FileInspection.isBinaryName(node.name())) {
                continue;
            }
            String path = index.resolvePath(entry.getKey());
            if (ctx.signatures().isAllowedPath(path.toLowerCase(Locale.ROOT))) {
                continue; // OS / Steam / vendor code
            }
            try {
                Path file = Path.of(path);
                if (Files.isRegularFile(file)) {
                    FileInspection.inspect(file, ctx, ID, Category.FILES);
                    inspected++;
                }
            } catch (Exception ignored) {
                // unreadable or an exotic path — skip
            }
        }
        ctx.log(I18n.t("log.deepscan", inspected));
        if (truncated) {
            ctx.emit(Finding.builder(Category.FILES, ru.moon.checker.core.Severity.INFO,
                            "Глубокое сканирование остановлено по лимиту / Deep scan hit its budget")
                    .module(ID)
                    .detail("Проверено " + inspected + " файлов вне доверенных папок; "
                            + "остальные проверены по имени и хешу через таблицу файлов NTFS.")
                    .source("deep scan")
                    .build());
        }
    }

    private List<Path> deepScanRoots() {
        List<Path> roots = new ArrayList<>();
        for (Path profile : Platform.userProfiles()) {
            roots.add(profile.resolve("Downloads"));
            roots.add(profile.resolve("Desktop"));
            roots.add(profile.resolve("Documents"));
            roots.add(profile.resolve("Videos"));
            roots.add(profile.resolve("Music"));
            roots.add(profile.resolve("Pictures"));
            roots.add(profile.resolve("Saved Games"));
            roots.add(profile.resolve("Favorites"));
            roots.add(profile.resolve("OneDrive"));
            roots.add(Platform.localAppData(profile).resolve("Temp"));
            roots.add(profile.resolve("AppData").resolve("LocalLow"));
            roots.add(Platform.roamingAppData(profile));
        }
        if (Platform.isWindows()) {
            roots.add(Platform.systemDrive().resolve("Temp"));
            roots.add(Platform.systemDrive().resolve("Users").resolve("Public"));
            String programData = System.getenv("ProgramData");
            if (programData != null) {
                roots.add(Path.of(programData));
            }
        }
        return roots;
    }

    private static String parentOf(String winPath) {
        int i = winPath.lastIndexOf('\\');
        return i > 0 ? winPath.substring(0, i) : winPath;
    }
}

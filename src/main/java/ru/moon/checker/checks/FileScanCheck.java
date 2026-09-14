package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.win.Ntfs;
import ru.moon.checker.win.Volumes;

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

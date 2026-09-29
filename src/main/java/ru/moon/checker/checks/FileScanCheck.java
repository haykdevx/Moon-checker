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

    /**
     * The collector's own budget, inside the engine's 5-minute limit per collector: the
     * essential phases run first and the whole-drive content pass gets what is left, so a
     * PC with several large drives finishes instead of timing out (an incomplete scan).
     */
    static final Duration BUDGET = Duration.ofMinutes(4).plusSeconds(20);
    /** Our own budget, but never past the engine's deadline minus a margin to report cleanly. */
    static Instant stopAt(Instant now, Instant engineDeadline) {
        Instant own = now.plus(BUDGET);
        if (engineDeadline == null) {
            return own;
        }
        Instant engine = engineDeadline.minusSeconds(20);
        return engine.isBefore(own) ? engine : own;
    }

    /** Candidates kept for the whole-drive pass; bounds memory on a drive with millions of files. */
    private static final int MAX_CANDIDATES = 200_000;

    @Override
    public void run(ScanContext ctx) {
        Instant hardStop = stopAt(Instant.now(), ctx.deadline());
        boolean indexed = false;
        List<String> candidates = new ArrayList<>();
        // 1. every fixed drive by name through the MFT; keep the binaries outside trusted folders
        //    for the content pass and drop the index before the next drive (memory)
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
                    collectCandidates(ctx, index, candidates);
                }
            }
        }

        // 2. deep inspection of user-writable locations, wherever Windows keeps them
        for (Path root : deepScanRoots()) {
            if (ctx.isCancelled()) {
                return;
            }
            if (Instant.now().isAfter(hardStop)) {
                break;
            }
            ctx.log(I18n.t("log.scanning", root.toString()));
            FileInspection.walk(root, 8000, 8,
                    f -> FileInspection.inspect(f, ctx, ID, Category.FILES), ctx);
        }

        // 3. shallow sweep of every drive root — catches cheats dropped loose in
        //    C:\, D:\ or a top-level folder that isn't a user profile
        if (Platform.isWindows()) {
            for (char drive : Volumes.fixedDrives()) {
                if (ctx.isCancelled()) {
                    return;
                }
                if (Instant.now().isAfter(hardStop)) {
                    break;
                }
                Path driveRoot = Path.of(drive + ":\\");
                ctx.log(I18n.t("log.scanning", driveRoot.toString()));
                FileInspection.walk(driveRoot, 4000, 2,
                        f -> FileInspection.inspect(f, ctx, ID, Category.FILES), ctx);
            }
        }

        // 4. content of every other binary on the drives, with the time that is left
        if (!candidates.isEmpty()) {
            deepScanWholeDrive(ctx, candidates, hardStop);
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

    private static final int DEEP_SCAN_MAX_FILES = 20_000;

    /**
     * Binaries outside trusted folders (Windows, Program Files, Steam, vendor installs —
     * allowlisted for heuristics anyway), from one drive's MFT, for the content pass.
     */
    private void collectCandidates(ScanContext ctx, Ntfs.Index index, List<String> into) {
        for (var entry : index.nodes().entrySet()) {
            if (ctx.isCancelled() || into.size() >= MAX_CANDIDATES) {
                return;
            }
            Ntfs.Node node = entry.getValue();
            if (node.directory() || node.name() == null || !FileInspection.isBinaryName(node.name())) {
                continue;
            }
            String path = index.resolvePath(entry.getKey());
            if (!ctx.signatures().isAllowedPath(path.toLowerCase(Locale.ROOT))) {
                into.add(path);
            }
        }
    }

    /**
     * Content-inspect every binary on the drives that does not live in a trusted
     * location — so a cheat cannot escape inspection simply by sitting outside
     * the user's folders. Bounded by the collector's remaining time and a file
     * count, and it reports when it had to stop early rather than silently truncating.
     */
    private void deepScanWholeDrive(ScanContext ctx, List<String> candidates, Instant deadline) {
        int inspected = 0;
        boolean truncated = false;

        for (String path : candidates) {
            if (ctx.isCancelled()) {
                return;
            }
            if (inspected >= DEEP_SCAN_MAX_FILES || Instant.now().isAfter(deadline)) {
                truncated = true;
                break;
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
            roots.addAll(knownFolders());
        }
        return new ArrayList<>(new java.util.LinkedHashSet<>(roots));
    }

    /** Values under User Shell Folders: Desktop, Documents, Downloads, Videos, Pictures, Music. */
    private static final String[] SHELL_FOLDERS = {"Desktop", "Personal", "{374DE290-123F-4565-9164-39C4925E467B}",
            "My Video", "My Pictures", "My Music"};

    /**
     * Where Windows really keeps this user's folders: Desktop, Downloads and Documents
     * are often moved to OneDrive or to another drive (D:\Downloads), out of the
     * profile paths above.
     */
    static List<Path> knownFolders() {
        List<Path> out = new ArrayList<>();
        String key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
        for (String name : SHELL_FOLDERS) {
            String expanded = expandEnv(ru.moon.checker.win.Registry.getString(ru.moon.checker.win.Registry.HKCU,
                    key, name), System.getenv());
            if (expanded != null && !expanded.isBlank() && !expanded.contains("%")) {
                try {
                    out.add(Path.of(expanded));
                } catch (Exception ignored) {
                    // not a usable path
                }
            }
        }
        return out;
    }

    /** "%USERPROFILE%\Downloads" with the given environment; unknown variables stay as they are. */
    static String expandEnv(String raw, java.util.Map<String, String> env) {
        if (raw == null) {
            return null;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("%([^%]+)%").matcher(raw);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String value = null;
            for (var e : env.entrySet()) {  // Windows variable names are case-insensitive
                if (e.getKey().equalsIgnoreCase(m.group(1))) {
                    value = e.getValue();
                    break;
                }
            }
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(value != null ? value : m.group()));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String parentOf(String winPath) {
        int i = winPath.lastIndexOf('\\');
        return i > 0 ? winPath.substring(0, i) : winPath;
    }
}

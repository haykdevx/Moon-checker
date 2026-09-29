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
    /** Phase timings in the log: the only way to see on a player's PC where the time went. */
    private static void phase(String name, Instant started, int count) {
        ru.moon.checker.core.Log.info("files: " + name + " done at +" + Duration.between(started, Instant.now()).toSeconds()
                + "s" + (count >= 0 ? " (" + count + " candidates)" : ""));
    }

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

    /** Files per user folder before the walk stops and says so (the time budget usually decides first). */
    static final int USER_FOLDER_FILES = 50_000;

    @Override
    public void run(ScanContext ctx) {
        Instant started = Instant.now();
        Instant hardStop = stopAt(started, ctx.deadline());
        Scope scope = new Scope();
        List<String> candidates = new ArrayList<>();
        // a file in Downloads is met again in the whole-drive pass: read it once, report it once
        java.util.Set<String> inspected = new java.util.HashSet<>();

        // 1. REQUIRED (elevated, Windows): every fixed drive by name through the MFT; keep the binaries
        //    for the content pass and drop the index before the next drive (memory)
        if (Ntfs.isSupported() && ctx.isElevated()) {
            for (char drive : Volumes.fixedDrives()) {
                if (ctx.isCancelled()) {
                    return;
                }
                String fs = Volumes.fileSystem(drive);
                if (!fs.isEmpty() && !fs.equalsIgnoreCase("NTFS")) {
                    scope.notes.add(drive + ": " + fs + " (no NTFS file table; its user folders and root are walked)");
                    continue;
                }
                ctx.log(I18n.t("log.mft", drive));
                Ntfs.Index index = Ntfs.buildIndex(drive);
                if (index.size() > 0) {
                    scope.indexedDrives++;
                    matchNames(ctx, index);
                    collectCandidates(ctx, index, candidates, scope);
                } else {
                    ctx.partial("drive " + drive + ": the NTFS file table could not be read, so names on it were not "
                            + "matched");
                }
            }
        } else if (Platform.isWindows()) {
            scope.notes.add("not elevated: no whole-drive name search (the scan is incomplete for that reason)");
        }
        phase("mft", started, candidates.size());

        // 2. REQUIRED: content of user-writable locations, wherever Windows keeps them
        for (Path root : deepScanRoots()) {
            if (ctx.isCancelled()) {
                return;
            }
            ctx.log(I18n.t("log.scanning", root.toString()));
            FileInspection.Walk walk = FileInspection.scan(root, USER_FOLDER_FILES, 8, hardStop,
                    f -> scope.count(inspectOnce(f, ctx, inspected)), ctx);
            scope.userFiles += walk.files();
            if (!walk.rootMissing() && !walk.complete()) {
                ctx.partial(walk.shortfall());
            }
        }
        phase("user folders", started, -1);

        // 3. extra: shallow sweep of every drive root — cheats dropped loose in C:\, D:\ or a top-level folder
        if (Platform.isWindows()) {
            for (char drive : Volumes.fixedDrives()) {
                if (ctx.isCancelled() || Instant.now().isAfter(hardStop)) {
                    break;
                }
                Path driveRoot = Path.of(drive + ":\\");
                ctx.log(I18n.t("log.scanning", driveRoot.toString()));
                FileInspection.scan(driveRoot, 4000, 2, hardStop, f -> scope.count(inspectOnce(f, ctx, inspected)), ctx);
            }
        }
        phase("drive roots", started, -1);

        // 4. extra: content of every other binary on the drives, most exposed locations first, with the time left
        if (!candidates.isEmpty()) {
            deepScanWholeDrive(ctx, candidates, hardStop, inspected, scope);
        }
        phase("whole-drive content", started, -1);
        emitScope(ctx, scope);
    }

    /** What this run covered: shown to the reviewer as context, so limits are never silent. */
    static final class Scope {
        final java.util.EnumMap<FileInspection.Outcome, Integer> outcomes = new java.util.EnumMap<>(FileInspection.Outcome.class);
        final java.util.EnumMap<Locations.Kind, Integer> candidatesByPlace = new java.util.EnumMap<>(Locations.Kind.class);
        final List<String> notes = new ArrayList<>();
        int indexedDrives, userFiles, systemBinariesByNameOnly, wholeDriveInspected, wholeDriveCandidates;
        boolean wholeDriveTruncated;

        void count(FileInspection.Outcome o) {
            if (o != null) {
                outcomes.merge(o, 1, Integer::sum);
            }
        }

        String summary() {
            StringBuilder sb = new StringBuilder();
            sb.append("NTFS drives indexed by name: ").append(indexedDrives)
                    .append("; files in user folders: ").append(userFiles)
                    .append("; outcomes: ").append(outcomes)
                    .append("; whole-drive content pass: ").append(wholeDriveInspected).append(" of ")
                    .append(wholeDriveCandidates).append(" candidate programs")
                    .append(wholeDriveTruncated ? " (stopped at its limit)" : "")
                    .append(" by place ").append(candidatesByPlace)
                    .append("; Windows-folder programs matched by name only: ").append(systemBinariesByNameOnly);
            for (String n : notes) {
                sb.append("; ").append(n);
            }
            sb.append(". Programs over ").append(FileInspection.STRING_SCAN_MAX / (1024 * 1024))
                    .append(" MiB: name, streams and hash only; OneDrive online-only files: name only.");
            return sb.toString();
        }
    }

    private void emitScope(ScanContext ctx, Scope scope) {
        ctx.emit(Finding.builder(Category.FILES, ru.moon.checker.core.Severity.INFO,
                        "Что охватила проверка файлов / What the file scan covered")
                .module(ID).kind(ru.moon.checker.core.EvidenceKind.CONTEXT).rule("files:scan-scope")
                .detail(scope.summary())
                .source("file scan")
                .build());
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
     * Programs (by name) from one drive's file table for the content pass. Windows-folder
     * programs are left to name matching (counted in the scope note); everything else is kept,
     * user-writable places first, program folders last, so the time budget goes where cheats
     * are usually dropped. Location decides order here, never whether a finding is reported.
     */
    private void collectCandidates(ScanContext ctx, Ntfs.Index index, List<String> into, Scope scope) {
        for (var entry : index.nodes().entrySet()) {
            if (ctx.isCancelled() || into.size() >= MAX_CANDIDATES) {
                return;
            }
            Ntfs.Node node = entry.getValue();
            if (node.directory() || node.name() == null || !FileInspection.isBinaryName(node.name())) {
                continue;
            }
            String path = index.resolvePath(entry.getKey());
            Locations.Kind place = Locations.classify(path);
            if (place == Locations.Kind.SYSTEM) {
                scope.systemBinariesByNameOnly++;
                continue;
            }
            scope.candidatesByPlace.merge(place, 1, Integer::sum);
            into.add(path);
        }
    }

    /** User-writable first, then other folders, then program folders. */
    static int priority(String path) {
        return switch (Locations.classify(path)) {
            case USER_WRITABLE, NETWORK, UNKNOWN -> 0;
            case OTHER -> 1;
            case PROGRAM -> 2;
            case SYSTEM -> 3;
        };
    }

    /**
     * Content-inspect every binary on the drives that does not live in a trusted
     * location — so a cheat cannot escape inspection simply by sitting outside
     * the user's folders. Bounded by the collector's remaining time and a file
     * count, and it reports when it had to stop early rather than silently truncating.
     */
    private void deepScanWholeDrive(ScanContext ctx, List<String> candidates, Instant deadline, java.util.Set<String> seen,
                                    Scope scope) {
        int inspected = 0;
        boolean truncated = false;
        candidates.sort(java.util.Comparator.comparingInt(FileScanCheck::priority));
        scope.wholeDriveCandidates = candidates.size();

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
                if (!seen.contains(key(file)) && Files.isRegularFile(file)) {
                    scope.count(inspectOnce(file, ctx, seen));
                    inspected++;
                }
            } catch (Exception ignored) {
                // unreadable or an exotic path — skip
            }
        }
        ctx.log(I18n.t("log.deepscan", inspected));
        scope.wholeDriveInspected = inspected;
        scope.wholeDriveTruncated = truncated;
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

    private static FileInspection.Outcome inspectOnce(Path file, ScanContext ctx, java.util.Set<String> seen) {
        return seen.add(key(file)) ? FileInspection.inspect(file, ctx, ID, Category.FILES) : null;
    }

    /** One spelling per file: Windows paths are case-insensitive and may arrive with either slash. */
    static String key(Path file) {
        return file.toAbsolutePath().normalize().toString().replace('/', '\\').toLowerCase(Locale.ROOT);
    }

    private static String parentOf(String winPath) {
        int i = winPath.lastIndexOf('\\');
        return i > 0 ? winPath.substring(0, i) : winPath;
    }
}

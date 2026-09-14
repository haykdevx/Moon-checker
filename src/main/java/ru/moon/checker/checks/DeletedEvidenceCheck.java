package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.RecycleBin;
import ru.moon.checker.parse.Usn;
import ru.moon.checker.win.Ntfs;
import ru.moon.checker.win.Volumes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Recovers evidence of files that were deleted or renamed — a very common
 * "clean before the check" move. Sources:
 * <ul>
 *   <li>the NTFS USN change journal (delete / rename records), and</li>
 *   <li>Recycle Bin {@code $I} index files (items sent to the bin).</li>
 * </ul>
 * Only entries whose name matches a cheat signature are reported.
 */
public final class DeletedEvidenceCheck implements CheckModule {

    public static final String ID = "deleted";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.deleted");
    }

    @Override
    public Category category() {
        return Category.DELETED;
    }

    @Override
    public void run(ScanContext ctx) {
        if (ctx.isElevated()) {
            for (char drive : Volumes.fixedDrives()) {
                if (ctx.isCancelled()) {
                    return;
                }
                ctx.log(I18n.t("log.journal", drive));
                for (Usn.Record r : Ntfs.readJournalChanges(drive)) {
                    if (r.fileName() == null) {
                        continue;
                    }
                    ctx.signatures().matchCheatName(r.fileName()).ifPresent(rule ->
                            ctx.emit(Finding.builder(Category.DELETED, escalate(rule.severity()),
                                            "Чит-файл удалён/переименован / Cheat file deleted or renamed")
                                    .module(ID)
                                    .detail(rule.label() + "  [" + Usn.reasonToString(r.reason()) + "]")
                                    .evidence(r.fileName())
                                    .source("USN journal " + drive + ":")
                                    .when(r.timestamp())
                                    .build()));
                }
            }
        }

        scanRecycleBins(ctx);
    }

    private void scanRecycleBins(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        for (char drive : Volumes.fixedDrives()) {
            Path bin = Path.of(drive + ":\\$Recycle.Bin");
            if (!Files.isDirectory(bin)) {
                continue;
            }
            ctx.log(I18n.t("log.recyclebin", drive));
            FileInspection.walk(bin, 20000, 4, f -> {
                String n = f.getFileName().toString();
                if (!n.regionMatches(true, 0, "$I", 0, 2)) {
                    return;
                }
                try {
                    RecycleBin.Entry e = RecycleBin.parse(Files.readAllBytes(f));
                    if (e == null || e.originalPath() == null) {
                        return;
                    }
                    String base = baseName(e.originalPath());
                    ctx.signatures().matchCheatName(base).ifPresent(rule ->
                            ctx.emit(Finding.builder(Category.DELETED, escalate(rule.severity()),
                                            "Чит-файл в корзине / Cheat file in Recycle Bin")
                                    .module(ID)
                                    .detail(rule.label())
                                    .evidence(e.originalPath())
                                    .source("Recycle Bin " + drive + ":")
                                    .when(e.deletedAt())
                                    .build()));
                } catch (Exception ignored) {
                    // unreadable $I
                }
            }, ctx);
        }
    }

    /** Deleting a cheat is itself incriminating, so bump a HIGH to CRITICAL. */
    private Severity escalate(Severity s) {
        return s == Severity.HIGH || s == Severity.CRITICAL ? Severity.CRITICAL : s;
    }

    private static String baseName(String path) {
        String p = path.replace('/', '\\');
        int i = p.lastIndexOf('\\');
        return (i >= 0 ? p.substring(i + 1) : p).toLowerCase(Locale.ROOT);
    }
}

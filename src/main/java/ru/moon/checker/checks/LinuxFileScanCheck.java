package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Linux file scan. Reuses the shared {@link FileInspection} (hash match, CS2
 * offset strings, ELF/PE content, entropy) over the locations Linux cheats live
 * in: home folders, {@code .local/share}, {@code .steam}, {@code /tmp},
 * {@code /var/tmp} and {@code /dev/shm} (a favourite for fileless payloads).
 */
public final class LinuxFileScanCheck implements CheckModule {

    public static final String ID = "linuxfiles";

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
        for (Path root : roots()) {
            if (ctx.isCancelled()) {
                return;
            }
            ctx.log(I18n.t("log.scanning", root.toString()));
            FileInspection.walk(root, 8000, 8,
                    f -> FileInspection.inspect(f, ctx, ID, Category.FILES), ctx);
        }
    }

    private List<Path> roots() {
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

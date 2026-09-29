package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.cs2.Cs2Locator;
import ru.moon.checker.cs2.GameInfo;
import ru.moon.checker.parse.Pe;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;

/**
 * Checks CS2 itself for tampering — the trail a cheat leaves in the game
 * regardless of what it is called or where its loader lives.
 *
 * <ul>
 *   <li><b>gameinfo.gi</b> — Source 2 loads code from the search paths declared
 *       here; injecting an extra path is how loader-less cheats and rogue
 *       "addons" get into the game.</li>
 *   <li><b>Foreign binaries in the game folder</b> — a DLL in CS2's bin
 *       directories that Valve did not sign has no business being there.</li>
 *   <li><b>client-side addons/plugin dirs</b> — Metamod-style loaders belong on
 *       a server, not on a player's machine.</li>
 *   <li><b>Launch options</b> — {@code -insecure} disables VAC for the session;
 *       {@code -allow_third_party_software} explicitly permits injection.</li>
 *   <li><b>Config scripts</b> — bhop / auto-jump alias chains in .cfg files.</li>
 * </ul>
 */
public final class Cs2IntegrityCheck implements CheckModule {

    public static final String ID = "cs2";

    /** Launch options that weaken or disable anti-cheat for the session. */
    private static final String[][] BAD_LAUNCH_OPTIONS = {
            {"-insecure", "VAC отключён для сессии / VAC disabled for the session"},
            {"-allow_third_party_software", "явно разрешена сторонняя инъекция / third-party injection explicitly allowed"},
            {"-tools", "режим инструментов Source 2 / Source 2 tools mode"},
            {"-nosteam", "запуск в обход Steam / launched outside Steam"}
    };

    /** Script patterns that automate movement or firing from a config file. */
    private static final String[][] CFG_PATTERNS = {
            {"+jump;-jump", "скрипт банихопа / bunny-hop script"},
            {"+jump; -jump", "скрипт банихопа / bunny-hop script"},
            {"bhop", "банихоп / bunny-hop"},
            {"jumpthrow", "jumpthrow-скрипт"},
            {"+attack;-attack", "авто-стрельба / auto-fire script"}
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.cs2");
    }

    @Override
    public Category category() {
        return Category.CS2;
    }

    @Override
    public boolean windowsOnly() {
        return false; // CS2 runs on Linux too
    }

    @Override
    public void run(ScanContext ctx) {
        ctx.log(I18n.t("log.cs2"));
        Optional<Cs2Locator.Install> found = Cs2Locator.find();
        if (found.isEmpty()) {
            ctx.emit(Finding.builder(Category.CS2, Severity.INFO,
                            "CS2 не найден на этом ПК / CS2 not installed on this PC")
                    .module(ID)
                    .detail("Проверка игровых файлов пропущена — игра не установлена или установлена не через Steam.")
                    .source("Steam library")
                    .build());
            return;
        }
        Cs2Locator.Install cs2 = found.get();
        ctx.emit(Finding.builder(Category.CS2, Severity.INFO, "Установка CS2 найдена / CS2 install located")
                .module(ID)
                .detail("build " + (cs2.buildId() == null ? "?" : cs2.buildId()))
                .evidence(cs2.gameRoot().toString())
                .openPath(cs2.gameRoot().toString())
                .source("appmanifest_730.acf")
                .build());

        gameInfo(ctx, cs2);
        foreignBinaries(ctx, cs2);
        addons(ctx, cs2);
        launchOptions(ctx, cs2);
        configs(ctx, cs2);
    }

    /*
     * Deliberately NOT implemented: "game file modified after the Steam update".
     * It sounds like a clean integrity signal and it is not. Measured on a clean
     * install, 11 of Valve's own libraries (libengine2.so, libtier0.so,
     * libparticles.so ...) carry mtimes days after the app manifest's
     * LastUpdated, because Steam touches files on incremental patches and
     * verification. The rule fired 11 times with zero true positives, so it was
     * removed rather than shipped as noise. Tampering is caught instead by the
     * signature check, the cheat-name match and gameinfo.gi below.
     */

    /** Extra search paths in gameinfo.gi let arbitrary code load into Source 2. */
    private void gameInfo(ScanContext ctx, Cs2Locator.Install cs2) {
        Path gi = cs2.gameinfo();
        if (!Files.isRegularFile(gi)) {
            return;
        }
        try {
            GameInfo parsed = GameInfo.parse(Files.readString(gi));
            for (String extra : parsed.foreignSearchPaths()) {
                ctx.emit(Finding.builder(Category.CS2, Severity.CRITICAL,
                                "gameinfo.gi изменён — внедрён путь загрузки / gameinfo.gi tampered: injected search path")
                        .module(ID)
                        .detail("Source 2 будет грузить код отсюда: " + extra)
                        .evidence(gi + "  →  " + extra)
                        .openPath(gi.getParent().toString())
                        .source("gameinfo.gi")
                        .build());
            }
        } catch (Exception e) {
            // unreadable gameinfo is not evidence
        }
    }

    /** A binary in CS2's bin dirs that Valve did not sign. */
    private void foreignBinaries(ScanContext ctx, Cs2Locator.Install cs2) {
        for (Path dir : cs2.binDirs()) {
            if (!Files.isDirectory(dir) || ctx.isCancelled()) {
                continue;
            }
            FileInspection.walk(dir, 2000, 2, f -> {
                String name = f.getFileName().toString();
                String lower = name.toLowerCase(Locale.ROOT);
                if (!lower.endsWith(".dll") && !lower.endsWith(".so") && !lower.endsWith(".exe")) {
                    return;
                }
                // a signature match here is decisive regardless of signing
                ctx.signatures().matchCheatName(lower).ifPresent(rule ->
                        ctx.emit(Finding.builder(Category.CS2, Severity.CRITICAL,
                                        "Чит-модуль внутри папки CS2 / Cheat module inside the CS2 folder")
                                .module(ID).detail(rule.label()).evidence(f.toString())
                                .openPath(dir.toString()).source("CS2 bin").build()));

                if (!Platform.isWindows()) {
                    return; // signature verification below is Windows-only
                }
                try {
                    byte[] head = readHead(f);
                    Pe pe = Pe.parse(head);
                    if (pe.isPe() && !pe.signed()) {
                        // context until measured on real installs: CS2 ships third-party libraries, and
                        // "signed" here only means a certificate is present (a self-signed cheat passes)
                        ctx.emit(Finding.builder(Category.CS2, Severity.LOW,
                                        "Неподписанный бинарник в папке CS2 / Unsigned binary in the CS2 folder")
                                .module(ID).rule("cs2:unsigned-binary")
                                .detail("Valve подписывает свои файлы игры; этот не подписан. Сверьте имя с чистой установкой.")
                                .evidence(f.toString())
                                .openPath(dir.toString())
                                .source("CS2 bin · signature")
                                .build());
                    }
                } catch (Exception ignored) {
                    // unreadable
                }
            }, ctx);
        }
    }

    /** Client-side plugin loaders (Metamod &co) do not belong on a player's PC. */
    private void addons(ScanContext ctx, Cs2Locator.Install cs2) {
        Path addons = cs2.addonsDir();
        if (!Files.isDirectory(addons)) {
            return;
        }
        ctx.emit(Finding.builder(Category.CS2, Severity.HIGH,
                        "Папка addons в клиенте CS2 / Client-side addons folder in CS2")
                .module(ID)
                .detail("Загрузчики плагинов (Metamod и подобные) нужны серверу, а не игроку.")
                .evidence(addons.toString())
                .openPath(addons.toString())
                .source("csgo/addons")
                .build());
    }

    private void launchOptions(ScanContext ctx, Cs2Locator.Install cs2) {
        for (String opts : Cs2Locator.launchOptions(cs2.steamRoot())) {
            String lower = opts.toLowerCase(Locale.ROOT);
            for (String[] bad : BAD_LAUNCH_OPTIONS) {
                if (hasOption(lower, bad[0])) {
                    // a setting that lowers protection (mappers use -tools, practice uses -insecure):
                    // it lowers trust in the report and is never a verdict on its own
                    ctx.emit(Finding.builder(Category.CS2, Severity.MEDIUM,
                                    "Опасная опция запуска CS2 / Unsafe CS2 launch option")
                            .module(ID).kind(ru.moon.checker.core.EvidenceKind.CONFIGURATION)
                            .rule("cs2:unsafe-launch-option")
                            .detail(bad[0] + " — " + bad[1])
                            .evidence(opts)
                            .source("Steam launch options")
                            .build());
                }
            }
        }
    }

    private void configs(ScanContext ctx, Cs2Locator.Install cs2) {
        Path cfg = cs2.cfgDir();
        if (!Files.isDirectory(cfg)) {
            return;
        }
        FileInspection.walk(cfg, 500, 2, f -> {
            if (!f.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".cfg")) {
                return;
            }
            try {
                String text = Files.readString(f).toLowerCase(Locale.ROOT);
                for (String[] pattern : CFG_PATTERNS) {
                    if (text.contains(pattern[0])) {
                        // practice configs and jump binds are common; shown to the reviewer, not a reason on its own
                        ctx.emit(Finding.builder(Category.CS2, Severity.LOW,
                                        "Скрипт в конфиге CS2 / Script in a CS2 config")
                                .module(ID).rule("cs2:config-script")
                                .detail(pattern[1] + "  (" + pattern[0] + ")")
                                .evidence(f.toString())
                                .openPath(cfg.toString())
                                .source("csgo/cfg")
                                .build());
                        break;
                    }
                }
                ctx.signatures().matchCheatName(text).ifPresent(rule ->
                        ctx.emit(Finding.builder(Category.CS2, Severity.HIGH,
                                        "Упоминание чита в конфиге CS2 / Cheat referenced in a CS2 config")
                                .module(ID).detail(rule.label()).evidence(f.toString())
                                .openPath(cfg.toString()).source("csgo/cfg").build()));
            } catch (Exception ignored) {
                // unreadable cfg
            }
        }, ctx);
    }

    /** "-tools" as a whole option, not inside "-toolsmode" or a path. */
    static boolean hasOption(String lowerOptions, String option) {
        for (String token : lowerOptions.split("\\s+")) {
            if (token.equals(option)) {
                return true;
            }
        }
        return false;
    }

    private byte[] readHead(Path f) throws Exception {
        long size = Files.size(f);
        int want = (int) Math.min(size, 4096);
        byte[] buf = new byte[want];
        try (var in = Files.newInputStream(f)) {
            int read = in.readNBytes(buf, 0, want);
            if (read < want) {
                byte[] trimmed = new byte[read];
                System.arraycopy(buf, 0, trimmed, 0, read);
                return trimmed;
            }
        }
        return buf;
    }
}

package ru.moon.checker.checks;

import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinDef.HWND;
import com.sun.jna.platform.win32.WinDef.RECT;
import com.sun.jna.platform.win32.WinUser;
import com.sun.jna.ptr.IntByReference;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckModule;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.cs2.Cs2Locator;
import ru.moon.checker.win.WinProcess;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The running game: what is loaded into {@code cs2.exe}, and what is drawn over it.
 *
 * <ul>
 *   <li><b>Modules</b> — a DLL loaded into the game from Temp, Downloads, the Desktop or
 *       another user folder is how most internal cheats get in (HIGH); a cheat-named one
 *       is critical. Overlays and recorders (Steam, Discord, NVIDIA, AMD, RivaTuner, OBS,
 *       Overwolf, Medal) are listed as context.</li>
 *   <li><b>Overlay windows</b> — a transparent, always-on-top window covering the game,
 *       owned by a program that is not a known overlay, is the shape of an external
 *       ESP (MEDIUM; HIGH when the program runs from a user folder).</li>
 * </ul>
 * Manually mapped cheats are absent from the module list, and an ESP can draw without a
 * window (DirectX hooks): nothing found here is never proof. Needs CS2 running; when it
 * is not, the collector says so and the admin can ask the player to start the game.
 */
public final class LiveGameCheck implements CheckModule {

    public static final String ID = "cs2live";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return I18n.t("module.cs2live");
    }

    @Override
    public Category category() {
        return Category.CS2;
    }

    @Override
    public boolean required() {
        return false; // only meaningful while CS2 runs
    }

    @Override
    public void run(ScanContext ctx) {
        if (!Platform.isWindows()) {
            return;
        }
        ctx.log(I18n.t("log.cs2live"));
        List<WinProcess.Proc> processes = WinProcess.list();
        WinProcess.Proc game = processes.stream().filter(p -> "cs2.exe".equalsIgnoreCase(p.name())).findFirst().orElse(null);
        if (game == null) {
            ctx.emit(Finding.builder(Category.CS2, Severity.INFO,
                            "CS2 не запущен — проверка игры на лету пропущена / CS2 not running: live checks skipped")
                    .module(ID).kind(EvidenceKind.CONTEXT).rule("cs2:not-running")
                    .detail("Попросите игрока запустить CS2 (главное меню) и пройти проверку ещё раз, "
                            + "чтобы увидеть, что загружено в игру и что рисуется поверх неё.")
                    .source("process list").build());
            return;
        }
        String gameRoot = Cs2Locator.find().map(i -> i.gameRoot().toString()).orElse(installRoot(game.path()));
        modules(ctx, game, gameRoot);
        overlays(ctx, game, processes);
    }

    private void modules(ScanContext ctx, WinProcess.Proc game, String gameRoot) {
        List<Tlhelp32.MODULEENTRY32W> modules;
        try {
            modules = Kernel32Util.getModules(game.pid());
        } catch (Throwable t) {
            throw new IllegalStateException("the module list of cs2.exe could not be read: " + t.getMessage(), t);
        }
        Set<String> overlays = new LinkedHashSet<>();
        List<String> programs = new ArrayList<>();
        // one PowerShell start for every module outside Windows' own folders
        List<java.nio.file.Path> toVerify = new ArrayList<>();
        for (Tlhelp32.MODULEENTRY32W m : modules) {
            if (LiveGamePolicy.needsIdentity(LiveGamePolicy.place(m.szExePath(), gameRoot))) {
                try {
                    toVerify.add(java.nio.file.Path.of(m.szExePath()));
                } catch (Exception ignored) {
                    // an odd path: stays unverified
                }
            }
        }
        var identities = ru.moon.checker.win.Authenticode.verifyAll(toVerify);
        for (Tlhelp32.MODULEENTRY32W m : modules) {
            String path = m.szExePath();
            String name = m.szModule();
            var cheat = ctx.signatures().matchCheatName(name.toLowerCase(Locale.ROOT));
            if (cheat.isPresent()) {
                ctx.emit(Finding.builder(Category.CS2, Severity.CRITICAL,
                                "Модуль чита загружен в CS2 / Cheat module loaded into CS2")
                        .module(ID).rule("cs2:module-cheat-name")
                        .detail(cheat.get().label()).evidence(path).source("cs2.exe modules").build());
                continue;
            }
            LiveGamePolicy.Place place = LiveGamePolicy.place(path, gameRoot);
            boolean verified = verified(identities.get(path), ctx);
            switch (LiveGamePolicy.module(name, place, verified)) {
                case USER_FOLDER -> ctx.emit(Finding.builder(Category.CS2, Severity.HIGH,
                                "В CS2 загружена DLL из пользовательской папки / DLL from a user folder loaded into CS2")
                        .module(ID).rule("cs2:module-user-folder")
                        .detail("Внутренние читы попадают в игру именно так; издатель файла не подтверждён"
                                + (LiveGamePolicy.OVERLAY_DLLS.contains(name.toLowerCase(Locale.ROOT))
                                ? " (имя как у оверлея, но подписи нет — имя ничего не доказывает)" : "") + ".")
                        .evidence(path).source("cs2.exe modules").build());
                case UNUSUAL -> ctx.emit(Finding.builder(Category.CS2, Severity.MEDIUM,
                                "В CS2 загружена DLL из необычной папки / DLL from an unusual folder loaded into CS2")
                        .module(ID).rule("cs2:module-unusual-folder")
                        .detail("Не папка игры, Windows или программ; издатель не подтверждён.")
                        .evidence(path).source("cs2.exe modules").build());
                case PROXY -> ctx.emit(Finding.builder(Category.CS2, Severity.MEDIUM,
                                "Системная библиотека загружена из папки игры / Windows library name loaded from the game folder")
                        .module(ID).rule("cs2:module-proxy-dll")
                        .detail("CS2 берёт " + name + " из System32; копия в папке игры подменяет её (DLL proxying). "
                                + "Издатель не подтверждён.")
                        .evidence(path).source("cs2.exe modules").build());
                case OVERLAY -> overlays.add(name);
                case PROGRAM -> programs.add(name + (verified ? "" : " (publisher not verified)"));
                case IGNORE -> {
                    // Windows' own libraries and the game's own files
                }
            }
        }
        if (!overlays.isEmpty() || !programs.isEmpty()) {
            ctx.emit(Finding.builder(Category.CS2, Severity.INFO,
                            "Сторонние модули в CS2 (оверлеи, программы) / Third-party modules in CS2")
                    .module(ID).kind(EvidenceKind.CONTEXT).rule("cs2:modules-context")
                    .detail((overlays.isEmpty() ? "" : "verified overlays: " + String.join(", ", overlays))
                            + (programs.isEmpty() ? "" : (overlays.isEmpty() ? "" : "; ")
                            + "program libraries: " + String.join(", ", programs)))
                    .source("cs2.exe modules").build());
        }
    }

    /** The publisher of a file is one this rule set vouches for (see SignatureDb#isTrustedIdentity). */
    private static boolean verified(ru.moon.checker.win.Authenticode.Result r, ScanContext ctx) {
        return r != null && ctx.signatures().isTrustedIdentity(r.valid(), r.rootSha1(), r.signerNames());
    }

    private void overlays(ScanContext ctx, WinProcess.Proc game, List<WinProcess.Proc> processes) {
        Map<Integer, WinProcess.Proc> byPid = new HashMap<>();
        processes.forEach(p -> byPid.put(p.pid(), p));
        User32 u = User32.INSTANCE;
        List<Object[]> windows = new ArrayList<>();   // {pid, exStyle, rect int[4]}
        u.EnumWindows((HWND hwnd, com.sun.jna.Pointer data) -> {
            try {
                if (!u.IsWindowVisible(hwnd)) {
                    return true;
                }
                IntByReference pid = new IntByReference();
                u.GetWindowThreadProcessId(hwnd, pid);
                RECT r = new RECT();
                u.GetWindowRect(hwnd, r);
                windows.add(new Object[]{pid.getValue(), u.GetWindowLong(hwnd, WinUser.GWL_EXSTYLE),
                        new int[]{r.left, r.top, r.right, r.bottom}});
            } catch (Throwable ignored) {
                // keep enumerating
            }
            return true;
        }, null);
        int[] gameRect = null;
        long bestArea = 0;
        for (Object[] w : windows) {
            int[] r = (int[]) w[2];
            long area = (long) (r[2] - r[0]) * (r[3] - r[1]);
            if ((int) w[0] == game.pid() && area > bestArea) {
                bestArea = area;
                gameRect = r;
            }
        }
        if (gameRect == null) {
            return; // the game has no visible window (minimised to the tray or still loading)
        }
        final int[] rect = gameRect;
        List<Object[]> over = windows.stream().filter(w -> (int) w[0] != game.pid()
                && LiveGamePolicy.overlayStyle((int) w[1]) && LiveGamePolicy.coverage((int[]) w[2], rect) >= LiveGamePolicy.COVER)
                .toList();
        List<java.nio.file.Path> owners = new ArrayList<>();
        for (Object[] w : over) {
            WinProcess.Proc owner = byPid.get((int) w[0]);
            if (owner != null && owner.path() != null) {
                try {
                    owners.add(java.nio.file.Path.of(owner.path()));
                } catch (Exception ignored) {
                    // unverified
                }
            }
        }
        var identities = ru.moon.checker.win.Authenticode.verifyAll(owners);
        Set<Integer> reported = new java.util.HashSet<>();
        for (Object[] w : over) {
            int pid = (int) w[0];
            WinProcess.Proc owner = byPid.get(pid);
            String exe = owner != null ? owner.name() : "?";
            String path = owner != null && owner.path() != null ? owner.path() : exe;
            // a known overlay program only with a verified publisher: a name alone is not an identity
            if (LiveGamePolicy.trustedOverlayOwner(exe, verified(identities.get(path), ctx)) || !reported.add(pid)) {
                continue;
            }
            boolean userFolder = Locations.classify(path) == Locations.Kind.USER_WRITABLE;
            ctx.emit(Finding.builder(Category.CS2, userFolder ? Severity.HIGH : Severity.MEDIUM,
                            "Прозрачное окно поверх игры / Transparent window over the game")
                    .module(ID).rule("cs2:overlay-window")
                    .detail("Окно «всегда сверху» и прозрачное, закрывает игру; так рисуют ESP внешние читы. "
                            + "Программа: " + exe + (LiveGamePolicy.knownOverlayProcess(exe)
                            ? " (имя как у известного оверлея, но издатель не подтверждён)" : ""))
                    .evidence(path).source("window list").build());
        }
    }

    /** "…\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe" → the install folder. */
    static String installRoot(String exePath) {
        if (exePath == null) {
            return null;
        }
        int i = exePath.toLowerCase(Locale.ROOT).lastIndexOf("\\game\\");
        return i > 0 ? exePath.substring(0, i) : exePath.substring(0, Math.max(0, exePath.lastIndexOf('\\')));
    }
}

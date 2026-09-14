package ru.moon.checker.cs2;

import ru.moon.checker.core.Platform;
import ru.moon.checker.parse.Vdf;
import ru.moon.checker.win.Registry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Finds the Counter-Strike 2 installation and its Steam launch options.
 *
 * <p>Steam scatters games across "library folders" on any drive, so the install
 * is located the way Steam itself does: {@code libraryfolders.vdf} lists the
 * libraries, {@code appmanifest_730.acf} names the install directory inside the
 * one that owns app 730.
 */
public final class Cs2Locator {

    public static final String CS2_APP_ID = "730";

    private Cs2Locator() {
    }

    /**
     * @param gameRoot   .../steamapps/common/Counter-Strike Global Offensive
     * @param steamRoot  the Steam root that owns the manifest
     * @param buildId    installed build, from the app manifest
     * @param lastUpdated app manifest LastUpdated (unix seconds, 0 if absent)
     */
    public record Install(Path gameRoot, Path steamRoot, String buildId, long lastUpdated) {
        /** Where the engine binaries live, per platform. */
        public List<Path> binDirs() {
            List<Path> out = new ArrayList<>();
            out.add(gameRoot.resolve("game").resolve("bin").resolve("win64"));
            out.add(gameRoot.resolve("game").resolve("csgo").resolve("bin").resolve("win64"));
            out.add(gameRoot.resolve("game").resolve("bin").resolve("linuxsteamrt64"));
            out.add(gameRoot.resolve("game").resolve("csgo").resolve("bin").resolve("linuxsteamrt64"));
            return out;
        }

        public Path csgoDir() {
            return gameRoot.resolve("game").resolve("csgo");
        }

        public Path gameinfo() {
            return csgoDir().resolve("gameinfo.gi");
        }

        public Path cfgDir() {
            return csgoDir().resolve("cfg");
        }

        public Path addonsDir() {
            return csgoDir().resolve("addons");
        }
    }

    /** Every Steam root this machine might have. */
    public static List<Path> steamRoots() {
        Set<Path> roots = new LinkedHashSet<>();
        if (Platform.isWindows()) {
            String reg = Registry.getString(Registry.HKCU, "Software\\Valve\\Steam", "SteamPath");
            if (reg != null && !reg.isBlank()) {
                roots.add(Path.of(reg.replace('/', '\\')));
            }
            for (String base : new String[]{System.getenv("ProgramFiles(x86)"), System.getenv("ProgramFiles")}) {
                if (base != null) {
                    roots.add(Path.of(base, "Steam"));
                }
            }
        } else {
            for (Path home : Platform.userProfiles()) {
                roots.add(home.resolve(".steam").resolve("steam"));
                roots.add(home.resolve(".local").resolve("share").resolve("Steam"));
                roots.add(home.resolve(".steam").resolve("root"));
            }
        }
        List<Path> out = new ArrayList<>();
        for (Path p : roots) {
            if (Files.isDirectory(p)) {
                out.add(p);
            }
        }
        return out;
    }

    /**
     * Library folders declared in {@code steamapps/libraryfolders.vdf}, plus the
     * Steam root itself (which is always a library).
     */
    public static List<Path> libraries(Path steamRoot) {
        List<Path> out = new ArrayList<>();
        out.add(steamRoot);
        Path vdf = steamRoot.resolve("steamapps").resolve("libraryfolders.vdf");
        if (!Files.isRegularFile(vdf)) {
            return out;
        }
        try {
            Vdf.Node root = Vdf.parse(Files.readString(vdf));
            Vdf.Node folders = root.childIgnoreCase("libraryfolders");
            if (folders == null) {
                return out;
            }
            for (var e : folders.children().entrySet()) {
                Vdf.Node entry = e.getValue();
                if (entry.isLeaf()) {
                    // very old format: "1" "D:\\SteamLibrary"
                    addIfDir(out, entry.value());
                } else {
                    Vdf.Node path = entry.childIgnoreCase("path");
                    if (path != null) {
                        addIfDir(out, path.value());
                    }
                }
            }
        } catch (Exception ignored) {
            // unreadable — the Steam root alone still counts
        }
        return out;
    }

    private static void addIfDir(List<Path> out, String raw) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        Path p = Path.of(raw.replace("\\\\", "\\"));
        if (Files.isDirectory(p) && !out.contains(p)) {
            out.add(p);
        }
    }

    /** Locate CS2, searching every Steam root and library. */
    public static Optional<Install> find() {
        for (Path steamRoot : steamRoots()) {
            for (Path library : libraries(steamRoot)) {
                Path manifest = library.resolve("steamapps").resolve("appmanifest_" + CS2_APP_ID + ".acf");
                if (!Files.isRegularFile(manifest)) {
                    continue;
                }
                try {
                    Vdf.Node state = Vdf.parse(Files.readString(manifest)).childIgnoreCase("AppState");
                    if (state == null) {
                        continue;
                    }
                    String installDir = leaf(state, "installdir");
                    if (installDir == null || installDir.isBlank()) {
                        continue;
                    }
                    Path gameRoot = library.resolve("steamapps").resolve("common").resolve(installDir);
                    if (!Files.isDirectory(gameRoot)) {
                        continue;
                    }
                    long updated = parseLong(leaf(state, "LastUpdated"));
                    return Optional.of(new Install(gameRoot, steamRoot, leaf(state, "buildid"), updated));
                } catch (Exception ignored) {
                    // try the next library
                }
            }
        }
        return Optional.empty();
    }

    /** CS2 launch options set in Steam, per local user profile. */
    public static List<String> launchOptions(Path steamRoot) {
        List<String> out = new ArrayList<>();
        Path userdata = steamRoot.resolve("userdata");
        if (!Files.isDirectory(userdata)) {
            return out;
        }
        try (var users = Files.list(userdata)) {
            for (Path user : users.toList()) {
                Path local = user.resolve("config").resolve("localconfig.vdf");
                if (!Files.isRegularFile(local)) {
                    continue;
                }
                try {
                    Vdf.Node node = Vdf.parse(Files.readString(local));
                    Vdf.Node apps = descend(node, "UserLocalConfigStore", "Software", "Valve", "Steam", "apps");
                    if (apps == null) {
                        continue;
                    }
                    Vdf.Node cs2 = apps.childIgnoreCase(CS2_APP_ID);
                    if (cs2 == null) {
                        continue;
                    }
                    String opts = leaf(cs2, "LaunchOptions");
                    if (opts != null && !opts.isBlank()) {
                        out.add(opts.trim());
                    }
                } catch (Exception ignored) {
                    // next user
                }
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }

    static Vdf.Node descend(Vdf.Node from, String... path) {
        Vdf.Node cur = from;
        for (String key : path) {
            if (cur == null) {
                return null;
            }
            cur = cur.childIgnoreCase(key);
        }
        return cur;
    }

    private static String leaf(Vdf.Node parent, String key) {
        Vdf.Node n = parent.childIgnoreCase(key);
        return n != null ? n.value() : null;
    }

    private static long parseLong(String s) {
        try {
            return s == null ? 0 : Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}

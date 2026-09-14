package ru.moon.checker.cs2;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parser for CS2's {@code gameinfo.gi}, specifically its
 * {@code FileSystem / SearchPaths} block.
 *
 * <p>Source 2 loads code and assets from these paths, so adding one is how a
 * cheat gets itself loaded without patching any game binary. This needs its own
 * line-based parser rather than the generic {@link ru.moon.checker.parse.Vdf}
 * one, because SearchPaths deliberately repeats keys ({@code Game csgo},
 * {@code Game core}, ...) and a map-backed parser collapses duplicates.
 */
public final class GameInfo {

    /** Path tokens a stock CS2 install declares. */
    private static final Set<String> STOCK = Set.of(
            "", ".", "csgo", "core", "platform", "csgo_imported", "csgo_core",
            "csgo_lv", "csgo_addons", "game", "content", "mod"
    );

    /** Stock installs also use csgo_<locale> style folders. */
    private static final Pattern STOCK_PREFIXED = Pattern.compile("^csgo_[a-z0-9_]+$");

    /** Engine macros that may prefix a path value. */
    private static final String[] MACROS = {
            "|all_source_engine_paths|", "|gameinfo_path|", "|game_path|"
    };

    private final List<String> searchPaths;

    private GameInfo(List<String> searchPaths) {
        this.searchPaths = searchPaths;
    }

    public List<String> searchPaths() {
        return searchPaths;
    }

    public static GameInfo parse(String text) {
        List<String> paths = new ArrayList<>();
        if (text == null) {
            return new GameInfo(paths);
        }
        boolean inSearchPaths = false;
        int depth = 0;
        for (String raw : text.split("\\R")) {
            String line = stripComment(raw).trim();
            if (line.isEmpty()) {
                continue;
            }
            if (!inSearchPaths) {
                // the key may be bare (SearchPaths) or quoted ("SearchPaths")
                String key = line.replace("\"", "").trim().toLowerCase(Locale.ROOT);
                if (key.startsWith("searchpaths")) {
                    inSearchPaths = true;
                    depth = 0;
                }
                continue;
            }
            if (line.startsWith("{")) {
                depth++;
                continue;
            }
            if (line.startsWith("}")) {
                if (--depth <= 0) {
                    break; // end of SearchPaths
                }
                continue;
            }
            String value = valueOf(line);
            if (value != null && !value.isBlank()) {
                paths.add(value.trim());
            }
        }
        return new GameInfo(paths);
    }

    /** {@code Game    csgo} -> {@code csgo}; handles quoted forms. */
    private static String valueOf(String line) {
        if (line.startsWith("\"")) {
            // "Game"    "csgo"
            int closeKey = line.indexOf('"', 1);
            if (closeKey < 0) {
                return null;
            }
            String rest = line.substring(closeKey + 1).trim();
            return unquote(rest);
        }
        int sp = indexOfWhitespace(line);
        if (sp < 0) {
            return null;
        }
        return unquote(line.substring(sp).trim());
    }

    private static int indexOfWhitespace(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    private static String unquote(String s) {
        String t = s.trim();
        if (t.length() >= 2 && t.startsWith("\"") && t.endsWith("\"")) {
            return t.substring(1, t.length() - 1);
        }
        int q = t.indexOf('"');
        if (q >= 0) {
            int end = t.indexOf('"', q + 1);
            if (end > q) {
                return t.substring(q + 1, end);
            }
        }
        return t;
    }

    private static String stripComment(String line) {
        int i = line.indexOf("//");
        return i >= 0 ? line.substring(0, i) : line;
    }

    /**
     * Search paths that a stock install would not declare — an absolute path, a
     * parent-directory escape, or an unknown folder name. These are the ones
     * worth showing an admin.
     */
    public List<String> foreignSearchPaths() {
        List<String> out = new ArrayList<>();
        for (String path : searchPaths) {
            if (isForeign(path)) {
                out.add(path);
            }
        }
        return out;
    }

    static boolean isForeign(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return false;
        }
        String p = rawPath.trim().toLowerCase(Locale.ROOT);

        // absolute paths and directory escapes are never stock
        if (p.contains("..") || p.startsWith("/") || p.startsWith("\\")
                || p.matches("^[a-z]:[\\\\/].*")) {
            return true;
        }
        for (String macro : MACROS) {
            if (p.startsWith(macro)) {
                p = p.substring(macro.length());
            }
        }
        // trim decoration the engine allows around a token
        p = p.replace("\\", "/").trim();
        while (p.startsWith("./")) {
            p = p.substring(2);
        }
        while (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        if (STOCK.contains(p) || STOCK_PREFIXED.matcher(p).matches()) {
            return false;
        }
        return true;
    }
}

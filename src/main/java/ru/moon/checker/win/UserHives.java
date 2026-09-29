package ru.moon.checker.win;

import com.sun.jna.platform.win32.WinReg.HKEY;
import ru.moon.checker.core.Log;
import ru.moon.checker.core.Platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Gives every module access to <em>all</em> users' registry hives, not just the
 * interactive user's — so a cheater's second Windows account can't hide the
 * evidence. Currently-logged-in users are read straight from {@code HKEY_USERS};
 * logged-off users have their {@code NTUSER.DAT} temporarily mounted with
 * {@code reg load} and always unmounted on {@link Scope#close()}.
 */
public final class UserHives {

    private static final AtomicInteger COUNTER = new AtomicInteger();

    private UserHives() {
    }

    /** One user's registry root: read keys via {@code Registry.*(root(), path(rel))}. */
    public record User(HKEY root, String prefix, String label) {
        public String path(String relative) {
            return prefix + relative;
        }
    }

    /** A set of user hives; unmounts any it mounted when closed. */
    public static final class Scope implements AutoCloseable {
        private final List<User> users;
        private final List<String> mounted;

        Scope(List<User> users, List<String> mounted) {
            this.users = users;
            this.mounted = mounted;
        }

        public List<User> users() {
            return users;
        }

        @Override
        public void close() {
            for (String key : mounted) {
                if (!WinCommand.run(15, "reg", "unload", "HKU\\" + key).ok()) {
                    Log.warn("failed to unload hive " + key);
                }
            }
        }
    }

    public static Scope open() {
        List<User> users = new ArrayList<>();
        List<String> mounted = new ArrayList<>();

        if (!Platform.isWindows()) {
            users.add(new User(Registry.HKCU, "", "current"));
            return new Scope(users, mounted);
        }

        // 1. every currently-loaded user hive under HKEY_USERS
        java.util.Set<String> loadedSids = new java.util.HashSet<>();
        for (String sid : Registry.subKeys(Registry.HKU, "")) {
            if (sid.startsWith("S-1-5-21") && !sid.endsWith("_Classes")) {
                users.add(new User(Registry.HKU, sid + "\\", sid));
                loadedSids.add(sid.toUpperCase(java.util.Locale.ROOT));
            }
        }
        if (users.isEmpty()) {
            users.add(new User(Registry.HKCU, "", "current"));
        }
        java.util.Set<String> loadedProfiles = loadedProfilePaths(loadedSids);

        // 2. logged-off profiles: mount NTUSER.DAT. A signed-in user's hive is already under
        //    HKEY_USERS (read above) and its file is locked, so it is skipped, not re-mounted.
        for (Path profile : Platform.userProfiles()) {
            Path ntuser = profile.resolve("NTUSER.DAT");
            if (!Files.isRegularFile(ntuser)
                    || loadedProfiles.contains(profile.toString().toLowerCase(java.util.Locale.ROOT))) {
                continue;
            }
            String tempKey = "MoonChk_" + COUNTER.incrementAndGet();
            if (WinCommand.run(20, "reg", "load", "HKU\\" + tempKey, ntuser.toString()).ok()) {
                mounted.add(tempKey);
                users.add(new User(Registry.HKU, tempKey + "\\", profile.getFileName().toString()));
            } else {
                Log.warn("could not mount hive for " + profile);
            }
        }
        return new Scope(users, mounted);
    }

    /** Profile folders (lower case) of the users whose hives are loaded, from ProfileList. */
    private static java.util.Set<String> loadedProfilePaths(java.util.Set<String> loadedSids) {
        java.util.Set<String> out = new java.util.HashSet<>();
        String base = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        for (String sid : Registry.subKeys(Registry.HKLM, base)) {
            if (loadedSids.contains(sid.toUpperCase(java.util.Locale.ROOT))) {
                String path = Registry.getString(Registry.HKLM, base + "\\" + sid, "ProfileImagePath");
                if (path != null) {
                    out.add(expand(path).toLowerCase(java.util.Locale.ROOT));
                }
            }
        }
        return out;
    }

    /** ProfileImagePath is REG_EXPAND_SZ ("%SystemDrive%\\Users\\x"). */
    static String expand(String path) {
        String drive = System.getenv("SystemDrive");
        return path.replaceAll("(?i)%SystemDrive%", java.util.regex.Matcher.quoteReplacement(drive != null ? drive : "C:"));
    }
}

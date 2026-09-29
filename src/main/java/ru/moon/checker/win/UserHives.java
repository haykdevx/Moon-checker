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
        for (String sid : Registry.subKeys(Registry.HKU, "")) {
            if (sid.startsWith("S-1-5-21") && !sid.endsWith("_Classes")) {
                users.add(new User(Registry.HKU, sid + "\\", sid));
            }
        }
        if (users.isEmpty()) {
            users.add(new User(Registry.HKCU, "", "current"));
        }

        // 2. logged-off profiles: mount NTUSER.DAT (fails for locked/loaded ones)
        for (Path profile : Platform.userProfiles()) {
            Path ntuser = profile.resolve("NTUSER.DAT");
            if (!Files.isRegularFile(ntuser)) {
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
}

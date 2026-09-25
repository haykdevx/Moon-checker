package ru.moon.checker.win;

import com.sun.jna.platform.win32.WinReg.HKEY;
import ru.moon.checker.core.Log;
import ru.moon.checker.core.Platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Gives every module access to <em>all</em> users' registry hives, not just the
 * interactive user's — so a cheater's second Windows account can't hide the
 * evidence. Currently-logged-in users are read straight from {@code HKEY_USERS};
 * logged-off users have their {@code NTUSER.DAT} temporarily mounted with
 * {@code reg load}.
 *
 * <p>The mounts are <b>shared and reference-counted</b>: several modules run in
 * parallel and each opens a scope. Mounting per scope made the second
 * {@code reg load} of the same {@code NTUSER.DAT} fail (the first mount holds the
 * file), so whichever module lost the race silently skipped those users. Now the
 * first {@link #open()} mounts, later ones reuse, and the last
 * {@link Scope#close()} unmounts.
 */
public final class UserHives {

    private static final Object LOCK = new Object();
    private static int refs;
    private static List<User> shared = List.of();
    private static List<String> mounted = List.of();

    /** Platform access; replaced in tests. */
    static volatile Mounter mounter = new RegMounter();

    private UserHives() {
    }

    /** One user's registry root: read keys via {@code Registry.*(root(), path(rel))}. */
    public record User(HKEY root, String prefix, String label) {
        public String path(String relative) {
            return prefix + relative;
        }
    }

    /** A view of the shared user hives; releases its reference when closed. */
    public static final class Scope implements AutoCloseable {
        private final List<User> users;
        private final AtomicBoolean closed = new AtomicBoolean();

        Scope(List<User> users) {
            this.users = users;
        }

        public List<User> users() {
            return users;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                release();
            }
        }
    }

    /** What {@link UserHives} needs from the OS. */
    interface Mounter {
        /** Users whose hive is already loaded (plus a fallback when none are). */
        List<User> loadedUsers();

        /** Profile folders whose {@code NTUSER.DAT} is not loaded yet. */
        List<Path> offlineProfiles(List<User> loaded);

        boolean mount(String key, Path ntuserDat);

        void unmount(String key);
    }

    public static Scope open() {
        synchronized (LOCK) {
            if (refs++ == 0) {
                acquire();
            }
            return new Scope(shared);
        }
    }

    private static void acquire() {
        Mounter m = mounter;
        List<User> users = new ArrayList<>(m.loadedUsers());
        List<String> keys = new ArrayList<>();
        int n = 0;
        for (Path profile : m.offlineProfiles(users)) {
            String key = "MoonChk_" + (++n); // stable names: a stale mount is reclaimed next run
            if (m.mount(key, profile.resolve("NTUSER.DAT"))) {
                keys.add(key);
                users.add(new User(Registry.HKU, key + "\\", String.valueOf(profile.getFileName())));
            }
        }
        shared = List.copyOf(users);
        mounted = List.copyOf(keys);
    }

    private static void release() {
        synchronized (LOCK) {
            if (refs == 0 || --refs > 0) {
                return;
            }
            for (String key : mounted) {
                mounter.unmount(key);
            }
            mounted = List.of();
            shared = List.of();
        }
    }

    /** Production mounter backed by HKEY_USERS, ProfileList and reg.exe. */
    static final class RegMounter implements Mounter {
        private static final String PROFILE_LIST = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

        @Override
        public List<User> loadedUsers() {
            List<User> users = new ArrayList<>();
            if (Platform.isWindows()) {
                for (String sid : Registry.subKeys(Registry.HKU, "")) {
                    if (sid.startsWith("S-1-5-21") && !sid.endsWith("_Classes")) {
                        users.add(new User(Registry.HKU, sid + "\\", profileName(sid)));
                    }
                }
            }
            if (users.isEmpty()) {
                users.add(new User(Registry.HKCU, "", "current"));
            }
            return users;
        }

        @Override
        public List<Path> offlineProfiles(List<User> loaded) {
            List<Path> out = new ArrayList<>();
            if (!Platform.isWindows()) {
                return out;
            }
            Set<String> loadedNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            loaded.forEach(u -> loadedNames.add(u.label()));
            for (Path profile : Platform.userProfiles()) {
                String name = String.valueOf(profile.getFileName());
                if (!loadedNames.contains(name) && Files.isRegularFile(profile.resolve("NTUSER.DAT"))) {
                    out.add(profile);
                }
            }
            return out;
        }

        @Override
        public boolean mount(String key, Path ntuserDat) {
            HiveMount.LoadResult r = HiveMount.load(HiveMount.Root.HKU, key, ntuserDat);
            if (!r.loaded()) {
                Log.warn("could not mount " + ntuserDat + ": " + r.output());
            }
            return r.loaded();
        }

        @Override
        public void unmount(String key) {
            HiveMount.unload(HiveMount.Root.HKU, key);
        }

        /** Profile folder name for a SID (e.g. "Игрок"), or the SID itself. */
        private static String profileName(String sid) {
            String image = Registry.getString(Registry.HKLM, PROFILE_LIST + "\\" + sid, "ProfileImagePath");
            if (image == null || image.isBlank()) {
                return sid;
            }
            String p = image.replace('/', '\\');
            int i = p.lastIndexOf('\\');
            String name = i >= 0 ? p.substring(i + 1) : p;
            return name.isEmpty() ? sid : name;
        }
    }
}

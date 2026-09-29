package ru.moon.checker.checks;

import ru.moon.checker.core.Platform;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Where a file lives, decided on normalised paths and whole path components.
 *
 * <p>This replaced substring matching ("\\steam\\steamapps\\common\\" anywhere in the
 * path), which let {@code Downloads\x\steam\steamapps\common\cheat.exe} count as a Steam
 * file. The rules:
 * <ul>
 *   <li>paths are normalised first (Windows: case-folded, {@code /} → {@code \}, the
 *       {@code \\?\}, {@code \??\}, {@code \\.\} prefixes removed, {@code .} and {@code ..}
 *       resolved without leaving the drive);</li>
 *   <li>a root matches only as a whole prefix followed by a separator, so
 *       {@code C:\Program Files Evil} is not under {@code C:\Program Files};</li>
 *   <li>roots come from this machine (SystemRoot, ProgramFiles, …), not from fixed letters;</li>
 *   <li>the most specific root wins: {@code C:\Windows\Temp} is user-writable although it
 *       is under {@code C:\Windows};</li>
 *   <li>for a file on disk the real path (symbolic links and junctions resolved) is
 *       classified too and the less trusted answer is used; a path that cannot be resolved
 *       is never trusted; network paths are never trusted;</li>
 *   <li>on Linux a system location also needs a root-owned file that no one else can write.</li>
 * </ul>
 *
 * <p>A location is not an identity. Anyone with administrator rights — the player, on their
 * own PC — can write into Program Files. {@link FileInspection} therefore never drops a
 * finding because of the location alone; it uses the location to word and weigh findings
 * whose file identity could not be verified.
 */
public final class Locations {

    public enum Kind {
        /** Operating-system folders (Windows directory, /usr, /lib…). */
        SYSTEM,
        /** Program install folders (Program Files, /opt). */
        PROGRAM,
        /** Folders an ordinary user can write to: profiles, Temp, ProgramData, Public, /home, /tmp. */
        USER_WRITABLE,
        /** A network share: never trusted. */
        NETWORK,
        /** Anywhere else on a local drive (D:\Games, C:\tools). */
        OTHER,
        /** Not an absolute path, or its real location could not be established. */
        UNKNOWN;

        /** Locations where a program is normally installed by an administrator. */
        public boolean protectedByDefault() {
            return this == SYSTEM || this == PROGRAM;
        }
    }

    private record Root(String path, Kind kind) {
    }

    /** The roots of one machine, normalised. */
    public static final class Roots {
        private final boolean windows;
        private final List<Root> roots;

        private Roots(boolean windows, List<Root> roots) {
            this.windows = windows;
            this.roots = List.copyOf(roots);
        }

        public boolean windows() {
            return windows;
        }

        /** Windows roots from environment variables (case-insensitive names), falling back to defaults. */
        public static Roots windows(Map<String, String> env) {
            String systemRoot = firstNonBlank(get(env, "SystemRoot"), get(env, "windir"), "C:\\Windows");
            String systemDrive = firstNonBlank(get(env, "SystemDrive"), systemRoot.length() >= 2
                    ? systemRoot.substring(0, 2) : "C:");
            List<Root> out = new ArrayList<>();
            add(out, systemRoot, Kind.SYSTEM, true);
            // folders inside the Windows directory that standard users can write to by default
            for (String sub : new String[]{"Temp", "Tasks", "Tracing", "Registration\\CRMLog",
                    "System32\\spool\\drivers\\color", "System32\\spool\\PRINTERS", "System32\\spool\\SERVERS",
                    "System32\\Tasks", "SysWOW64\\Tasks", "System32\\Microsoft\\Crypto\\RSA\\MachineKeys",
                    "SysWOW64\\Microsoft\\Crypto\\RSA\\MachineKeys", "System32\\com\\dmp", "SysWOW64\\com\\dmp",
                    "System32\\FxsTmp", "SysWOW64\\FxsTmp"}) {
                add(out, systemRoot + "\\" + sub, Kind.USER_WRITABLE, true);
            }
            for (String var : new String[]{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"}) {
                add(out, get(env, var), Kind.PROGRAM, true);
            }
            add(out, systemDrive + "\\Program Files", Kind.PROGRAM, true);
            add(out, systemDrive + "\\Program Files (x86)", Kind.PROGRAM, true);
            String programData = firstNonBlank(get(env, "ProgramData"), systemDrive + "\\ProgramData");
            add(out, programData, Kind.USER_WRITABLE, true);   // users may create folders there
            add(out, programData + "\\Microsoft\\Windows Defender", Kind.SYSTEM, true);
            add(out, systemDrive + "\\Users", Kind.USER_WRITABLE, true);
            add(out, get(env, "PUBLIC"), Kind.USER_WRITABLE, true);
            add(out, systemDrive + "\\$Recycle.Bin", Kind.USER_WRITABLE, true);
            add(out, systemDrive + "\\Temp", Kind.USER_WRITABLE, true);
            add(out, get(env, "TEMP"), Kind.USER_WRITABLE, true);
            add(out, get(env, "TMP"), Kind.USER_WRITABLE, true);
            return new Roots(true, out);
        }

        /** Linux / Unix roots. */
        public static Roots unix() {
            List<Root> out = new ArrayList<>();
            for (String s : new String[]{"/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/boot"}) {
                add(out, s, Kind.SYSTEM, false);
            }
            for (String s : new String[]{"/opt", "/snap", "/var/lib/flatpak"}) {
                add(out, s, Kind.PROGRAM, false);
            }
            for (String s : new String[]{"/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/run/user", "/media",
                    "/mnt", "/usr/local/games/tmp"}) {
                add(out, s, Kind.USER_WRITABLE, false);
            }
            return new Roots(false, out);
        }

        /** Explicit roots (tests): path → kind, normalised here. */
        static Roots of(boolean windows, Map<String, Kind> roots) {
            List<Root> out = new ArrayList<>();
            roots.forEach((path, kind) -> add(out, path, kind, windows));
            return new Roots(windows, out);
        }

        /** The roots of the machine this runs on. */
        public static Roots current() {
            return Platform.isWindows() ? windows(System.getenv()) : unix();
        }

        private static void add(List<Root> out, String raw, Kind kind, boolean windows) {
            String n = normalize(raw, windows);
            if (n != null && n.length() > (windows ? 3 : 1)) {   // never a whole drive or "/"
                out.add(new Root(n, kind));
            }
        }
    }

    private static volatile Roots current;

    private Locations() {
    }

    public static Roots roots() {
        Roots r = current;
        if (r == null) {
            r = current = Roots.current();
        }
        return r;
    }

    /**
     * A comparable form of {@code raw}, or null when it is not an absolute path. Windows paths
     * are case-folded; network paths keep their {@code \\server\share} form.
     */
    public static String normalize(String raw, boolean windows) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String s = raw.trim();
        if (!windows) {
            if (!s.startsWith("/")) {
                return null;
            }
            return join(resolveDots(s.substring(1).split("/+")), "/", "/");
        }
        s = s.replace('/', '\\');
        if (s.regionMatches(true, 0, "\\\\?\\UNC\\", 0, 8)) {
            s = "\\\\" + s.substring(8);
        } else if (s.startsWith("\\\\?\\") || s.startsWith("\\??\\") || s.startsWith("\\\\.\\")) {
            s = s.substring(4);
        }
        s = s.toLowerCase(Locale.ROOT);
        if (s.startsWith("\\\\")) {                      // \\server\share\…
            List<String> parts = resolveDots(s.substring(2).split("\\\\+"));
            return parts.size() < 2 ? null : "\\\\" + String.join("\\", parts);
        }
        if (s.length() < 3 || !Character.isLetter(s.charAt(0)) || s.charAt(1) != ':' || s.charAt(2) != '\\') {
            return null;
        }
        return join(resolveDots(s.substring(3).split("\\\\+")), s.substring(0, 3), "\\");
    }

    private static List<String> resolveDots(String[] parts) {
        List<String> out = new ArrayList<>();
        for (String p : parts) {
            if (p.isEmpty() || p.equals(".")) {
                continue;
            }
            if (p.equals("..")) {
                if (!out.isEmpty()) {
                    out.remove(out.size() - 1);   // never above the drive or "/"
                }
                continue;
            }
            out.add(p);
        }
        return out;
    }

    private static String join(List<String> parts, String prefix, String sep) {
        return prefix + String.join(sep, parts);
    }

    /** {@code path} is {@code root} itself or inside it (whole path components). Both normalised. */
    public static boolean under(String path, String root, boolean windows) {
        if (path == null || root == null) {
            return false;
        }
        if (path.equals(root)) {
            return true;
        }
        String sep = windows ? "\\" : "/";
        return path.startsWith(root.endsWith(sep) ? root : root + sep);
    }

    /** Classifies a normalised path by the most specific matching root. */
    public static Kind classify(String normalized, Roots roots) {
        if (normalized == null) {
            return Kind.UNKNOWN;
        }
        if (roots.windows() && normalized.startsWith("\\\\")) {
            return Kind.NETWORK;
        }
        Root best = null;
        for (Root r : roots.roots) {
            if (under(normalized, r.path(), roots.windows()) && (best == null || r.path().length() > best.path().length())) {
                best = r;
            }
        }
        return best != null ? best.kind() : Kind.OTHER;
    }

    /** Classifies a path as written (no file-system access). */
    public static Kind classify(String rawPath) {
        Roots r = roots();
        return classify(normalize(rawPath, r.windows()), r);
    }

    /**
     * Where a file on disk really is: the path as given and its real path (links and
     * junctions resolved) are both classified and the less trusted answer is returned. A
     * protected location that cannot be confirmed (the real path is unavailable, or on Linux
     * the file is not root-owned and closed to others) is {@link Kind#UNKNOWN}.
     */
    public static Kind ofFile(Path file) {
        return ofFile(file, roots());
    }

    static Kind ofFile(Path file, Roots roots) {
        Kind lexical = classify(normalize(file.toString(), roots.windows()), roots);
        Path real;
        try {
            real = file.toRealPath();
        } catch (Exception e) {
            return lexical.protectedByDefault() ? Kind.UNKNOWN : lexical;
        }
        Kind resolved = classify(normalize(real.toString(), roots.windows()), roots);
        Kind kind = lessTrusted(lexical, resolved);
        if (kind.protectedByDefault() && !roots.windows() && !rootOwnedAndClosed(real)) {
            return Kind.UNKNOWN;
        }
        return kind;
    }

    /** Of two answers, the one that grants less trust. */
    static Kind lessTrusted(Kind a, Kind b) {
        return rank(a) <= rank(b) ? a : b;
    }

    private static int rank(Kind k) {
        return switch (k) {
            case NETWORK, UNKNOWN -> 0;
            case USER_WRITABLE -> 1;
            case OTHER -> 2;
            case PROGRAM -> 3;
            case SYSTEM -> 4;
        };
    }

    /** Linux: owned by root, and neither the file nor its folder writable by group or others. */
    static boolean rootOwnedAndClosed(Path real) {
        try {
            for (Path p : new Path[]{real, real.getParent()}) {
                if (p == null) {
                    continue;
                }
                Object uid = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS);
                Object mode = Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS);
                if (!(uid instanceof Integer u) || u != 0 || !(mode instanceof Integer m) || (m & 0022) != 0) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String get(Map<String, String> env, String name) {
        for (var e : env.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return null;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}

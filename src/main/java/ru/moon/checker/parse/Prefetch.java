package ru.moon.checker.parse;

/**
 * Prefetch helper. A file {@code C:\Windows\Prefetch\NAME.EXE-1A2B3C4D.pf}
 * proves {@code NAME.EXE} was executed; the file's own last-modified time is
 * (very close to) the last run. Windows 10/11 prefetch bodies are MAM-compressed,
 * so this parser works from the filename — which is all we need to correlate an
 * executable name against the signature list.
 */
public final class Prefetch {

    private Prefetch() {
    }

    public record Info(String exeName, String hash) {
    }

    /** Parse {@code NAME.EXE-HASH.pf}; returns null if it isn't a .pf name. */
    public static Info fromFileName(String fileName) {
        if (fileName == null) {
            return null;
        }
        String lower = fileName.toLowerCase();
        if (!lower.endsWith(".pf")) {
            return null;
        }
        String base = fileName.substring(0, fileName.length() - 3); // drop .pf
        int dash = base.lastIndexOf('-');
        if (dash <= 0) {
            return new Info(base, null);
        }
        String exe = base.substring(0, dash);
        String hash = base.substring(dash + 1);
        return new Info(exe, hash);
    }
}

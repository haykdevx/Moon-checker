package ru.moon.checker.core;

import java.nio.file.Path;

/** Build metadata shared by the GUI and the command-line entry points. */
public final class AppInfo {

    private static final String FALLBACK_VERSION = "1.1.0";

    private AppInfo() {
    }

    /** Version from the jar manifest ({@code Implementation-Version}). */
    public static String version() {
        String v = AppInfo.class.getPackage().getImplementationVersion();
        return v != null ? v : FALLBACK_VERSION;
    }

    /** Folder containing the running jar/exe (where an override signatures.json may sit). */
    public static Path exeDir() {
        try {
            Path self = Path.of(AppInfo.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return self.getParent();
        } catch (Exception e) {
            return Path.of(".");
        }
    }
}

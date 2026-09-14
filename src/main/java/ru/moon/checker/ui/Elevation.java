package ru.moon.checker.ui;

import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Platform;

import javax.swing.JOptionPane;
import java.nio.file.Path;

/**
 * Relaunches the checker elevated (administrator) via the UAC prompt. In the
 * shipped .exe elevation is already requested by the manifest, so this is
 * mainly for running the raw .jar during development.
 */
public final class Elevation {

    private Elevation() {
    }

    public static void relaunchElevated() {
        if (!Platform.isWindows()) {
            info(I18n.t("elevate.manual"));
            return;
        }
        try {
            Path self = Path.of(Elevation.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            String selfStr = self.toString();
            ProcessBuilder pb;
            if (selfStr.toLowerCase().endsWith(".exe")) {
                pb = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                        "Start-Process", "-FilePath", "\"" + selfStr + "\"", "-Verb", "RunAs");
            } else if (selfStr.toLowerCase().endsWith(".jar")) {
                String javaw = Path.of(System.getProperty("java.home"), "bin", "javaw.exe").toString();
                pb = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                        "Start-Process", "-FilePath", "\"" + javaw + "\"",
                        "-ArgumentList", "'-jar','\"" + selfStr + "\"'", "-Verb", "RunAs");
            } else {
                info(I18n.t("elevate.manual"));
                return;
            }
            pb.start();
            System.exit(0);
        } catch (Throwable t) {
            info(I18n.t("elevate.manual"));
        }
    }

    private static void info(String msg) {
        JOptionPane.showMessageDialog(null, msg, "Moon Checker", JOptionPane.INFORMATION_MESSAGE);
    }
}

package ru.moon.checker;

import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Hashing;
import ru.moon.checker.core.I18n;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.ui.MainWindow;
import ru.moon.checker.ui.MoonTheme;
import ru.moon.checker.win.WinInfo;

import javax.swing.SwingUtilities;
import java.nio.file.Path;

/**
 * Application entry point for the Moon anti-cheat checker.
 *
 * <p>Boots the Swing UI in the cs2-moon.ru theme, captures machine/run metadata
 * (including whether we are elevated and the self-hash of this build), loads the
 * signature database (bundled, or an override sitting next to the exe), and
 * opens the main window. The scan itself is triggered by the operator from the
 * start screen.
 */
public final class Main {

    private static final String FALLBACK_VERSION = "1.0.0";

    private Main() {
    }

    public static void main(String[] args) {
        Thread.setDefaultUncaughtExceptionHandler((t, e) ->
                ru.moon.checker.core.Log.error("uncaught in " + t.getName(), e));

        boolean elevated = ru.moon.checker.core.Platform.isWindows()
                ? WinInfo.isElevated()
                : ru.moon.checker.linux.LinuxInfo.isRoot();
        String version = appVersion();
        String selfHash = Hashing.selfHashShort();
        EnvironmentInfo env = EnvironmentInfo.capture(elevated, version, selfHash);

        SignatureLoader.Result sig = SignatureLoader.load(exeDir());
        SignatureDb db = sig.db();
        ru.moon.checker.core.Log.info("Moon Checker " + version + " start; elevated=" + elevated
                + "; signatures " + sig.origin() + " v" + db.version() + " (" + db.ruleCount() + " rules)"
                + (sig.error() != null ? "; sigError=" + sig.error() : ""));

        I18n.setLocale(I18n.RUSSIAN);

        SwingUtilities.invokeLater(() -> {
            MoonTheme.install();
            MainWindow window = new MainWindow(env, db);
            window.setTitle("Moon Checker — " + I18n.t("app.subtitle"));
            window.setVisible(true);
        });
    }

    private static String appVersion() {
        String v = Main.class.getPackage().getImplementationVersion();
        return v != null ? v : FALLBACK_VERSION;
    }

    private static Path exeDir() {
        try {
            Path self = Path.of(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return self.getParent();
        } catch (Exception e) {
            return Path.of(".");
        }
    }
}

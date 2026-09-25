package ru.moon.checker;

import ru.moon.checker.cli.Cli;
import ru.moon.checker.cli.CliArgs;
import ru.moon.checker.core.AppInfo;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Hashing;
import ru.moon.checker.core.I18n;
import ru.moon.checker.net.ServerConfig;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.ui.MainWindow;
import ru.moon.checker.ui.MoonTheme;
import ru.moon.checker.win.WinInfo;

import javax.swing.SwingUtilities;

/**
 * Application entry point for the Moon anti-cheat checker.
 *
 * <p>Boots the Swing UI in the cs2-moon.ru theme, captures machine/run metadata
 * (including whether we are elevated and the self-hash of this build), loads the
 * signature database (bundled, or an override sitting next to the exe), and
 * opens the main window. The scan itself is triggered by the operator from the
 * start screen once the admin's check code is accepted by the Moon panel.
 * {@code --headless} / {@code --diagnose} select a non-GUI mode instead, and
 * {@code --server} / {@code --offline} change where results go (see {@link CliArgs}).
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        Thread.setDefaultUncaughtExceptionHandler((t, e) ->
                ru.moon.checker.core.Log.error("uncaught in " + t.getName(), e));

        CliArgs cli = CliArgs.parse(args);
        if (cli.mode() != CliArgs.Mode.GUI || cli.error() != null) {
            System.exit(Cli.run(cli));
            return;
        }

        boolean elevated = ru.moon.checker.core.Platform.isWindows()
                ? WinInfo.isElevated()
                : ru.moon.checker.linux.LinuxInfo.isRoot();
        String version = AppInfo.version();
        String selfHash = Hashing.selfHashShort();
        EnvironmentInfo env = EnvironmentInfo.capture(elevated, version, selfHash);

        SignatureLoader.Result sig = SignatureLoader.load(AppInfo.exeDir());
        SignatureDb db = sig.db();
        ru.moon.checker.core.Log.info("Moon Checker " + version + " start; elevated=" + elevated
                + "; signatures " + sig.origin() + " v" + db.version() + " (" + db.ruleCount() + " rules)"
                + (sig.error() != null ? "; sigError=" + sig.error() : ""));

        ServerConfig server = ServerConfig.resolve(cli.server(), cli.offline(), AppInfo.exeDir());
        ru.moon.checker.core.Log.info("panel: " + (server.online() ? server.base() : "offline")
                + " (" + server.origin() + ")" + (server.error() != null ? "; error=" + server.error() : ""));

        I18n.setLocale(I18n.RUSSIAN);

        SwingUtilities.invokeLater(() -> {
            MoonTheme.install();
            if (server.error() != null) {
                javax.swing.JOptionPane.showMessageDialog(null, "Moon panel URL is invalid: " + server.error()
                        + "\nThe checker will run offline.", "Moon Checker", javax.swing.JOptionPane.WARNING_MESSAGE);
            }
            MainWindow window = new MainWindow(env, db, server);
            window.setTitle("Moon Checker — " + I18n.t("app.subtitle"));
            window.setVisible(true);
        });
    }
}

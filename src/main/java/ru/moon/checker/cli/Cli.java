package ru.moon.checker.cli;

import ru.moon.checker.core.AppInfo;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Hashing;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.Log;
import ru.moon.checker.core.Platform;
import ru.moon.checker.diag.Diagnostics;
import ru.moon.checker.linux.LinuxInfo;
import ru.moon.checker.net.ServerConfig;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.win.WinInfo;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/** Command-line entry: {@code --headless}, {@code --diagnose}, {@code --help}. */
public final class Cli {

    public static final int EXIT_CRASH = 1;
    public static final int EXIT_USAGE = 2;

    private Cli() {
    }

    /** Runs a non-GUI mode and returns the process exit code. */
    public static int run(CliArgs args) {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        if (args.error() != null) {
            out.println("error: " + args.error());
            out.print(CliArgs.USAGE);
            return EXIT_USAGE;
        }
        if (args.mode() == CliArgs.Mode.HELP) {
            out.print(CliArgs.USAGE);
            return 0;
        }
        System.setProperty("java.awt.headless", "true");
        I18n.setLocale(args.lang().equals("en") ? I18n.ENGLISH : I18n.RUSSIAN);
        try {
            boolean elevated = Platform.isWindows() ? WinInfo.isElevated() : LinuxInfo.isRoot();
            EnvironmentInfo env = EnvironmentInfo.capture(elevated, AppInfo.version(), Hashing.selfHashShort());
            if (args.mode() == CliArgs.Mode.DIAGNOSE) {
                return Diagnostics.run(env, args.out(), out);
            }
            SignatureLoader.Result sig = SignatureLoader.load(AppInfo.exeDir());
            if (sig.error() != null) {
                out.println("signature warning: " + sig.error());
            }
            ServerConfig server = ServerConfig.resolve(args.server(), args.offline() || args.code() == null,
                    AppInfo.exeDir());
            if (args.code() != null && !server.online()) {
                out.println("error: no usable Moon panel URL: " + server.error());
                return EXIT_USAGE;
            }
            return HeadlessScan.run(args, env, sig.db(), server, out);
        } catch (Throwable t) {
            Log.error("command-line run crashed", t);
            out.println("crashed: " + t);
            return EXIT_CRASH;
        }
    }
}

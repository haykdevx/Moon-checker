package ru.moon.checker.cli;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Parsed command line. No arguments means the normal GUI; the flags below exist
 * for CI smoke runs, for validating a Windows build on a test machine, and for
 * pointing the checker at a different Moon panel.
 *
 * <pre>
 *   --headless            run a full scan without UI, write JSON + HTML reports
 *   --diagnose            self-test every OS primitive the modules rely on
 *   --out DIR             where reports go (default: current directory)
 *   --lang ru|en          report / console language (default ru)
 *   --modules a,b,c       headless: only run these module ids
 *   --server URL          Moon panel to report to (GUI or headless)
 *   --code XXXX-XXXX      headless: the admin's check code; results are uploaded
 *   --offline             never contact the panel (GUI or headless)
 *   --help
 * </pre>
 */
public record CliArgs(Mode mode, Path out, String lang, Set<String> modules, String server, String code,
                      boolean offline, String error) {

    public enum Mode { GUI, HEADLESS, DIAGNOSE, HELP }

    public static final String USAGE = """
            Moon Checker — command line
              (no arguments)        start the GUI (asks for the admin's check code)
              --headless            scan without UI; writes MoonCheck-<id>.json/.html
              --diagnose            self-test the OS primitives (registry, MFT, USN, AmCache, ADS, ...)
              --out DIR             output folder (default: current directory)
              --lang ru|en          language of console output and reports (default: ru)
              --modules a,b         with --headless: run only these module ids
              --server URL          Moon panel URL (default: bundled / moon.properties)
              --code XXXX-XXXX      with --headless: connect with the admin's code and upload results
              --offline             do not contact the panel (standalone check, nothing is sent)
              --help                this text
            Exit codes: 0 ok, 1 crash, 2 bad arguments, 3 module error/timeout, 4 diagnostic failure,
                        5 results not delivered to the panel
            """;

    public static CliArgs parse(String[] args) {
        Mode mode = Mode.GUI;
        Path out = Path.of(".");
        String lang = "ru";
        String server = null;
        String code = null;
        boolean offline = false;
        Set<String> modules = new LinkedHashSet<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--headless" -> mode = pick(mode, Mode.HEADLESS);
                case "--diagnose" -> mode = pick(mode, Mode.DIAGNOSE);
                case "--help", "-h", "/?" -> mode = Mode.HELP;
                case "--offline" -> offline = true;
                case "--out", "--lang", "--modules", "--server", "--code" -> {
                    if (i + 1 >= args.length) {
                        return failed(a + " needs a value");
                    }
                    String v = args[++i];
                    switch (a) {
                        case "--out" -> out = Path.of(v);
                        case "--lang" -> {
                            lang = v.toLowerCase(Locale.ROOT);
                            if (!lang.equals("ru") && !lang.equals("en")) {
                                return failed("--lang must be ru or en");
                            }
                        }
                        case "--server" -> server = v.trim();
                        case "--code" -> code = v.trim();
                        default -> {
                            for (String id : v.split(",")) {
                                if (!id.isBlank()) {
                                    modules.add(id.trim());
                                }
                            }
                        }
                    }
                }
                default -> {
                    return failed("unknown argument: " + a);
                }
            }
            if (mode == null) {
                return failed("--headless and --diagnose are mutually exclusive");
            }
        }
        if (!modules.isEmpty() && mode != Mode.HEADLESS) {
            return failed("--modules only applies to --headless");
        }
        if (code != null && mode != Mode.HEADLESS) {
            return failed("--code only applies to --headless (the GUI asks for it)");
        }
        if (offline && (server != null || code != null)) {
            return failed("--offline cannot be combined with --server or --code");
        }
        if (mode == Mode.DIAGNOSE && (server != null || offline)) {
            return failed("--server/--offline do not apply to --diagnose");
        }
        return new CliArgs(mode, out, lang, Set.copyOf(modules), server, code, offline, null);
    }

    private static Mode pick(Mode current, Mode wanted) {
        return current == Mode.GUI || current == wanted ? wanted : current == Mode.HELP ? Mode.HELP : null;
    }

    private static CliArgs failed(String why) {
        return new CliArgs(Mode.HELP, Path.of("."), "ru", Set.of(), null, null, false, why);
    }

    public List<String> moduleList() {
        return List.copyOf(modules);
    }
}

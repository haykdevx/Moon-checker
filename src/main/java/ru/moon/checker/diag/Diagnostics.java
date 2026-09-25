package ru.moon.checker.diag;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Platform;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code --diagnose}: exercises every OS primitive the check modules depend on
 * and reports PASS / FAIL per primitive. Modules are deliberately best-effort
 * (a broken API yields "no findings", never a crash), so without this a broken
 * Windows code path would look exactly like a clean PC. This is the executable
 * form of the Windows integration checklist.
 */
public final class Diagnostics {

    public static final int EXIT_OK = 0;
    public static final int EXIT_FAILED = 4;

    private Diagnostics() {
    }

    public static int run(EnvironmentInfo env, Path outDir, PrintStream out) throws Exception {
        out.println("Moon Checker " + env.appVersion() + " diagnostics | " + env.osName()
                + " | elevated=" + env.elevated() + " | " + env.jvm());
        List<Probe> probes = Platform.isWindows() ? WindowsProbes.all(env, out)
                : Platform.isLinux() ? LinuxProbes.all(env) : List.of();
        print(probes, out);
        Files.createDirectories(outDir);
        Path json = outDir.resolve("moon-diagnostics.json");
        Files.writeString(json, toJson(env, probes));
        out.println("written: " + json.toAbsolutePath());
        return exitCode(probes);
    }

    static int exitCode(List<Probe> probes) {
        return probes.stream().anyMatch(p -> p.status() == Probe.Status.FAIL) ? EXIT_FAILED : EXIT_OK;
    }

    static void print(List<Probe> probes, PrintStream out) {
        int pass = 0;
        int fail = 0;
        for (Probe p : probes) {
            out.printf("[%-4s] %-22s %6d ms  %s%n", p.status(), p.id(), p.millis(), p.detail());
            if (p.status() == Probe.Status.PASS) {
                pass++;
            } else if (p.status() == Probe.Status.FAIL) {
                fail++;
            }
        }
        out.println("summary: " + pass + " passed, " + fail + " failed, " + probes.size() + " total");
    }

    static String toJson(EnvironmentInfo env, List<Probe> probes) throws Exception {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema", "moon-diagnostics/1");
        root.put("appVersion", env.appVersion());
        root.put("os", env.osName());
        root.put("osVersion", System.getProperty("os.version"));
        root.put("elevated", env.elevated());
        root.put("jvm", env.jvm());
        List<Map<String, Object>> list = new ArrayList<>();
        for (Probe p : probes) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", p.id());
            m.put("status", p.status().name());
            m.put("detail", p.detail());
            m.put("millis", p.millis());
            list.add(m);
        }
        root.put("probes", list);
        return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(root);
    }
}

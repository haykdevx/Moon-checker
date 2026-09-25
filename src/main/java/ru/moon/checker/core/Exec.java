package ru.moon.checker.core;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs an external command with a hard timeout and a known output encoding.
 *
 * <p>Why not {@code new String(p.getInputStream().readAllBytes())}: that read
 * blocks until the child exits, so a {@code waitFor(timeout)} placed after it
 * never fires on a hung {@code powershell}/{@code reg} call, and decoding with
 * the JVM default charset garbles Cyrillic output on Russian Windows, where
 * console tools write in the OEM code page (cp866). Here output is drained on a
 * separate thread, the child is killed when the budget runs out (or the calling
 * module thread is interrupted by the engine watchdog), and PowerShell is forced
 * to emit UTF-8.
 */
public final class Exec {

    /** Upper bound on captured output so a runaway child cannot exhaust the heap. */
    static final int MAX_OUTPUT = 8 * 1024 * 1024;

    private Exec() {
    }

    /**
     * Outcome of a command.
     *
     * @param exitCode exit status, or -1 if it did not start / was killed
     * @param output   combined stdout+stderr
     * @param timedOut true if the command was killed for exceeding its budget
     * @param error    why it could not be started, or null
     */
    public record Result(int exitCode, String output, boolean timedOut, String error) {
        public boolean ok() {
            return exitCode == 0 && !timedOut && error == null;
        }
    }

    public static Result run(List<String> command, Duration timeout) {
        return run(command, timeout, StandardCharsets.UTF_8);
    }

    public static Result run(List<String> command, Duration timeout, Charset charset) {
        Process p;
        try {
            p = new ProcessBuilder(command).redirectErrorStream(true).start();
        } catch (Exception e) {
            return new Result(-1, "", false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Thread drain = new Thread(() -> copyBounded(p.getInputStream(), buf), "moon-exec-drain");
        drain.setDaemon(true);
        drain.start();
        boolean finished;
        try {
            finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            return new Result(-1, snapshot(buf, charset), true, "interrupted");
        }
        if (!finished) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
        }
        try {
            drain.join(2_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return new Result(finished ? p.exitValue() : -1, snapshot(buf, charset), !finished, null);
    }

    /**
     * Runs a PowerShell script. The script is passed via {@code -EncodedCommand}
     * (base64 UTF-16LE) so no quoting survives Java's Windows argument escaping,
     * and it is prefixed to switch the console output encoding to UTF-8.
     */
    public static Result powershell(String script, Duration timeout) {
        List<String> cmd = new ArrayList<>(List.of("powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowershell(script)));
        return run(cmd, timeout, StandardCharsets.UTF_8);
    }

    /** The {@code -EncodedCommand} payload for a script (UTF-8 console prelude included). */
    static String encodePowershell(String script) {
        String full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
                + "$OutputEncoding=[System.Text.Encoding]::UTF8;"
                + "$ProgressPreference='SilentlyContinue';"
                + script;
        return Base64.getEncoder().encodeToString(full.getBytes(StandardCharsets.UTF_16LE));
    }

    private static void copyBounded(InputStream in, ByteArrayOutputStream out) {
        byte[] chunk = new byte[8192];
        try (in) {
            int n;
            while ((n = in.read(chunk)) > 0) {
                synchronized (out) {
                    if (out.size() < MAX_OUTPUT) {
                        out.write(chunk, 0, Math.min(n, MAX_OUTPUT - out.size()));
                    }
                }
            }
        } catch (Exception ignored) {
            // stream closed when the child was killed
        }
    }

    private static String snapshot(ByteArrayOutputStream buf, Charset charset) {
        synchronized (buf) {
            return buf.toString(charset);
        }
    }
}

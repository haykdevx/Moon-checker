package ru.moon.checker.win;

import com.sun.jna.Native;
import com.sun.jna.win32.StdCallLibrary;
import ru.moon.checker.core.Log;
import ru.moon.checker.core.Platform;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs a Windows command with a real time limit and decodes its output correctly.
 *
 * <p>Two things went wrong with plain {@code ProcessBuilder} on players' PCs:
 * <ul>
 *   <li>{@code readAllBytes()} blocks until the process exits, so a {@code waitFor}
 *       timeout after it never fires — a hung PowerShell (antivirus scanning it,
 *       a broken module) froze the collector until its whole budget ran out;</li>
 *   <li>Java 21 decodes as UTF-8, but console programs write in the OEM code page
 *       (866 on Russian Windows): Cyrillic paths and names came out garbled.</li>
 * </ul>
 * PowerShell is told to write UTF-8; native tools are read in the OEM code page.
 */
public final class WinCommand {

    /** What a command produced; {@code timedOut} when it was killed at the limit. */
    public record Result(int exitCode, String output, boolean timedOut) {
        public boolean ok() {
            return !timedOut && exitCode == 0;
        }

        static Result failed() {
            return new Result(-1, "", false);
        }
    }

    private static final int MAX_OUTPUT = 8 * 1024 * 1024;

    /** The one kernel32 call JNA's platform binding lacks. */
    private interface CodePages extends StdCallLibrary {
        int GetOEMCP();
    }

    private WinCommand() {
    }

    /** A native console tool (reg, esentutl, bcdedit…), output in the OEM code page. */
    public static Result run(long timeoutSeconds, String... command) {
        return exec(List.of(command), oemCharset(), timeoutSeconds);
    }

    /** A PowerShell script whose output is UTF-8 whatever the console code page. */
    public static Result powershell(long timeoutSeconds, String script) {
        List<String> cmd = new ArrayList<>(List.of("powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", utf8Prelude() + script));
        return exec(cmd, StandardCharsets.UTF_8, timeoutSeconds);
    }

    /** Prepended to every script: UTF-8 output, errors do not become interactive prompts. */
    static String utf8Prelude() {
        return "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; "
                + "$ProgressPreference='SilentlyContinue'; ";
    }

    private static Result exec(List<String> command, Charset charset, long timeoutSeconds) {
        if (!Platform.isWindows()) {
            return Result.failed();
        }
        Process p;
        try {
            p = new ProcessBuilder(command).redirectErrorStream(true).start();
        } catch (IOException e) {
            Log.warn("could not start " + command.get(0), e);
            return Result.failed();
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread reader = Thread.ofVirtual().start(() -> drain(p.getInputStream(), out));
        boolean finished;
        try {
            finished = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            return new Result(-1, decode(out, charset), true);
        }
        if (!finished) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
        }
        try {
            reader.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return new Result(finished ? p.exitValue() : -1, decode(out, charset), !finished);
    }

    private static void drain(InputStream in, ByteArrayOutputStream out) {
        byte[] buf = new byte[8192];
        try (in) {
            int n;
            while ((n = in.read(buf)) > 0) {
                synchronized (out) {
                    if (out.size() < MAX_OUTPUT) {
                        out.write(buf, 0, Math.min(n, MAX_OUTPUT - out.size()));
                    }
                }
            }
        } catch (IOException ignored) {
            // the process was killed or closed its output
        }
    }

    private static String decode(ByteArrayOutputStream out, Charset charset) {
        synchronized (out) {
            return new String(out.toByteArray(), charset);
        }
    }

    /** The console (OEM) code page of this PC — 866 on Russian Windows, 437 on US English. */
    static Charset oemCharset() {
        try {
            return charsetForCodePage(Native.load("kernel32", CodePages.class).GetOEMCP());
        } catch (Throwable t) {
            return StandardCharsets.UTF_8;
        }
    }

    static Charset charsetForCodePage(int codePage) {
        if (codePage == 65001) {
            return StandardCharsets.UTF_8;
        }
        for (String name : new String[]{"IBM" + codePage, "cp" + codePage, "x-IBM" + codePage, "windows-" + codePage}) {
            try {
                return Charset.forName(name);
            } catch (Exception ignored) {
                // try the next spelling
            }
        }
        return StandardCharsets.UTF_8;
    }
}

package ru.moon.checker.core;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Minimal thread-safe logger. Writes to stderr and to a per-day log file under
 * {@code %LOCALAPPDATA%\MoonCheck\logs} (or the user home as a fallback), so a
 * failed check can be diagnosed after the fact without a debugger attached.
 */
public final class Log {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final Object LOCK = new Object();
    private static volatile Path logFile;
    private static volatile boolean initialised;

    private Log() {
    }

    private static Path resolveLogFile() {
        String base = System.getenv("LOCALAPPDATA");
        Path dir;
        if (base != null && !base.isBlank()) {
            dir = Path.of(base, "MoonCheck", "logs");
        } else {
            dir = Path.of(System.getProperty("user.home", "."), ".moon-check", "logs");
        }
        try {
            Files.createDirectories(dir);
        } catch (Exception ignored) {
            return null;
        }
        return dir.resolve("moon-" + LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE) + ".log");
    }

    private static void ensureInit() {
        if (!initialised) {
            synchronized (LOCK) {
                if (!initialised) {
                    logFile = resolveLogFile();
                    initialised = true;
                }
            }
        }
    }

    public static void info(String msg) {
        write("INFO", msg, null);
    }

    public static void warn(String msg) {
        write("WARN", msg, null);
    }

    public static void warn(String msg, Throwable t) {
        write("WARN", msg, t);
    }

    public static void error(String msg, Throwable t) {
        write("ERROR", msg, t);
    }

    public static Path logFile() {
        ensureInit();
        return logFile;
    }

    private static void write(String level, String msg, Throwable t) {
        ensureInit();
        String line = LocalDateTime.now().format(TS) + " [" + level + "] " + msg;
        System.err.println(line);
        StringBuilder sb = new StringBuilder(line).append(System.lineSeparator());
        if (t != null) {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            sb.append(sw).append(System.lineSeparator());
        }
        Path f = logFile;
        if (f == null) {
            return;
        }
        synchronized (LOCK) {
            try {
                Files.writeString(f, sb.toString(), StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (Exception ignored) {
                // never let logging break the app
            }
        }
    }
}

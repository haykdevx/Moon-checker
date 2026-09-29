package ru.moon.checker.win;

import ru.moon.checker.core.Platform;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Authenticode signature check for a Windows binary.
 *
 * <p>Used only to <em>suppress</em> heuristic findings on properly signed
 * vendor binaries (Microsoft, Valve, NVIDIA...), never to clear an exact
 * cheat-name or hash match — cheats are signed sometimes too.
 *
 * <p>Implemented with {@code Get-AuthenticodeSignature} rather than a hand-rolled
 * {@code WinVerifyTrust} JNA mapping: the nested WINTRUST_DATA structures are
 * easy to get subtly wrong and a mismatch crashes the JVM natively, which is a
 * bad trade for a tool that must not fall over on a player's PC. Calls are
 * cached per path and capped per run, and only happen when a heuristic finding
 * is about to fire.
 */
public final class Authenticode {

    private static final int MAX_LOOKUPS = 80;
    private static final Map<String, Result> CACHE = new ConcurrentHashMap<>();
    private static final AtomicInteger LOOKUPS = new AtomicInteger();

    private Authenticode() {
    }

    /**
     * @param status Authenticode status ("Valid", "NotSigned", "HashMismatch"...)
     * @param signer certificate subject, lower-cased; empty when unsigned
     */
    public record Result(String status, String signer) {
        public boolean valid() {
            return "valid".equalsIgnoreCase(status);
        }

        static Result unknown() {
            return new Result("Unknown", "");
        }
    }

    public static Result verify(Path file) {
        if (!Platform.isWindows() || file == null) {
            return Result.unknown();
        }
        String key = file.toString();
        Result cached = CACHE.get(key);
        if (cached != null) {
            return cached;
        }
        if (LOOKUPS.incrementAndGet() > MAX_LOOKUPS) {
            return Result.unknown();
        }
        Result result = Result.unknown();
        try {
            String escaped = key.replace("'", "''");
            WinCommand.Result r = WinCommand.powershell(20,
                    "$s = Get-AuthenticodeSignature -LiteralPath '" + escaped + "'; "
                            + "[string]$s.Status; [string]$s.SignerCertificate.Subject");
            if (r.timedOut() || r.exitCode() < 0) {
                return Result.unknown();
            }
            String[] lines = r.output().split("\\R");
            String status = lines.length > 0 ? lines[0].trim() : "Unknown";
            String signer = lines.length > 1 ? lines[1].trim().toLowerCase(Locale.ROOT) : "";
            result = new Result(status, signer);
        } catch (Throwable t) {
            result = Result.unknown();
        }
        CACHE.put(key, result);
        return result;
    }

    /** Reset caches (tests). */
    static void reset() {
        CACHE.clear();
        LOOKUPS.set(0);
    }
}

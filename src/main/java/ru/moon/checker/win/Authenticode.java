package ru.moon.checker.win;

import ru.moon.checker.core.Platform;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Authenticode signature of a Windows binary: status, signer and the root its chain ends in.
 *
 * <p>Used only to decide whether a <em>heuristic</em> finding needs a reviewer — never to
 * clear an exact cheat-name or hash match (cheats are signed sometimes too). A signature
 * counts as an identity only together with {@link ru.moon.checker.signatures.SignatureDb#isTrustedIdentity}:
 * status {@code Valid}, the chain ending in a pinned public root (a root the player added
 * to their own store does not count) and the signer's CN or O equal to an allowed vendor.
 *
 * <p>What this cannot rule out: Windows answers these questions, and an administrator —
 * the player — can change how Windows answers (a kernel driver, a patched system DLL). A
 * verified signature is evidence about the file, not about the PC.
 *
 * <p>Implemented with {@code Get-AuthenticodeSignature} rather than a hand-rolled
 * {@code WinVerifyTrust} JNA mapping: the nested WINTRUST_DATA structures are easy to get
 * subtly wrong and a mismatch crashes the JVM natively. Calls are cached per path and
 * capped per run; {@link #verifyAll} checks many files in one PowerShell start.
 */
public final class Authenticode {

    private static final int MAX_LOOKUPS = 1500;
    private static final int BATCH = 40;   // keeps the encoded command line far below Windows' 32 767 characters
    private static final Map<String, Result> CACHE = new ConcurrentHashMap<>();
    private static final AtomicInteger LOOKUPS = new AtomicInteger();

    private Authenticode() {
    }

    /**
     * @param status  Authenticode status ("Valid", "NotSigned", "HashMismatch", "NotTrusted", "UnknownError", "Unknown")
     * @param subject signer certificate subject as Windows prints it; empty when unsigned
     * @param rootSha1 SHA-1 thumbprint of the chain's root, upper-case hex; empty when unknown
     */
    public record Result(String status, String subject, String rootSha1) {
        public boolean valid() {
            return "valid".equalsIgnoreCase(status);
        }

        /** Signed, but the file was changed after signing. */
        public boolean broken() {
            return "hashmismatch".equalsIgnoreCase(status);
        }

        public boolean unknown() {
            return status == null || status.isBlank() || "unknown".equalsIgnoreCase(status)
                    || "unknownerror".equalsIgnoreCase(status);
        }

        /** The signer's CN and O values, lower-case, trailing dots and repeated spaces removed. */
        public List<String> signerNames() {
            return names(subject);
        }

        public static Result unknown(String why) {
            return new Result("Unknown", "", "");
        }
    }

    /** CN and O of a distinguished name such as {@code CN=Valve Corp., O="Valve, Inc.", C=US}. */
    public static List<String> names(String dn) {
        List<String> out = new ArrayList<>();
        if (dn == null) {
            return out;
        }
        for (String rdn : splitRdns(dn)) {
            int eq = rdn.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = rdn.substring(0, eq).trim().toUpperCase(Locale.ROOT);
            if (key.equals("CN") || key.equals("O")) {
                String v = rdn.substring(eq + 1).trim();
                if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1).replace("\"\"", "\"");
                }
                out.add(normalizeName(v));
            }
        }
        return out;
    }

    /** "Valve Corp." → "valve corp"; used on both sides of the comparison. */
    public static String normalizeName(String v) {
        String s = v == null ? "" : v.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1).trim();
        }
        return s;
    }

    private static List<String> splitRdns(String dn) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < dn.length(); i++) {
            char c = dn.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            }
            if (c == ',' && !quoted) {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        return parts;
    }

    public static Result verify(Path file) {
        if (!Platform.isWindows() || file == null) {
            return Result.unknown("not windows");
        }
        Result cached = CACHE.get(file.toString());
        if (cached != null) {
            return cached;
        }
        return verifyAll(List.of(file)).getOrDefault(file.toString(), Result.unknown("not checked"));
    }

    /** Checks several files with as few PowerShell starts as possible; results are cached per path. */
    public static Map<String, Result> verifyAll(Collection<Path> files) {
        Map<String, Result> out = new LinkedHashMap<>();
        if (!Platform.isWindows() || files == null) {
            return out;
        }
        List<String> todo = new ArrayList<>();
        for (Path f : files) {
            String key = f.toString();
            Result cached = CACHE.get(key);
            if (cached != null) {
                out.put(key, cached);
            } else if (!todo.contains(key)) {
                todo.add(key);
            }
        }
        for (int i = 0; i < todo.size(); i += BATCH) {
            List<String> batch = todo.subList(i, Math.min(todo.size(), i + BATCH));
            if (LOOKUPS.addAndGet(batch.size()) > MAX_LOOKUPS) {
                batch.forEach(k -> out.put(k, Result.unknown("lookup budget")));
                continue;
            }
            Map<String, Result> got = runBatch(batch);
            for (String k : batch) {
                Result r = got.getOrDefault(k, Result.unknown("no answer"));
                CACHE.put(k, r);
                out.put(k, r);
            }
        }
        return out;
    }

    private static Map<String, Result> runBatch(List<String> paths) {
        StringBuilder script = new StringBuilder("$p = @(");
        for (int i = 0; i < paths.size(); i++) {
            script.append(i > 0 ? "," : "").append('\'').append(paths.get(i).replace("'", "''")).append('\'');
        }
        // one tab-separated line per file: index, status, root thumbprint, subject (subject last: it has commas)
        script.append("); for ($i = 0; $i -lt $p.Count; $i++) { try { "
                + "$s = Get-AuthenticodeSignature -LiteralPath $p[$i]; $root = ''; "
                + "if ($s.SignerCertificate) { $c = New-Object Security.Cryptography.X509Certificates.X509Chain; "
                + "$c.ChainPolicy.RevocationMode = 'NoCheck'; [void]$c.Build($s.SignerCertificate); "
                + "if ($c.ChainElements.Count -gt 0) { $root = $c.ChainElements[$c.ChainElements.Count - 1].Certificate.Thumbprint } } "
                + "\"$i`t$($s.Status)`t$root`t$($s.SignerCertificate.Subject)\" } catch { \"$i`tUnknown`t`t\" } }");
        Map<String, Result> out = new LinkedHashMap<>();
        try {
            WinCommand.Result r = WinCommand.powershell(20 + paths.size(), script.toString());
            if (r.timedOut() || r.exitCode() < 0) {
                return out;
            }
            for (String line : r.output().split("\\R")) {
                Result parsed = parseLine(line);
                int idx = index(line);
                if (parsed != null && idx >= 0 && idx < paths.size()) {
                    out.put(paths.get(idx), parsed);
                }
            }
        } catch (Throwable t) {
            // unknown for all: the findings stay visible
        }
        return out;
    }

    static int index(String line) {
        int tab = line.indexOf('\t');
        try {
            return tab > 0 ? Integer.parseInt(line.substring(0, tab).trim()) : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** "3\tValid\tABCD…\tCN=…, O=…" → Result; null for a line that is not ours. */
    public static Result parseLine(String line) {
        String[] f = line.split("\t", 4);
        if (f.length < 3 || index(line) < 0) {
            return null;
        }
        return new Result(f[1].trim(), f.length > 3 ? f[3].trim() : "", f[2].trim().toUpperCase(Locale.ROOT));
    }

    /** Reset caches (tests). */
    static void reset() {
        CACHE.clear();
        LOOKUPS.set(0);
    }
}

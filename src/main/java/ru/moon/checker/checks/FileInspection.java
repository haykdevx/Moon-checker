package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Hashing;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.BinStrings;
import ru.moon.checker.parse.Pe;
import ru.moon.checker.signatures.SignatureRule;
import ru.moon.checker.win.AlternateStreams;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Shared logic for inspecting a candidate binary and walking user-writable
 * directories. Kept out of the individual modules so the file-scan and
 * execution-trace checks can reuse it.
 */
public final class FileInspection {

    /** Extensions worth a deep inspection. */
    private static final String[] BINARY_EXT = {".exe", ".dll", ".sys", ".bin", ".dat", ".scr"};
    private static final long STRING_SCAN_MAX = 48L * 1024 * 1024;  // 48 MiB deep-scan cap
    private static final long HASH_MAX = 512L * 1024 * 1024;        // 512 MiB hashing cap
    private static final int MIN_STRING = 4;
    private static final int OFFSET_HIT_HIGH = 3;   // this many offset names => strong
    private static final double PACKED_ENTROPY = 7.2; // near-8.0 => packed/encrypted

    /** Stream enumeration; replaced in tests (the real API only exists on Windows). */
    static volatile Function<String, List<AlternateStreams.Stream>> streamLister = AlternateStreams::list;

    private FileInspection() {
    }

    public static boolean isBinaryName(String name) {
        String l = name.toLowerCase(Locale.ROOT);
        for (String e : BINARY_EXT) {
            if (l.endsWith(e)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isSuspiciousLocation(String pathLower) {
        return pathLower.contains("\\temp\\")
                || pathLower.contains("\\downloads\\")
                || pathLower.contains("\\appdata\\local\\temp")
                || pathLower.contains("\\users\\public\\")
                || pathLower.contains("\\$recycle.bin\\")
                || pathLower.contains("\\programdata\\")
                || pathLower.matches(".*\\\\[a-z]:\\\\[^\\\\]+\\.(exe|dll)$"); // loose "in drive root"
    }

    /**
     * Inspect one file: signature name match, hash match, embedded CS2 offset
     * strings, and injector-style imports. Emits findings via the context.
     */
    public static void inspect(Path file, ScanContext ctx, String module, Category category) {
        String name = file.getFileName().toString();
        String nameLower = name.toLowerCase(Locale.ROOT);
        String pathStr = file.toString();
        String pathLower = pathStr.toLowerCase(Locale.ROOT);

        // 1. filename against cheat-name rules
        ctx.signatures().matchCheatName(nameLower).ifPresent(rule ->
                ctx.emit(Finding.builder(category, rule.severity(),
                                "Файл совпал с сигнатурой чита / Cheat-signature file")
                        .module(module)
                        .detail(rule.label())
                        .evidence(pathStr)
                        .source("filename")
                        .openPath(parent(file))
                        .build()));

        // 2. hidden Alternate Data Streams — a classic cheat-payload hiding spot.
        //    Checked before the size gate: `type cheat.dll > notes.txt:x` leaves a
        //    0-byte host file whose only content is the hidden stream.
        for (AlternateStreams.Stream st : streamLister.apply(pathStr)) {
            var streamRule = ctx.signatures().matchCheatName(st.name());
            Severity sev = streamRule.isPresent() ? Severity.CRITICAL : Severity.HIGH;
            ctx.emit(Finding.builder(category, sev,
                            "Скрытый поток данных (ADS) / Hidden alternate data stream")
                    .module(module)
                    .detail("Stream \"" + st.name() + "\" (" + st.size() + " bytes)"
                            + streamRule.map(r -> " — " + r.label()).orElse(""))
                    .evidence(pathStr + ":" + st.name())
                    .source("NTFS ADS")
                    .openPath(parent(file))
                    .build());
        }

        long size;
        try {
            size = Files.size(file);
        } catch (IOException e) {
            return;
        }
        if (size <= 0) {
            return;
        }

        // 3. executable disguised under a non-executable extension (MZ header)
        boolean binaryExt = isBinaryName(nameLower);
        boolean disguised = !binaryExt && peekMz(file);
        if (disguised) {
            ctx.emit(Finding.builder(category, Severity.HIGH,
                            "Исполняемый файл под чужим расширением / Executable disguised by extension")
                    .module(module)
                    .detail("PE (MZ) content with a non-executable extension")
                    .evidence(pathStr)
                    .source("content vs extension")
                    .openPath(parent(file))
                    .build());
        }

        // 4. exact hash match (streamed) — for binaries, disguised PEs, or when
        //    the signature DB actually contains hashes (to catch renamed cheats)
        boolean hashAll = !ctx.signatures().hashes().isEmpty();
        if ((binaryExt || disguised || hashAll) && size <= HASH_MAX) {
            String hash = Hashing.sha256File(file);
            if (hash != null) {
                final String h = hash;
                ctx.signatures().matchHash(hash).ifPresent(rule ->
                        ctx.emit(Finding.builder(category, Severity.CRITICAL,
                                        "Точное совпадение хеша чит-файла / Known cheat file hash")
                                .module(module)
                                .detail(rule.label() + "  [sha256=" + h.substring(0, 16) + "…]")
                                .evidence(pathStr)
                                .source("sha256")
                                .openPath(parent(file))
                                .build()));
            }
        }

        // 5. deep content scan for reasonably-sized binaries (or disguised PEs)
        if (size > STRING_SCAN_MAX || !(binaryExt || disguised)) {
            return;
        }
        byte[] data;
        try {
            data = Files.readAllBytes(file);
        } catch (IOException | OutOfMemoryError e) {
            return;
        }

        List<String> strings = BinStrings.all(data, MIN_STRING);
        int offsetHits = 0;
        StringBuilder matched = new StringBuilder();
        java.util.Set<String> seen = new java.util.LinkedHashSet<>();
        for (String s : strings) {
            for (SignatureRule r : ctx.signatures().allOffsetMatches(s)) {
                if (seen.add(r.label())) {
                    offsetHits++;
                    if (matched.length() < 200) {
                        matched.append(r.label()).append(", ");
                    }
                }
            }
        }
        if (offsetHits > 0) {
            Severity sev = offsetHits >= OFFSET_HIT_HIGH ? Severity.HIGH : Severity.MEDIUM;
            ctx.emit(Finding.builder(category, sev,
                            "Строки оффсетов CS2 в бинарнике / CS2 offset strings in binary")
                    .module(module)
                    .detail(offsetHits + " match(es): " + trimTail(matched.toString()))
                    .evidence(pathStr)
                    .source("binary strings")
                    .openPath(parent(file))
                    .weight(sev == Severity.HIGH ? 40 : 12)
                    .build());
        }

        Pe pe = Pe.parse(data);
        if (pe.isPe() && pe.looksLikeInjector()) {
            boolean suspicious = isSuspiciousLocation(pathLower) || !pe.signed();
            Severity sev = suspicious ? Severity.HIGH : Severity.LOW;
            ctx.emit(Finding.builder(category, sev,
                            "Импорт функций инъекции в процесс / Process-injection imports")
                    .module(module)
                    .detail("Imports remote-injection APIs" + (pe.signed() ? "" : ", unsigned")
                            + (isSuspiciousLocation(pathLower) ? ", suspicious location" : ""))
                    .evidence(pathStr)
                    .source("PE imports")
                    .openPath(parent(file))
                    .build());
        }

        // 6. packed / encrypted binary sitting in a user-writable location
        if (isSuspiciousLocation(pathLower)) {
            double entropy = ru.moon.checker.parse.Entropy.shannon(data);
            if (entropy >= PACKED_ENTROPY) {
                ctx.emit(Finding.builder(category, Severity.LOW,
                                "Упакованный/зашифрованный бинарник / Packed or encrypted binary")
                        .module(module)
                        .detail(String.format(Locale.ROOT, "entropy %.2f/8.0 in a user-writable location", entropy))
                        .evidence(pathStr)
                        .source("entropy")
                        .openPath(parent(file))
                        .weight(6)
                        .build());
            }
        }
    }

    private static boolean peekMz(Path file) {
        try (var in = Files.newInputStream(file)) {
            return in.read() == 'M' && in.read() == 'Z';
        } catch (Exception e) {
            return false;
        }
    }

    /** Walk a directory tree (bounded) invoking {@code onFile} for each file. */
    public static int walk(Path root, int maxFiles, int maxDepth, Consumer<Path> onFile, ScanContext ctx) {
        if (root == null || !Files.isDirectory(root)) {
            return 0;
        }
        final int[] count = {0};
        try {
            Files.walkFileTree(root, java.util.EnumSet.noneOf(java.nio.file.FileVisitOption.class),
                    maxDepth, new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) {
                            if (ctx.isCancelled() || count[0] >= maxFiles) {
                                return FileVisitResult.TERMINATE;
                            }
                            if (attrs.isRegularFile()) {
                                onFile.accept(f);
                                count[0]++;
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed(Path f, IOException exc) {
                            return FileVisitResult.CONTINUE; // skip unreadable
                        }
                    });
        } catch (IOException e) {
            // best-effort
        }
        return count[0];
    }

    private static String parent(Path p) {
        Path parent = p.getParent();
        return parent != null ? parent.toString() : p.toString();
    }

    private static String trimTail(String s) {
        String t = s.strip();
        if (t.endsWith(",")) {
            t = t.substring(0, t.length() - 1);
        }
        return t;
    }
}

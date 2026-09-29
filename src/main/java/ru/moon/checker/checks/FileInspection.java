package ru.moon.checker.checks;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Hashing;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.parse.BinStrings;
import ru.moon.checker.parse.Pe;
import ru.moon.checker.signatures.SignatureRule;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * Shared logic for inspecting a candidate binary and walking user-writable
 * directories. Kept out of the individual modules so the file-scan and
 * execution-trace checks can reuse it.
 */
public final class FileInspection {

    /**
     * Extensions that are legitimately PE/binary on Windows. These are deep
     * scanned but never reported as "disguised" — System32 is full of .cpl,
     * .drv, .ocx, .ax and .tlb files that are perfectly normal PE images.
     */
    private static final String[] BINARY_EXT = {
            ".exe", ".dll", ".sys", ".bin", ".dat", ".scr", ".com",
            ".cpl", ".drv", ".ocx", ".ax", ".tlb", ".acm", ".msstyles",
            ".node", ".efi", ".mui", ".so", ".elf"
    };

    /**
     * Document / media / archive extensions. A PE header under one of THESE is
     * genuinely suspicious (a cheat renamed to {@code screenshot.png}).
     */
    private static final String[] NON_EXECUTABLE_EXT = {
            ".txt", ".log", ".ini", ".cfg", ".conf", ".json", ".xml", ".csv", ".md",
            ".html", ".htm", ".rtf", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".ppt", ".pptx", ".odt", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".webp", ".ico", ".svg", ".mp3", ".mp4", ".avi", ".mkv", ".mov",
            ".wav", ".flac", ".ogg", ".zip", ".rar", ".7z", ".tar", ".gz",
            ".iso", ".vdf", ".lua", ".py", ".js", ".css"
    };
    private static final long STRING_SCAN_MAX = 48L * 1024 * 1024;  // 48 MiB deep-scan cap
    private static final long HASH_MAX = 512L * 1024 * 1024;        // 512 MiB hashing cap
    private static final int MIN_STRING = 4;
    private static final int OFFSET_HIT_HIGH = 3;   // this many offset names => strong
    private static final double PACKED_ENTROPY = 7.2; // near-8.0 => packed/encrypted

    private FileInspection() {
    }

    public static boolean isBinaryName(String name) {
        return endsWithAny(name.toLowerCase(Locale.ROOT), BINARY_EXT);
    }

    /** True for document/media/archive extensions that should never be a PE. */
    public static boolean isNonExecutableName(String name) {
        return endsWithAny(name.toLowerCase(Locale.ROOT), NON_EXECUTABLE_EXT);
    }

    private static boolean endsWithAny(String lower, String[] exts) {
        for (String e : exts) {
            if (lower.endsWith(e)) {
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

        long size;
        try {
            size = Files.size(file);
        } catch (IOException e) {
            return;
        }
        if (size <= 0) {
            return;
        }
        if (isCloudPlaceholder(file)) {
            return; // OneDrive "files on demand": reading it would download it; the name was matched above
        }

        // Trusted location? Heuristics (ADS, disguise, offsets, imports, entropy)
        // are suppressed for OS/Steam/vendor paths; exact name and hash matches
        // above and below are never suppressed.
        boolean trustedPath = ctx.signatures().isAllowedPath(pathLower);

        // 2. hidden Alternate Data Streams — a classic cheat-payload hiding spot
        for (ru.moon.checker.win.AlternateStreams.Stream st : ru.moon.checker.win.AlternateStreams.list(pathStr)) {
            var streamRule = ctx.signatures().matchCheatName(st.name());
            if (trustedPath && streamRule.isEmpty()) {
                continue; // Windows itself uses streams on system files
            }
            // a cheat-named stream is critical; a stream big enough to hold a program is high;
            // a small unknown stream (notes, tags some software writes) is context for the reviewer
            Severity sev = streamRule.isPresent() ? Severity.CRITICAL
                    : st.size() >= ru.moon.checker.win.AlternateStreams.PAYLOAD_BYTES ? Severity.HIGH : Severity.LOW;
            ctx.emit(Finding.builder(category, sev,
                            "Скрытый поток данных (ADS) / Hidden alternate data stream")
                    .module(module).rule("files:alternate-data-stream")
                    .detail("Stream \"" + st.name() + "\" (" + st.size() + " bytes)"
                            + streamRule.map(r -> " — " + r.label()).orElse(""))
                    .evidence(pathStr + ":" + st.name())
                    .source("NTFS ADS")
                    .openPath(parent(file))
                    .build());
        }

        // 3. executable disguised under a document/media extension (MZ header).
        //    Only probe files whose extension isn't already a known binary one,
        //    and only raise the finding for genuinely non-executable extensions —
        //    .cpl/.drv/.ocx/.tlb etc. are legitimately PE images.
        boolean binaryExt = isBinaryName(nameLower);
        boolean mz = !binaryExt && peekMz(file);
        boolean disguised = mz && isNonExecutableName(nameLower) && !trustedPath;
        if (disguised) {
            ctx.emit(Finding.builder(category, Severity.HIGH,
                            "Исполняемый файл под чужим расширением / Executable disguised by extension")
                    .module(module)
                    .detail("PE (MZ) content with a non-executable extension")
                    .evidence(pathStr)
                    .source("content vs extension · heuristic")
                    .openPath(parent(file))
                    .build());
        }

        // 4. exact hash match (streamed) — for binaries, disguised PEs, or when
        //    the signature DB actually contains hashes (to catch renamed cheats)
        boolean hashAll = !ctx.signatures().hashes().isEmpty();
        // hashing a big binary costs seconds: only when a hash rule or allowlisted hash can use it
        boolean hashUseful = hashAll || !ctx.signatures().allowHashes().isEmpty();
        String fileHash = null;
        if (hashUseful && (binaryExt || mz || hashAll) && size <= HASH_MAX) {
            String hash = Hashing.sha256File(file);
            fileHash = hash;
            if (hash != null) {
                final String h = hash;
                ctx.signatures().matchHash(hash).ifPresent(rule ->
                        ctx.emit(Finding.builder(category, Severity.CRITICAL,
                                        "Точное совпадение хеша чит-файла / Known cheat file hash")
                                .kind(EvidenceKind.DETECTION).rule("files:known-cheat-hash")
                                .module(module)
                                .detail(rule.label() + "  [sha256=" + h.substring(0, 16) + "…]")
                                .evidence(pathStr)
                                .source("sha256")
                                .openPath(parent(file))
                                .build()));
            }
        }

        // 5. deep content scan for reasonably-sized binaries (or disguised PEs)
        if (size > STRING_SCAN_MAX || !(binaryExt || mz)) {
            return;
        }
        byte[] data;
        try {
            data = Files.readAllBytes(file);
        } catch (IOException | OutOfMemoryError e) {
            return;
        }

        if (trustedPath) {
            return; // exact name/hash matches already reported above
        }
        // Heuristics are computed first; the signature check (a PowerShell start, about a second
        // on a player's PC) runs only when one of them would fire — not for every binary.
        List<Finding> heuristic = new java.util.ArrayList<>();

        List<String> strings = BinStrings.all(data, MIN_STRING);
        int offsetHits = 0;
        boolean dumpName = false;
        StringBuilder matched = new StringBuilder();
        java.util.Set<String> seen = new java.util.LinkedHashSet<>();
        for (String s : strings) {
            for (SignatureRule r : ctx.signatures().allOffsetMatches(s)) {
                if (seen.add(r.label())) {
                    offsetHits++;
                    dumpName |= r.severity().rank() >= Severity.HIGH.rank();
                    if (matched.length() < 200) {
                        matched.append(r.label()).append(", ");
                    }
                }
            }
        }
        if (offsetHits > 0) {
            // One game field name alone is common in legitimate Source-engine tools (demo and movie
            // tools, server plugins, SDK code): it is shown as LOW and does not ask for a review.
            Severity sev = offsetSeverity(offsetHits, dumpName);
            heuristic.add(Finding.builder(category, sev,
                            "Строки оффсетов CS2 в бинарнике / CS2 offset strings in binary")
                    .module(module)
                    .detail(offsetHits + " match(es): " + trimTail(matched.toString()))
                    .evidence(pathStr)
                    .source("binary strings · heuristic")
                    .openPath(parent(file))
                    .build());
        }

        Pe pe = Pe.parse(data);
        if (pe.isPe() && pe.looksLikeInjector()) {
            boolean suspicious = isSuspiciousLocation(pathLower) || !pe.signed();
            Severity sev = suspicious ? Severity.HIGH : Severity.LOW;
            heuristic.add(Finding.builder(category, sev,
                            "Импорт функций инъекции в процесс / Process-injection imports")
                    .module(module)
                    .detail("Imports remote-injection APIs" + (pe.signed() ? "" : ", unsigned")
                            + (isSuspiciousLocation(pathLower) ? ", suspicious location" : ""))
                    .evidence(pathStr)
                    .source("PE imports · heuristic")
                    .openPath(parent(file))
                    .build());
        }

        // 6. packed / encrypted binary sitting in a user-writable location
        if (isSuspiciousLocation(pathLower)) {
            double entropy = ru.moon.checker.parse.Entropy.shannon(data);
            if (entropy >= PACKED_ENTROPY) {
                heuristic.add(Finding.builder(category, Severity.LOW,
                                "Упакованный/зашифрованный бинарник / Packed or encrypted binary")
                        .module(module)
                        .detail(String.format(Locale.ROOT, "entropy %.2f/8.0 in a user-writable location", entropy))
                        .evidence(pathStr)
                        .source("entropy · heuristic")
                        .openPath(parent(file))
                        .build());
            }
        }

        // an explicitly allowlisted hash or a valid signature from a known vendor suppresses them
        if (!heuristic.isEmpty() && !isTrusted(file, fileHash, ctx)) {
            heuristic.forEach(ctx::emit);
        }
    }

    /**
     * Severity of the offset-strings finding for a binary that contains {@code distinctNames}
     * different offset/field names, {@code dumpName} when one of them comes from a HIGH rule
     * (an offset-dump name): three or more names HIGH; a dump name or two names MEDIUM; one
     * game field name alone LOW.
     */
    public static Severity offsetSeverity(int distinctNames, boolean dumpName) {
        if (distinctNames >= OFFSET_HIT_HIGH) {
            return Severity.HIGH;
        }
        return dumpName || distinctNames >= 2 ? Severity.MEDIUM : Severity.LOW;
    }

    /**
     * Whether heuristic findings should be suppressed for this file: an
     * explicitly allowlisted hash, or (Windows) a valid Authenticode signature
     * from a trusted vendor. Exact cheat-name / cheat-hash matches are reported
     * before this is consulted, so a signed cheat is still caught.
     */
    private static boolean isTrusted(Path file, String fileHash, ScanContext ctx) {
        if (fileHash != null && ctx.signatures().isAllowedHash(fileHash)) {
            return true;
        }
        if (ru.moon.checker.core.Platform.isWindows()) {
            var sig = ru.moon.checker.win.Authenticode.verify(file);
            return sig.valid() && ctx.signatures().isAllowedSigner(sig.signer());
        }
        return false;
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
                        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                            // Windows' compatibility junctions ("C:\\ProgramData\\Application Data" points back
                            // at ProgramData) made the walk loop 8 levels deep; Java does not see them as links
                            if (!dir.equals(root) && (attrs.isSymbolicLink() || attrs.isOther() || isReparsePoint(dir))) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }

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

    private static final int FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private static final int FILE_ATTRIBUTE_OFFLINE = 0x1000;
    private static final int FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000;
    private static final int FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000;

    /** Windows file attributes, or -1 when unknown (not Windows, no access). */
    static int windowsAttributes(Path p) {
        if (!ru.moon.checker.core.Platform.isWindows()) {
            return -1;
        }
        try {
            return com.sun.jna.platform.win32.Kernel32.INSTANCE.GetFileAttributes(p.toString());
        } catch (Throwable t) {
            return -1;
        }
    }

    /** A junction, symbolic link or mount point (directories are not followed into them). */
    static boolean isReparsePoint(Path p) {
        return isReparse(windowsAttributes(p));
    }

    static boolean isReparse(int attributes) {
        return attributes != -1 && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    }

    /** OneDrive / cloud-only placeholder: content lives in the cloud until something reads it. */
    static boolean isCloudPlaceholder(Path p) {
        return isCloudOnly(windowsAttributes(p));
    }

    static boolean isCloudOnly(int attributes) {
        return attributes != -1 && (attributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)) != 0;
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

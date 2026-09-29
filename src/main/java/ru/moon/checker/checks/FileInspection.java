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
    static final long STRING_SCAN_MAX = 48L * 1024 * 1024;  // 48 MiB deep-scan cap
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

    /** A folder an ordinary user can write to, or a program loose in a drive root (whole roots, not substrings). */
    public static boolean isSuspiciousLocation(String path) {
        if (Locations.classify(path) == Locations.Kind.USER_WRITABLE) {
            return true;
        }
        String n = Locations.normalize(path, true);
        return n != null && n.matches("^[a-z]:\\\\[^\\\\]+\\.(exe|dll|sys|scr)$");
    }

    /** What {@link #inspect} did with a file (collectors count these to state their limits). */
    public enum Outcome {
        /** Read and inspected (content heuristics ran, if the format allows). */
        INSPECTED,
        /** Not an executable by content; only the name, streams and disguise checks applied. */
        NOT_EXECUTABLE,
        /** An executable larger than the content cap: name, streams and hash only. */
        TOO_LARGE,
        /** Starts like an executable but the header is broken: string and entropy checks only. */
        MALFORMED,
        /** Could not be read (permissions, locked, vanished). */
        UNREADABLE,
        /** A cloud-only placeholder: reading it would download it. Name matched only. */
        CLOUD_ONLY,
        /** Zero bytes. */
        EMPTY
    }

    /** Executable formats recognised by content (extension-independent). */
    public enum Format { PE, ELF, MZ_MALFORMED, ELF_MALFORMED, NONE, UNREADABLE }

    /** Reads at most a few hundred bytes: the MZ header and PE signature, or the ELF identification. */
    public static Format format(Path file) {
        try (var ch = Files.newByteChannel(file)) {
            java.nio.ByteBuffer head = java.nio.ByteBuffer.allocate(64).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            while (head.hasRemaining() && ch.read(head) > 0) {
                // fill
            }
            int n = head.position();
            head.flip();
            return format(head, n, ch);
        } catch (IOException | RuntimeException e) {
            return Format.UNREADABLE;
        }
    }

    static Format format(java.nio.ByteBuffer head, int n, java.nio.channels.SeekableByteChannel ch) throws IOException {
        if (n >= 2 && head.get(0) == 'M' && head.get(1) == 'Z') {
            if (n < 64) {
                return Format.MZ_MALFORMED;
            }
            long peOffset = Integer.toUnsignedLong(head.getInt(0x3C));
            if (peOffset < 64 || ch == null || peOffset + 4 > ch.size() || peOffset > 16L * 1024 * 1024) {
                return Format.MZ_MALFORMED;
            }
            java.nio.ByteBuffer sig = java.nio.ByteBuffer.allocate(4);
            ch.position(peOffset);
            while (sig.hasRemaining() && ch.read(sig) > 0) {
                // fill
            }
            return sig.position() == 4 && sig.get(0) == 'P' && sig.get(1) == 'E' && sig.get(2) == 0 && sig.get(3) == 0
                    ? Format.PE : Format.MZ_MALFORMED;
        }
        if (n >= 4 && head.get(0) == 0x7F && head.get(1) == 'E' && head.get(2) == 'L' && head.get(3) == 'F') {
            if (n < 20) {
                return Format.ELF_MALFORMED;
            }
            int cls = head.get(4), data = head.get(5), version = head.get(6);
            return (cls == 1 || cls == 2) && (data == 1 || data == 2) && version == 1 ? Format.ELF : Format.ELF_MALFORMED;
        }
        return Format.NONE;
    }

    /**
     * One heuristic observation, before the identity gate decides how it is reported.
     *
     * @param aboutTheCode true for what the program's own code suggests (offset strings, injection
     *                     imports, entropy, process-memory calls): a verified publisher answers those.
     *                     False for concealment (a program renamed to a picture, a program-sized
     *                     hidden stream): hiding is the signal, whoever signed the hidden bytes.
     */
    private record Hit(Severity severity, String title, String rule, String detail, String evidence, String source,
                       boolean aboutTheCode) {
    }

    /**
     * Inspect one file: name match, streams, disguise, hash, and — for executables recognised by
     * content, of any name — embedded CS2 offset strings, injection imports and entropy.
     *
     * <p>Exact matches (cheat name, cheat-named stream, known hash) are reported as they are.
     * Concealment (a program under a picture's name, a program-sized hidden stream) is reported as
     * observed, whoever signed the hidden bytes. What the code itself suggests (offset strings,
     * injection imports, entropy, process-memory calls) passes an identity check instead of a
     * location allowlist: a file whose publisher this rule set vouches for (or whose hash is
     * approved) is not reported; unidentified in a system or program folder is low-weight context;
     * a signed file whose signature no longer matches is reported at least as MEDIUM.
     */
    public static Outcome inspect(Path file, ScanContext ctx, String module, Category category) {
        return inspect(file, ctx, module, category, null);
    }

    /**
     * As above; with a {@link Gatekeeper} the heuristic observations wait until it verifies the
     * publishers of many files at once (one PowerShell start per batch instead of per file).
     */
    public static Outcome inspect(Path file, ScanContext ctx, String module, Category category, Gatekeeper gate) {
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
            return Outcome.UNREADABLE;
        }
        if (size <= 0) {
            return Outcome.EMPTY;
        }
        if (isCloudPlaceholder(file)) {
            return Outcome.CLOUD_ONLY; // OneDrive "files on demand": reading it would download it
        }
        List<Hit> hits = new java.util.ArrayList<>();

        // 2. hidden Alternate Data Streams — a classic cheat-payload hiding spot
        for (ru.moon.checker.win.AlternateStreams.Stream st : ru.moon.checker.win.AlternateStreams.list(pathStr)) {
            var streamRule = ctx.signatures().matchCheatName(st.name());
            String detail = "Stream \"" + st.name() + "\" (" + st.size() + " bytes)"
                    + streamRule.map(r -> " — " + r.label()).orElse("");
            if (streamRule.isPresent()) {
                ctx.emit(Finding.builder(category, Severity.CRITICAL,
                                "Скрытый поток данных (ADS) / Hidden alternate data stream")
                        .module(module).rule("files:alternate-data-stream").detail(detail)
                        .evidence(pathStr + ":" + st.name()).source("NTFS ADS").openPath(parent(file)).build());
                continue;
            }
            // a stream big enough to hold a program is high; a small unknown stream is context
            hits.add(new Hit(st.size() >= ru.moon.checker.win.AlternateStreams.PAYLOAD_BYTES ? Severity.HIGH : Severity.LOW,
                    "Скрытый поток данных (ADS) / Hidden alternate data stream", "files:alternate-data-stream",
                    detail, pathStr + ":" + st.name(), "NTFS ADS", false));
        }

        // 3. what the content is, whatever the name says
        Format format = format(file);
        if (format == Format.UNREADABLE) {
            deliver(gate, hits, file, null, ctx, module, category);
            return Outcome.UNREADABLE;
        }
        boolean executable = format == Format.PE || format == Format.ELF;
        boolean looksExecutable = executable || format == Format.MZ_MALFORMED || format == Format.ELF_MALFORMED;
        if (looksExecutable && isNonExecutableName(nameLower)) {
            hits.add(new Hit(Severity.HIGH, "Исполняемый файл под чужим расширением / Executable disguised by extension",
                    null, (format == Format.ELF || format == Format.ELF_MALFORMED ? "ELF" : "PE (MZ)")
                    + " content with a non-executable extension", pathStr, "content vs extension · heuristic", false));
        }

        // 4. exact hash match (streamed) — for any executable by content, or every file when the
        //    rule set carries hashes (to catch renamed cheats)
        boolean hashAll = !ctx.signatures().hashes().isEmpty();
        boolean hashUseful = hashAll || !ctx.signatures().allowHashes().isEmpty();
        String fileHash = null;
        if (hashUseful && (looksExecutable || hashAll) && size <= HASH_MAX) {
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

        if (!looksExecutable) {
            deliver(gate, hits, file, fileHash, ctx, module, category);
            return Outcome.NOT_EXECUTABLE;
        }
        // a broken header still gets the string and entropy checks (they parse nothing); only the
        // PE import parse needs a valid header
        // 5. content heuristics, bounded: an executable above the cap keeps its name, stream and hash checks
        if (size > STRING_SCAN_MAX) {
            deliver(gate, hits, file, fileHash, ctx, module, category);
            return Outcome.TOO_LARGE;
        }
        byte[] data;
        try {
            data = Files.readAllBytes(file);
        } catch (IOException | OutOfMemoryError e) {
            deliver(gate, hits, file, fileHash, ctx, module, category);
            return Outcome.UNREADABLE;
        }

        List<String> strings = BinStrings.all(data, MIN_STRING);
        int offsetHits = 0;
        boolean dumpName = false;
        boolean processMemory = false;
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
            processMemory |= (format == Format.ELF || format == Format.ELF_MALFORMED)
                    && (s.equals("process_vm_readv") || s.equals("process_vm_writev"));
        }
        if (offsetHits > 0) {
            // One game field name alone is common in legitimate Source-engine tools (demo and movie
            // tools, server plugins, SDK code): it is shown as LOW and does not ask for a review.
            hits.add(new Hit(offsetSeverity(offsetHits, dumpName),
                    "Строки оффсетов CS2 в бинарнике / CS2 offset strings in binary", null,
                    offsetHits + " match(es): " + trimTail(matched.toString()), pathStr, "binary strings · heuristic",
                    true));
        }

        if (format == Format.PE) {
            Pe pe = Pe.parse(data);
            if (pe.isPe() && pe.looksLikeInjector()) {
                boolean suspicious = isSuspiciousLocation(pathLower) || !pe.signed();
                hits.add(new Hit(suspicious ? Severity.HIGH : Severity.LOW,
                        "Импорт функций инъекции в процесс / Process-injection imports", null,
                        "Imports remote-injection APIs" + (pe.signed() ? "" : ", unsigned")
                                + (isSuspiciousLocation(pathLower) ? ", suspicious location" : ""),
                        pathStr, "PE imports · heuristic", true));
            }
        } else if (processMemory) {
            // the Linux counterpart of injection imports; debuggers use it too, so it only asks with offsets
            hits.add(new Hit(offsetHits > 0 ? Severity.MEDIUM : Severity.LOW,
                    "Доступ к памяти другого процесса / Reads or writes another process's memory",
                    "linuxfiles:process-memory-access", "ELF refers to process_vm_readv / process_vm_writev",
                    pathStr, "ELF symbols · heuristic", true));
        }

        // 6. packed / encrypted binary sitting in a user-writable location
        if (isSuspiciousLocation(pathLower) || Locations.classify(pathStr) == Locations.Kind.USER_WRITABLE) {
            double entropy = ru.moon.checker.parse.Entropy.shannon(data);
            if (entropy >= PACKED_ENTROPY) {
                hits.add(new Hit(Severity.LOW, "Упакованный/зашифрованный бинарник / Packed or encrypted binary", null,
                        String.format(Locale.ROOT, "entropy %.2f/8.0 in a user-writable location", entropy),
                        pathStr, "entropy · heuristic", true));
            }
        }
        deliver(gate, hits, file, fileHash, ctx, module, category);
        return executable ? Outcome.INSPECTED : Outcome.MALFORMED;
    }

    private static void deliver(Gatekeeper gate, List<Hit> hits, Path file, String hash, ScanContext ctx, String module,
                                Category category) {
        if (hits.isEmpty()) {
            return;
        }
        if (gate == null) {
            emitGated(hits, file, hash, ctx, module, category);
        } else {
            gate.add(file, hash, hits);
        }
    }

    /**
     * Holds heuristic observations of many files and checks their publishers in batches. Call
     * {@link #flush()} before the collector returns (a try/finally): pending observations are
     * reported then, verified or not.
     */
    public static final class Gatekeeper {
        private static final int BATCH = 40;
        private final ScanContext ctx;
        private final String module;
        private final Category category;
        private final List<Object[]> pending = new java.util.ArrayList<>();   // {Path, hash, List<Hit>}

        public Gatekeeper(ScanContext ctx, String module, Category category) {
            this.ctx = ctx;
            this.module = module;
            this.category = category;
        }

        void add(Path file, String hash, List<Hit> hits) {
            pending.add(new Object[]{file, hash, hits});
            if (pending.size() >= BATCH) {
                flush();
            }
        }

        @SuppressWarnings("unchecked")
        public void flush() {
            if (pending.isEmpty()) {
                return;
            }
            if (ru.moon.checker.core.Platform.isWindows()) {
                ru.moon.checker.win.Authenticode.verifyAll(pending.stream().map(p -> (Path) p[0]).toList());
            }
            for (Object[] p : pending) {
                emitGated((List<Hit>) p[2], (Path) p[0], (String) p[1], ctx, module, category);
            }
            pending.clear();
        }
    }

    /** Identity of a file for the heuristic gate. */
    enum Identity { VERIFIED, BROKEN, UNVERIFIED }

    /**
     * Reports heuristic observations according to the file's identity (never its location alone):
     * verified → not reported; signature broken → at least MEDIUM; unverified in a system or program
     * folder → LOW context; unverified elsewhere → as observed.
     */
    private static void emitGated(List<Hit> hits, Path file, String fileHash, ScanContext ctx, String module,
                                  Category category) {
        if (hits.isEmpty()) {
            return;
        }
        boolean anyAboutCode = hits.stream().anyMatch(Hit::aboutTheCode);
        Identity id = anyAboutCode ? identity(file, fileHash, ctx) : Identity.UNVERIFIED;
        Locations.Kind where = Locations.ofFile(file);
        for (Hit h : hits) {
            Gate g = h.aboutTheCode() ? gate(id, where, h.severity())
                    : new Gate(h.severity(), null, "");   // concealment: reported as observed
            if (g == null) {
                continue;   // a verified publisher answers what its code suggests
            }
            Finding.Builder b = Finding.builder(category, g.severity(), h.title()).module(module)
                    .detail(h.detail() + g.note()).evidence(h.evidence()).source(h.source()).openPath(parent(file));
            if (h.rule() != null) {
                b.rule(h.rule());
            }
            if (g.kind() != null) {
                b.kind(g.kind());
            }
            ctx.emit(b.build());
        }
    }

    /** How one heuristic observation is reported; {@code null} from {@link #gate} means not at all. */
    record Gate(Severity severity, EvidenceKind kind, String note) {
    }

    /**
     * The identity gate, as a pure decision: a verified publisher (or approved hash) → not reported;
     * a signature that no longer matches → at least MEDIUM; unverified in a system or program folder →
     * LOW context (location alone proves nothing, but the folder needs administrator rights); unverified
     * anywhere else → as observed.
     */
    static Gate gate(Identity id, Locations.Kind where, Severity observed) {
        return switch (id) {
            case VERIFIED -> null;
            case BROKEN -> new Gate(observed.rank() < Severity.MEDIUM.rank() ? Severity.MEDIUM : observed, null,
                    "; its signature no longer matches the file (changed after signing)");
            case UNVERIFIED -> where.protectedByDefault()
                    ? new Gate(Severity.LOW, EvidenceKind.CONTEXT, "; in a " + (where == Locations.Kind.SYSTEM
                    ? "system" : "program") + " folder, publisher not verified (location alone proves nothing)")
                    : new Gate(observed, null, "; publisher not verified");
        };
    }

    private static Identity identity(Path file, String fileHash, ScanContext ctx) {
        if (fileHash == null && !ctx.signatures().allowHashes().isEmpty()) {
            fileHash = Hashing.sha256File(file);
        }
        if (fileHash != null && ctx.signatures().isAllowedHash(fileHash)) {
            return Identity.VERIFIED;
        }
        if (ru.moon.checker.core.Platform.isWindows()) {
            var sig = ru.moon.checker.win.Authenticode.verify(file);
            if (sig.broken()) {
                return Identity.BROKEN;
            }
            if (ctx.signatures().isTrustedIdentity(sig.valid(), sig.rootSha1(), sig.signerNames())) {
                return Identity.VERIFIED;
            }
        }
        return Identity.UNVERIFIED;
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

    /** What a bounded walk covered, and why it stopped if it did not finish. */
    public record Walk(Path root, int files, boolean rootMissing, boolean rootUnreadable, boolean fileLimitHit,
                       boolean timeUp, boolean cancelled, int deniedDirs, int skippedLinks, int depthLimited) {
        /** Every file under the root (to the depth asked) was offered to the callback. */
        public boolean complete() {
            return !rootUnreadable && !fileLimitHit && !timeUp && !cancelled && deniedDirs == 0;
        }

        /** Why not complete, in one line for the coverage report. */
        public String shortfall() {
            List<String> why = new java.util.ArrayList<>();
            if (rootUnreadable) {
                why.add("folder not readable");
            }
            if (fileLimitHit) {
                why.add("file limit of " + files + " reached");
            }
            if (timeUp) {
                why.add("time budget used up after " + files + " files");
            }
            if (cancelled) {
                why.add("cancelled");
            }
            if (deniedDirs > 0) {
                why.add(deniedDirs + " subfolder(s) not readable");
            }
            return root + ": " + String.join(", ", why);
        }
    }

    /** Walk a directory tree (bounded) invoking {@code onFile} for each file. */
    public static int walk(Path root, int maxFiles, int maxDepth, Consumer<Path> onFile, ScanContext ctx) {
        return scan(root, maxFiles, maxDepth, null, onFile, ctx).files();
    }

    /**
     * Walks {@code root} to {@code maxDepth}, offering every regular file to {@code onFile}, and
     * reports what it could not cover: a missing or unreadable root, the file limit, the time limit,
     * cancellation, unreadable subfolders. Links, junctions and mount points below the root are not
     * followed (counted in {@code skippedLinks}): they loop, or lead somewhere scanned on its own.
     */
    public static Walk scan(Path root, int maxFiles, int maxDepth, java.time.Instant stopAt, Consumer<Path> onFile,
                            ScanContext ctx) {
        return scan(root, maxFiles, maxDepth, stopAt, null, onFile, ctx);
    }

    /** As above; folders for which {@code skip} is true are not entered (a declared exclusion). */
    public static Walk scan(Path root, int maxFiles, int maxDepth, java.time.Instant stopAt,
                            java.util.function.Predicate<Path> skip, Consumer<Path> onFile, ScanContext ctx) {
        if (root == null || !Files.exists(root)) {
            return new Walk(root, 0, true, false, false, false, false, 0, 0, 0);
        }
        if (!Files.isDirectory(root) || !Files.isReadable(root)) {
            return new Walk(root, 0, false, true, false, false, false, 0, 0, 0);
        }
        final int[] count = {0};
        final int[] denied = {0};
        final int[] links = {0};
        final int[] deep = {0};
        final boolean[] limit = {false};
        final boolean[] late = {false};
        final boolean[] stopped = {false};
        try {
            Files.walkFileTree(root, java.util.EnumSet.noneOf(java.nio.file.FileVisitOption.class),
                    maxDepth, new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                            // Windows' compatibility junctions ("C:\\ProgramData\\Application Data" points back
                            // at ProgramData) made the walk loop 8 levels deep; Java does not see them as links
                            if (!dir.equals(root) && (attrs.isSymbolicLink() || attrs.isOther() || isReparsePoint(dir))) {
                                links[0]++;
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            if (!dir.equals(root) && skip != null && skip.test(dir)) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) {
                            if (ctx != null && ctx.isCancelled()) {
                                stopped[0] = true;
                                return FileVisitResult.TERMINATE;
                            }
                            if (count[0] >= maxFiles) {
                                limit[0] = true;
                                return FileVisitResult.TERMINATE;
                            }
                            if (stopAt != null && java.time.Instant.now().isAfter(stopAt)) {
                                late[0] = true;
                                return FileVisitResult.TERMINATE;
                            }
                            if (attrs.isDirectory()) {
                                deep[0]++;   // a folder at the depth limit: its content was not listed
                            } else if (attrs.isRegularFile()) {
                                onFile.accept(f);
                                count[0]++;
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed(Path f, IOException exc) {
                            if (exc instanceof java.nio.file.AccessDeniedException || Files.isDirectory(f)) {
                                denied[0]++;
                            }
                            return FileVisitResult.CONTINUE; // a file that vanished or is locked: skip
                        }
                    });
        } catch (IOException e) {
            return new Walk(root, count[0], false, true, limit[0], late[0], stopped[0], denied[0], links[0], deep[0]);
        }
        return new Walk(root, count[0], false, false, limit[0], late[0], stopped[0], denied[0], links[0], deep[0]);
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

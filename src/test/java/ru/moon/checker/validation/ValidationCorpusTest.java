package ru.moon.checker.validation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import ru.moon.checker.checks.FileInspection;
import ru.moon.checker.core.Assessment;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.Coverage;
import ru.moon.checker.core.EvidenceKind;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Integrity;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.RulesProvenance;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.Severity;
import ru.moon.checker.core.TestResults;
import ru.moon.checker.core.Verdict;
import ru.moon.checker.core.VerdictEngine;
import ru.moon.checker.parse.BinStrings;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.signatures.SignatureRule;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Measured validation — every number in {@code docs/validation.md} comes from here and is
 * pinned by an assertion, so a change that moves a number fails the build until the
 * document is updated with it. Results are written to {@code target/validation/results.json}
 * (each section records its numbers before asserting, so the file is written even when an
 * assertion fails).
 *
 * <p>No cheat software is used or needed. Positives are harmless generated files that a
 * test-only rule pack describes the way a real pack describes a cheat; negatives are
 * benign files, near-miss lookalikes and (opt-in, {@code -Dmoon.validation.host=true})
 * the real system files of the machine running the test. This measures whether the
 * matching logic and the outcome policy do what they claim. It does not measure how many
 * real cheats the shipped rules catch: that needs a labelled corpus of real samples.
 */
class ValidationCorpusTest {

    private static final long SEED = 20260928L;
    private static final Path OUT = Path.of("target", "validation", "results.json");
    /** Shared with the panel (web/tests/test_policy_golden.py): both engines must agree. */
    static final Path GOLDEN = Path.of("spec", "policy-golden.json");
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final Map<String, Object> RESULTS = new TreeMap<>();
    private static final SignatureDb BUNDLED = SignatureLoader.load(null).db();
    private static final String OFFSET_RULE = "files:cs2-offset-strings-in-binary";

    @TempDir
    static Path tmp;

    /** Binary-classifier counts; "positive" means "the checker should raise this". */
    record Confusion(int tp, int fp, int fn, int tn) {
        static Confusion of(List<boolean[]> rows) {
            int tp = 0, fp = 0, fn = 0, tn = 0;
            for (boolean[] r : rows) {
                boolean expected = r[0], raised = r[1];
                if (expected && raised) tp++;
                else if (!expected && raised) fp++;
                else if (expected) fn++;
                else tn++;
            }
            return new Confusion(tp, fp, fn, tn);
        }

        double precision() {
            return tp + fp == 0 ? Double.NaN : (double) tp / (tp + fp);
        }

        double recall() {
            return tp + fn == 0 ? Double.NaN : (double) tp / (tp + fn);
        }

        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tp", tp);
            m.put("fp", fp);
            m.put("fn", fn);
            m.put("tn", tn);
            m.put("precision", round(precision()));
            m.put("recall", round(recall()));
            return m;
        }
    }

    private static Object round(double v) {
        return Double.isNaN(v) ? null : Math.round(v * 10000) / 10000.0;
    }

    // ---- 1. exact hash rules ------------------------------------------------------------

    @Test
    void exactHashRules() throws IOException {
        Random rnd = new Random(SEED);
        Path dir = Files.createDirectories(tmp.resolve("hash"));
        List<byte[]> known = new ArrayList<>();
        List<byte[]> unknown = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            known.add(randomPe(rnd));
            unknown.add(randomPe(rnd));
        }
        List<SignatureRule> rules = new ArrayList<>();
        for (byte[] b : known) {
            rules.add(new SignatureRule(null, Integrity.sha256Hex(b), Severity.CRITICAL, "validation sample"));
        }
        SignatureDb pack = new SignatureDb("validation", null, null, rules, null, null, null, null, null, null, null);

        List<boolean[]> exact = new ArrayList<>();
        List<boolean[]> renamed = new ArrayList<>();
        List<boolean[]> patched = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            boolean negative = detected(inspect(write(dir, "other-" + i + ".exe", unknown.get(i)), pack));
            exact.add(new boolean[]{true, detected(inspect(write(dir, "sample-" + i + ".exe", known.get(i)), pack))});
            exact.add(new boolean[]{false, negative});
            // the same bytes under another name, folder and extension
            Path moved = write(Files.createDirectories(dir.resolve("moved")), "notes-" + i + ".png", known.get(i));
            renamed.add(new boolean[]{true, detected(inspect(moved, pack))});
            renamed.add(new boolean[]{false, negative});
            // the same program with one byte changed (a rebuild, a patched string, a new version)
            byte[] b = known.get(i).clone();
            int at = 2 + rnd.nextInt(b.length - 2);
            b[at] ^= 0x01;
            patched.add(new boolean[]{true, detected(inspect(write(dir, "patched-" + i + ".exe", b), pack))});
            patched.add(new boolean[]{false, negative});
        }
        Confusion e = Confusion.of(exact), r = Confusion.of(renamed), p = Confusion.of(patched);
        RESULTS.put("1-hash", Map.of("exactCopies", e.json(), "renamedCopies", r.json(), "oneBytePatched", p.json()));
        assertEquals(new Confusion(100, 0, 0, 100), e);
        assertEquals(new Confusion(100, 0, 0, 100), r);
        assertEquals(new Confusion(0, 0, 100, 100), p, "exact hashes do not survive any change — by design");
    }

    // ---- 2. executable disguised by extension -------------------------------------------

    @Test
    void disguisedExecutableHeuristic() throws IOException {
        Random rnd = new Random(SEED + 1);
        Path dir = Files.createDirectories(tmp.resolve("disguise"));
        String[] docExt = {".png", ".jpg", ".txt", ".mp4", ".zip", ".cfg"};
        String[] peExt = {".dll", ".cpl", ".drv", ".ocx", ".sys", ".exe"};
        List<boolean[]> rows = new ArrayList<>();
        int wrongKind = 0;
        for (int i = 0; i < 60; i++) {
            List<Finding> f = inspect(write(dir, "file-" + i + docExt[i % 6], randomPe(rnd)), BUNDLED);
            rows.add(new boolean[]{true, raised(f, "files:executable-disguised-by-extension")});
            wrongKind += (int) f.stream().filter(x -> x.kind() == EvidenceKind.DETECTION).count();
        }
        for (int i = 0; i < 60; i++) {   // real documents and media with those extensions
            String ext = docExt[i % 6];
            rows.add(new boolean[]{false, raised(inspect(write(dir, "real-" + i + ext, realContent(ext, rnd)), BUNDLED),
                    "files:executable-disguised-by-extension")});
        }
        for (int i = 0; i < 60; i++) {   // genuine binaries under legitimate PE extensions
            rows.add(new boolean[]{false, raised(inspect(write(dir, "lib-" + i + peExt[i % 6], randomPe(rnd)), BUNDLED),
                    "files:executable-disguised-by-extension")});
        }
        // a disguised PE inside an allowlisted location is not reported: heuristics trust those paths
        Path trusted = Files.createDirectories(dir.resolve("opt").resolve("vendor"));
        int suppressed = 0;
        for (int i = 0; i < 20; i++) {
            if (!raised(inspect(write(trusted, "asset-" + i + ".png", randomPe(rnd)), BUNDLED),
                    "files:executable-disguised-by-extension")) {
                suppressed++;
            }
        }
        Confusion c = Confusion.of(rows);
        Map<String, Object> m = new LinkedHashMap<>(c.json());
        m.put("suppressedInAllowlistedPath", suppressed + "/20");
        m.put("detectionsFromHeuristic", wrongKind);
        RESULTS.put("2-disguised-extension", m);
        assertEquals(new Confusion(60, 0, 0, 120), c);
        assertEquals(0, wrongKind, "a heuristic never produces a DETECTION");
        assertEquals(20, suppressed);
    }

    // ---- 3. CS2 offset names inside a binary --------------------------------------------

    /** The four groups of the offset corpus; only {@code cheatShaped} is labelled positive. */
    record OffsetCorpus(List<Path> cheatShaped, List<Path> singleField, List<Path> plain, List<Path> nearMiss) {
    }

    /** One measurement of the offset corpus. */
    record OffsetRun(Confusion confusion, int singleFieldReported, int singleFieldMoving, int nearMissReported) {
        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>(confusion.json());
            m.put("singleFieldNameReported", singleFieldReported + "/40");
            m.put("singleFieldNameOutcomeMoving", singleFieldMoving + "/40");
            m.put("nearMissFieldNameReported", nearMissReported + "/40");
            return m;
        }
    }

    /**
     * Two families of names: offset-dump names ({@code dw…}, severity HIGH in the rules), which
     * come from cheat-community offset dumps, and the game's own field names ({@code m_…},
     * MEDIUM), which legitimate Source-engine tools — demo and movie tools, server plugins,
     * SDK code — also contain. The label is "should move the outcome", i.e. raise a finding at
     * MEDIUM or above.
     *
     * <p>The same corpus is also measured as rules 2026.09.14-cs2 behaved: every name matched as a
     * substring and every hit raised at MEDIUM or above, so under that policy "reported" and
     * "outcome-moving" were the same thing. Those are the "before" numbers in docs/validation.md;
     * they were first measured on the unmodified code (commit 22e0012) and this reproduces them.
     */
    @Test
    void offsetStringHeuristic() throws IOException {
        Random rnd = new Random(SEED + 2);
        Path dir = Files.createDirectories(tmp.resolve("offsets"));
        List<String> dumper = BUNDLED.offsetStrings().stream().filter(r -> r.severity() == Severity.HIGH)
                .map(SignatureRule::pattern).toList();
        List<String> fields = BUNDLED.offsetStrings().stream().filter(r -> r.severity() != Severity.HIGH)
                .map(SignatureRule::pattern).toList();
        assertTrue(dumper.size() >= 5 && fields.size() >= 5, "bundled rules carry both families");

        List<Path> cheatShaped = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            List<String> embedded = new ArrayList<>();
            if (i % 2 == 0) {   // one offset-dump name, plus 0–2 game field names
                embedded.add(dumper.get(rnd.nextInt(dumper.size())));
                embedded.addAll(distinct(fields, rnd.nextInt(3), rnd));
            } else {            // 2–4 distinct game field names and no dump name
                embedded.addAll(distinct(fields, 2 + rnd.nextInt(3), rnd));
            }
            cheatShaped.add(write(dir, "tool-" + i + ".dll", peWithStrings(rnd, embedded)));
        }
        List<Path> singleField = new ArrayList<>();   // what a legitimate Source-engine tool can carry
        for (int i = 0; i < 40; i++) {
            singleField.add(write(dir, "field-" + i + ".dll",
                    peWithStrings(rnd, List.of(fields.get(i % fields.size())))));
        }
        List<Path> plain = new ArrayList<>();         // binaries without any of the names
        for (int i = 0; i < 60; i++) {
            plain.add(write(dir, "plain-" + i + ".dll", randomPe(rnd)));
        }
        List<Path> nearMiss = new ArrayList<>();      // a field name inside a longer, different identifier
        for (int i = 0; i < 40; i++) {
            String n = fields.get(i % fields.size());
            nearMiss.add(write(dir, "near-" + i + ".dll", peWithStrings(rnd, List.of(i % 2 == 0 ? n + "Max" : "Old" + n))));
        }
        OffsetCorpus corpus = new OffsetCorpus(cheatShaped, singleField, plain, nearMiss);

        OffsetRun now = offsetRun(corpus, BUNDLED, f -> moving(f, OFFSET_RULE));
        OffsetRun before = offsetRun(corpus, substringOffsets(BUNDLED), f -> raised(f, OFFSET_RULE));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("corpus", Map.of("cheatShaped", 60, "singleFieldName", 40, "plain", 60, "nearMissFieldName", 40));
        m.put("current", now.json());
        m.put("before-2026.09.14", before.json());
        RESULTS.put("3-offset-strings", m);
        assertEquals(new OffsetRun(new Confusion(60, 80, 0, 60), 40, 40, 40), now);
        assertEquals(new OffsetRun(new Confusion(60, 80, 0, 60), 40, 40, 40), before,
                "the 2026.09.14 behaviour is the documented baseline");
    }

    private static OffsetRun offsetRun(OffsetCorpus corpus, SignatureDb db, Predicate<List<Finding>> movesOutcome) {
        List<boolean[]> rows = new ArrayList<>();
        for (Path p : corpus.cheatShaped()) {
            rows.add(new boolean[]{true, movesOutcome.test(inspect(p, db))});
        }
        int singleReported = 0, singleMoving = 0, nearReported = 0;
        for (Path p : corpus.singleField()) {
            List<Finding> f = inspect(p, db);
            boolean moves = movesOutcome.test(f);
            singleReported += raised(f, OFFSET_RULE) ? 1 : 0;
            singleMoving += moves ? 1 : 0;
            rows.add(new boolean[]{false, moves});
        }
        for (Path p : corpus.plain()) {
            rows.add(new boolean[]{false, movesOutcome.test(inspect(p, db))});
        }
        for (Path p : corpus.nearMiss()) {
            List<Finding> f = inspect(p, db);
            nearReported += raised(f, OFFSET_RULE) ? 1 : 0;
            rows.add(new boolean[]{false, movesOutcome.test(f)});
        }
        return new OffsetRun(Confusion.of(rows), singleReported, singleMoving, nearReported);
    }

    /** The given rules with every offset name matched as a substring, as in rules 2026.09.14-cs2. */
    private static SignatureDb substringOffsets(SignatureDb db) {
        List<SignatureRule> offsets = db.offsetStrings().stream()
                .map(r -> new SignatureRule(r.pattern(), r.sha256(), r.severity(), r.note(), true)).toList();
        return new SignatureDb(db.version() + "+substring-offsets", db.cheatNames(), db.domains(), db.hashes(),
                offsets, db.vulnerableDrivers(), db.cleaners(), db.macroTools(), db.allowPaths(), db.allowSigners(),
                db.allowHashes());
    }

    /** {@code n} different entries of {@code from}, in random order. */
    private static List<String> distinct(List<String> from, int n, Random rnd) {
        List<String> copy = new ArrayList<>(from);
        Collections.shuffle(copy, rnd);
        return List.copyOf(copy.subList(0, n));
    }

    // ---- 4. outcome policy: one golden file for the checker and the panel ---------------

    private static final String[] REQUIRED = {"amcache", "antiforensic", "cs2", "deleted", "environment",
            "execution", "files", "kernel", "persistence"};

    /**
     * 1000 random evidence/coverage scenarios through {@link VerdictEngine}. The outcomes are
     * compared with {@code spec/policy-golden.json}, which the panel's copy of the policy is
     * tested against too; regenerate it deliberately with {@code -Dmoon.validation.writeGolden=true}.
     * The spec invariants are checked independently of the engine's code.
     */
    @Test
    void outcomePolicyGolden() throws IOException {
        List<Map<String, Object>> scenarios = scenarios(1000, new Random(SEED + 3));
        Map<String, Integer> outcomes = new TreeMap<>();
        int detections = 0, detectionsNotValidated = 0, reviews = 0, reviewsNotReview = 0;
        int quiet = 0, quietCalledCheating = 0, settingsOnly = 0, settingsOnlyCheating = 0, settingsOnlyClean = 0;
        int incompleteQuiet = 0, incompleteQuietCalledClean = 0;
        for (Map<String, Object> sc : scenarios) {
            Assessment a = assess(sc);
            Verdict v = a.outcome();
            sc.put("outcome", v.name());
            outcomes.merge(v.name(), 1, Integer::sum);
            boolean cheating = v == Verdict.VALIDATED_DETECTION || v == Verdict.REVIEW_REQUIRED;
            List<Map<String, String>> ev = evidence(sc);
            boolean detection = ev.stream().anyMatch(e -> e.get("kind").equals("DETECTION"));
            boolean review = ev.stream().anyMatch(e -> (e.get("kind").equals("INDICATOR")
                    || e.get("kind").equals("CONCEALMENT"))
                    && Severity.valueOf(e.get("severity")).compareTo(Severity.MEDIUM) >= 0);
            if (detection) {                 // any DETECTION => VALIDATED_DETECTION
                detections++;
                detectionsNotValidated += v != Verdict.VALIDATED_DETECTION ? 1 : 0;
            } else if (review) {             // else INDICATOR/CONCEALMENT at MEDIUM+ => REVIEW_REQUIRED
                reviews++;
                reviewsNotReview += v != Verdict.REVIEW_REQUIRED ? 1 : 0;
            } else {                         // neither => never a cheating outcome
                quiet++;
                quietCalledCheating += cheating ? 1 : 0;
                if (!a.coverage().complete()) {  // and missing telemetry is never "no evidence"
                    incompleteQuiet++;
                    incompleteQuietCalledClean += v == Verdict.NO_EVIDENCE ? 1 : 0;
                }
            }
            if (!ev.isEmpty() && ev.stream().allMatch(e -> e.get("kind").equals("CONFIGURATION"))) {
                settingsOnly++;              // security settings alone are never a cheating verdict
                settingsOnlyCheating += cheating ? 1 : 0;
                settingsOnlyClean += v == Verdict.NO_EVIDENCE ? 1 : 0;
            }
        }
        if (Boolean.getBoolean("moon.validation.writeGolden")) {
            writeGolden(scenarios);
        }
        List<Map<String, Object>> golden = JSON.readValue(GOLDEN.toFile(), new TypeReference<>() {
        });
        int agree = 0;
        for (int i = 0; i < Math.min(golden.size(), scenarios.size()); i++) {
            agree += golden.get(i).equals(scenarios.get(i)) ? 1 : 0;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scenarios", scenarios.size());
        m.put("goldenScenarios", golden.size());
        m.put("agreeWithGolden", agree);
        m.put("outcomes", outcomes);
        m.put("withDetection", detections);
        m.put("withDetectionNotValidated", detectionsNotValidated);
        m.put("withReviewEvidence", reviews);
        m.put("withReviewEvidenceNotReview", reviewsNotReview);
        m.put("withoutEitherScenarios", quiet);
        m.put("withoutEitherReportedAsCheating", quietCalledCheating);
        m.put("settingsOnlyScenarios", settingsOnly);
        m.put("settingsOnlyReportedAsCheating", settingsOnlyCheating);
        m.put("settingsOnlyNoEvidence", settingsOnlyClean);
        m.put("incompleteWithoutEvidence", incompleteQuiet);
        m.put("incompleteWithoutEvidenceCalledNoEvidence", incompleteQuietCalledClean);
        RESULTS.put("4-outcome-policy", m);

        assertEquals(golden, scenarios, "the engine changed its answers: regenerate the golden file on purpose");
        assertEquals(0, detectionsNotValidated + reviewsNotReview + quietCalledCheating + settingsOnlyCheating
                + incompleteQuietCalledClean, "spec invariants: " + m);
        assertEquals(Map.of("INCOMPLETE_SCAN", 430, "NO_EVIDENCE", 282, "REVIEW_REQUIRED", 205,
                "UNSUPPORTED_CONFIGURATION", 49, "VALIDATED_DETECTION", 34), outcomes, "every outcome is exercised");
        assertEquals(List.of(34, 205, 761, 71, 479), List.of(detections, reviews, quiet, settingsOnly, incompleteQuiet));
        assertEquals(24, settingsOnlyClean);
    }

    /** One scenario per line: a change of answers shows up as a readable diff. */
    private static void writeGolden(List<Map<String, Object>> scenarios) throws IOException {
        ObjectMapper compact = new ObjectMapper();
        StringBuilder sb = new StringBuilder("[\n");
        for (int i = 0; i < scenarios.size(); i++) {
            sb.append(compact.writeValueAsString(scenarios.get(i))).append(i + 1 < scenarios.size() ? ",\n" : "\n");
        }
        Files.createDirectories(GOLDEN.getParent());
        Files.writeString(GOLDEN, sb.append("]\n"), StandardCharsets.UTF_8);
    }

    private static List<Map<String, Object>> scenarios(int n, Random rnd) {
        String[] kinds = {"DETECTION", "INDICATOR", "INDICATOR", "INDICATOR", "CONCEALMENT", "CONFIGURATION",
                "CONFIGURATION", "CONFIGURATION", "CONTEXT", "CONTEXT", "CONTEXT"};
        Severity[] sev = Severity.values();
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            List<Map<String, String>> ev = new ArrayList<>();
            int count = rnd.nextInt(10) < 4 ? 0 : 1 + rnd.nextInt(3);
            for (int j = 0; j < count; j++) {
                String kind = kinds[rnd.nextInt(kinds.length)];
                if (kind.equals("DETECTION") && rnd.nextInt(3) != 0) {
                    kind = "CONTEXT"; // detections are rare
                }
                Map<String, String> e = new LinkedHashMap<>();
                e.put("kind", kind);
                e.put("severity", sev[rnd.nextInt(sev.length)].name());
                ev.add(e);
            }
            Map<String, String> modules = new TreeMap<>();
            for (String m : REQUIRED) {
                int roll = rnd.nextInt(100);
                modules.put(m, roll < 94 ? "OK" : roll < 96 ? "ERROR" : roll < 98 ? "TIMEOUT" : "SKIPPED");
            }
            Map<String, Object> cov = new LinkedHashMap<>();
            cov.put("elevated", rnd.nextInt(100) < 85);
            cov.put("platformSupported", rnd.nextInt(100) < 92);
            cov.put("required", List.of(REQUIRED));
            cov.put("modules", modules);
            int r = rnd.nextInt(100);
            Map<String, Object> rules = new LinkedHashMap<>();
            rules.put("origin", r < 80 ? "bundled" : r < 90 ? "signed-override" : "none");
            rules.put("count", r >= 90 || r % 17 == 0 ? 0 : 158);
            Map<String, Object> sc = new LinkedHashMap<>();
            sc.put("evidence", ev);
            sc.put("coverage", cov);
            sc.put("rules", rules);
            out.add(sc);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, String>> evidence(Map<String, Object> sc) {
        return (List<Map<String, String>>) sc.get("evidence");
    }

    @SuppressWarnings("unchecked")
    private static Assessment assess(Map<String, Object> sc) {
        List<Finding> findings = new ArrayList<>();
        int j = 0;
        for (Map<String, String> e : evidence(sc)) {
            j++;
            findings.add(Finding.builder(Category.FILES, Severity.valueOf(e.get("severity")), "item " + j)
                    .module("files").kind(EvidenceKind.valueOf(e.get("kind")))
                    .evidence("C:\\validation\\item-" + j).build());
        }
        Map<String, Object> cov = (Map<String, Object>) sc.get("coverage");
        Map<String, Object> rules = (Map<String, Object>) sc.get("rules");
        Map<String, ModuleStatus> modules = new LinkedHashMap<>();
        ((Map<String, String>) cov.get("modules")).forEach((k, v) -> modules.put(k, ModuleStatus.valueOf(v)));
        Coverage coverage = new Coverage(modules, new TreeSet<>((List<String>) cov.get("required")),
                (Boolean) cov.get("elevated"), (Boolean) cov.get("platformSupported"), "validation", Map.of(),
                new RulesProvenance((String) rules.get("origin"), "", (Integer) rules.get("count"), null));
        return VerdictEngine.assess(findings, coverage, TestResults.ENV);
    }

    // ---- 5. benign baseline on the machine running the test (opt-in) --------------------

    /**
     * Not pinned: the numbers describe whichever machine runs it. Name rules are reported by
     * list and index only ({@code cheatNames#12}), never by the name they contain.
     */
    @Test
    @EnabledIfSystemProperty(named = "moon.validation.host", matches = "true")
    void hostBenignBaseline() throws IOException {
        Map<String, List<SignatureRule>> nameLists = new LinkedHashMap<>();
        nameLists.put("cheatNames", BUNDLED.cheatNames());
        nameLists.put("cleaners", BUNDLED.cleaners());
        nameLists.put("macroTools", BUNDLED.macroTools());
        nameLists.put("vulnerableDrivers", BUNDLED.vulnerableDrivers());
        Map<String, Integer> hits = new TreeMap<>();
        Map<String, List<String>> examples = new TreeMap<>();
        long[] files = {0};
        List<Path> libraries = new ArrayList<>();
        List<String> roots = new ArrayList<>();
        for (String root : new String[]{"/usr", "/opt", "/snap", "/etc", "/var/lib"}) {
            Path start = Path.of(root);
            if (!Files.isDirectory(start)) {
                continue;
            }
            roots.add(root);
            Files.walkFileTree(start, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile() || files[0] >= 2_000_000) {
                        return FileVisitResult.CONTINUE;
                    }
                    files[0]++;
                    String name = f.getFileName().toString().toLowerCase(Locale.ROOT);
                    nameLists.forEach((list, rules) -> {
                        for (int i = 0; i < rules.size(); i++) {
                            if (rules.get(i).matches(name)) {
                                String key = list + "#" + i;
                                hits.merge(key, 1, Integer::sum);
                                List<String> ex = examples.computeIfAbsent(key, k -> new ArrayList<>());
                                if (ex.size() < 3) {
                                    ex.add(f.toString());
                                }
                            }
                        }
                    });
                    if (name.endsWith(".so") || name.contains(".so.")) {
                        if (libraries.size() < 4000 && attrs.size() < 48L * 1024 * 1024) {
                            libraries.add(f);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    return FileVisitResult.CONTINUE;
                }
            });
        }
        // the offset heuristic without the path allowlist: what a user-installed tool would face
        int libsWithOffsets = 0;
        Map<String, Integer> bySeverity = new TreeMap<>();
        Map<String, Integer> offsetHits = new TreeMap<>();
        for (Path lib : libraries) {
            byte[] data;
            try {
                data = Files.readAllBytes(lib);
            } catch (IOException | OutOfMemoryError e) {
                continue;
            }
            Set<String> seen = new TreeSet<>();
            boolean dumpName = false;
            for (String s : BinStrings.all(data, 4)) {
                for (SignatureRule r : BUNDLED.allOffsetMatches(s)) {
                    seen.add(r.pattern());
                    dumpName |= r.severity().compareTo(Severity.HIGH) >= 0;
                }
            }
            if (!seen.isEmpty()) {
                libsWithOffsets++;
                seen.forEach(p -> offsetHits.merge(p, 1, Integer::sum));
                bySeverity.merge(FileInspection.offsetSeverity(seen.size(), dumpName).name(), 1, Integer::sum);
            }
        }
        List<String> dictionaryWords = new ArrayList<>();
        Path dict = Path.of("/usr/share/dict/words");
        if (Files.isRegularFile(dict)) {
            Set<String> words = new HashSet<>();
            for (String w : Files.readAllLines(dict, StandardCharsets.UTF_8)) {
                words.add(w.toLowerCase(Locale.ROOT));
            }
            for (int i = 0; i < BUNDLED.cheatNames().size(); i++) {
                if (words.contains(BUNDLED.cheatNames().get(i).pattern())) {
                    dictionaryWords.add("cheatNames#" + i);
                }
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version"));
        m.put("roots", roots);
        m.put("filesScanned", files[0]);
        m.put("nameRuleHits", hits);
        m.put("nameRuleExamples", examples);
        m.put("filesWithNameHit", hits.values().stream().mapToInt(Integer::intValue).sum());
        m.put("sharedLibrariesScanned", libraries.size());
        m.put("sharedLibrariesWithOffsetNames", libsWithOffsets);
        m.put("sharedLibrariesWithOffsetNamesBySeverity", bySeverity);
        m.put("offsetNameHits", offsetHits);
        m.put("cheatNameRules", BUNDLED.cheatNames().size());
        m.put("dictionaryAvailable", Files.isRegularFile(dict));
        m.put("cheatNameRulesThatAreDictionaryWords", dictionaryWords.size());
        m.put("cheatNameRulesThatAreDictionaryWordsIds", dictionaryWords);
        RESULTS.put("5-host-baseline", m);
    }

    // ---- helpers ------------------------------------------------------------------------

    @AfterAll
    static void writeResults() throws IOException {
        Files.createDirectories(OUT.getParent());
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("seed", SEED);
        doc.put("rulesVersion", BUNDLED.version());
        doc.putAll(RESULTS);
        JSON.writeValue(OUT.toFile(), doc);
    }

    private static List<Finding> inspect(Path file, SignatureDb db) {
        List<Finding> out = new ArrayList<>();
        ScanContext ctx = new ScanContext(db, CheckId.generate(), TestResults.ENV, null, out::add);
        FileInspection.inspect(file, ctx, "files", Category.FILES);
        return out;
    }

    private static boolean detected(List<Finding> findings) {
        return findings.stream().anyMatch(f -> f.kind() == EvidenceKind.DETECTION);
    }

    private static boolean raised(List<Finding> findings, String ruleId) {
        return findings.stream().anyMatch(f -> f.ruleId().equals(ruleId));
    }

    /** Raised at a severity that moves the outcome (MEDIUM or above). */
    private static boolean moving(List<Finding> findings, String ruleId) {
        return findings.stream().anyMatch(f -> f.ruleId().equals(ruleId)
                && f.severity().compareTo(Severity.MEDIUM) >= 0);
    }

    private static Path write(Path dir, String name, byte[] data) throws IOException {
        return Files.write(dir.resolve(name), data);
    }

    /** "MZ" and random bytes: shaped like a Windows program to the checker, harmless as data. */
    private static byte[] randomPe(Random rnd) {
        byte[] b = new byte[4096 + rnd.nextInt(28_000)];
        rnd.nextBytes(b);
        b[0] = 'M';
        b[1] = 'Z';
        return b;
    }

    private static byte[] peWithStrings(Random rnd, List<String> strings) {
        byte[] b = randomPe(rnd);
        int at = 512;
        for (String s : strings) {
            byte[] t = s.getBytes(StandardCharsets.US_ASCII);
            b[at - 1] = 0;
            System.arraycopy(t, 0, b, at, t.length);
            b[at + t.length] = 0;
            at += t.length + 64;
        }
        return b;
    }

    private static byte[] realContent(String ext, Random rnd) {
        byte[] body = new byte[2048 + rnd.nextInt(8192)];
        rnd.nextBytes(body);
        byte[] head = switch (ext) {
            case ".png" -> new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
            case ".jpg" -> new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0};
            case ".mp4" -> new byte[]{0, 0, 0, 0x18, 'f', 't', 'y', 'p'};
            case ".zip" -> new byte[]{'P', 'K', 3, 4};
            default -> null;
        };
        if (head == null) {   // .txt / .cfg
            return ("# settings\nsensitivity=1.25\nfov=90\nname=player " + rnd.nextInt(1000) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
        }
        System.arraycopy(head, 0, body, 0, head.length);
        return body;
    }
}

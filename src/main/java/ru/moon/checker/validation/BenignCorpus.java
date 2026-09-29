package ru.moon.checker.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ru.moon.checker.checks.FileInspection;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.signatures.SignatureDb;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * False-positive measurement on a folder of legitimate files ({@code --evaluate-benign}).
 *
 * <p>Every file is inspected exactly as a scan would (content formats, identity gate, name rules).
 * Because the folder is known to be legitimate, every file that would be reported is a false
 * positive of the rule that fired, and every file whose finding would move the outcome is a false
 * "needs a look". Rates come with a Wilson 95 % interval over the number of files inspected. This
 * measures false positives only; it says nothing about how many cheats are caught.
 */
public final class BenignCorpus {

    private BenignCorpus() {
    }

    public static Map<String, Object> evaluate(Path root, int limit, SignatureDb db, EnvironmentInfo env) {
        Map<FileInspection.Outcome, Integer> outcomes = new TreeMap<>();
        Map<String, int[]> perRule = new TreeMap<>();   // rule → {files reported, files moving the outcome}
        int filesWithFinding = 0;
        int filesMoving = 0;
        List<String> movingExamples = new ArrayList<>();
        List<Finding> sink = new ArrayList<>();
        ScanContext ctx = new ScanContext(db, CheckId.generate(), env, null, sink::add);
        FileInspection.Gatekeeper gate = new FileInspection.Gatekeeper(ctx, "benign", Category.FILES);
        List<Path> files = new ArrayList<>();
        FileInspection.Walk walk = FileInspection.scan(root, limit, 16, null, files::add, null);
        // inspect in batches so the identity gate verifies publishers 40 at a time, then attribute per file
        for (int i = 0; i < files.size(); i += 40) {
            for (Path f : files.subList(i, Math.min(files.size(), i + 40))) {
                outcomes.merge(FileInspection.inspect(f, ctx, "benign", Category.FILES, gate), 1, Integer::sum);
            }
            gate.flush();
            Map<String, List<Finding>> byFile = new TreeMap<>();
            for (Finding f : sink) {
                String file = f.evidence() == null ? "?" : stripStream(f.evidence());
                byFile.computeIfAbsent(file, k -> new ArrayList<>()).add(f);
            }
            for (var e : byFile.entrySet()) {
                boolean moving = e.getValue().stream().anyMatch(Finding::movesOutcome);
                filesWithFinding++;
                if (moving) {
                    filesMoving++;
                    if (movingExamples.size() < 25) {
                        movingExamples.add(e.getKey() + " — " + e.getValue().stream().filter(Finding::movesOutcome)
                                .map(x -> x.ruleId() + " " + x.severity()).distinct().toList());
                    }
                }
                for (String rule : e.getValue().stream().map(Finding::ruleId).distinct().toList()) {
                    int[] c = perRule.computeIfAbsent(rule, k -> new int[2]);
                    c[0]++;
                    if (e.getValue().stream().anyMatch(x -> x.ruleId().equals(rule) && x.movesOutcome())) {
                        c[1]++;
                    }
                }
            }
            sink.clear();
        }
        int n = files.size();
        Map<String, Object> rules = new TreeMap<>();
        perRule.forEach((rule, c) -> rules.put(rule, Map.of("filesReported", c[0], "filesMovingOutcome", c[1],
                "movingRate", rate(c[1], n))));
        Map<String, Object> out = new TreeMap<>();
        out.put("folder", root.toString());
        out.put("filesInspected", n);
        out.put("walkComplete", walk.complete());
        out.put("walkShortfall", walk.complete() ? "" : walk.shortfall());
        out.put("outcomes", outcomes);
        out.put("filesWithAnyFinding", Map.of("n", filesWithFinding, "rate", rate(filesWithFinding, n)));
        out.put("filesMovingOutcome", Map.of("n", filesMoving, "rate", rate(filesMoving, n)));
        out.put("perRule", rules);
        out.put("movingExamples", movingExamples);
        out.put("rules", db.version());
        return out;
    }

    /** "C:\x\notes.txt:payload" → "C:\x\notes.txt" (a stream belongs to its file); drive letters stay. */
    static String stripStream(String evidence) {
        int colon = evidence.lastIndexOf(':');
        int sep = Math.max(evidence.lastIndexOf('\\'), evidence.lastIndexOf('/'));
        return colon > 1 && colon > sep ? evidence.substring(0, colon) : evidence;
    }

    /** Point estimate and Wilson 95 % interval, as fractions. */
    public static Map<String, Object> rate(int k, int n) {
        if (n == 0) {
            return Map.of("k", k, "n", n);
        }
        double z = 1.959964;
        double p = (double) k / n;
        double denom = 1 + z * z / n;
        double centre = (p + z * z / (2.0 * n)) / denom;
        double half = z * Math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n)) / denom;
        return Map.of("k", k, "n", n, "p", round(p),
                "wilson95", List.of(round(Math.max(0, centre - half)), round(Math.min(1, centre + half))));
    }

    private static double round(double v) {
        return Math.round(v * 1e6) / 1e6;
    }

    public static String json(Map<String, Object> result) throws Exception {
        return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(result);
    }
}

package ru.moon.checker.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ru.moon.checker.core.TestResults;
import ru.moon.checker.signatures.SignatureLoader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class BenignCorpusTest {

    @Test
    void wilsonIntervalsMatchTheTextbook() {
        // 0 of 1000: the upper bound is about 0.38 %, not 0 — a clean run is not proof of zero
        @SuppressWarnings("unchecked")
        List<Double> ci = (List<Double>) BenignCorpus.rate(0, 1000).get("wilson95");
        assertEquals(0.0, ci.get(0), 1e-9);
        assertEquals(0.003827, ci.get(1), 2e-6);
        @SuppressWarnings("unchecked")
        List<Double> half = (List<Double>) BenignCorpus.rate(50, 100).get("wilson95");
        assertEquals(0.4038, half.get(0), 1e-4);
        assertEquals(0.5962, half.get(1), 1e-4);
    }

    @Test
    void everyFileIsCountedAndAStreamBelongsToItsFile(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("readme.txt"), "hello");
        Files.writeString(dir.resolve("nixware_notes.txt"), "a name rule fires on this legitimate file");
        Map<String, Object> r = BenignCorpus.evaluate(dir, 100, SignatureLoader.load(null).db(), TestResults.ENV);
        assertEquals(2, r.get("filesInspected"));
        @SuppressWarnings("unchecked")
        Map<String, Object> moving = (Map<String, Object>) r.get("filesMovingOutcome");
        assertEquals(1, moving.get("n"));
        assertEquals("C:\\x\\notes.txt", BenignCorpus.stripStream("C:\\x\\notes.txt:payload"));
        assertEquals("C:\\x\\notes.txt", BenignCorpus.stripStream("C:\\x\\notes.txt"));
    }
}

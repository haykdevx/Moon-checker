package ru.moon.checker.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScoreCalculatorTest {

    private Finding f(Severity s) {
        return Finding.builder(Category.FILES, s, "t").module("m").build();
    }

    @Test
    void noFindingsIsClean() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(List.of());
        assertEquals(0, score.value());
        assertEquals(Verdict.CLEAN, score.verdict());
    }

    @Test
    void singleCriticalIsAlwaysCheat() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(List.of(f(Severity.CRITICAL)));
        assertEquals(100, score.value());
        assertEquals(Verdict.CHEAT, score.verdict());
    }

    @Test
    void oneHighIsSuspiciousNotCheat() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(List.of(f(Severity.HIGH)));
        assertEquals(30, score.value());
        assertEquals(Verdict.SUSPICIOUS, score.verdict());
    }

    @Test
    void multipleHighsReachCheat() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(
                List.of(f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH)));
        assertTrue(score.value() >= ScoreCalculator.CHEAT_THRESHOLD);
        assertEquals(Verdict.CHEAT, score.verdict());
    }

    @Test
    void lowInfoStayClean() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(
                List.of(f(Severity.LOW), f(Severity.INFO), f(Severity.INFO)));
        assertEquals(Verdict.CLEAN, score.verdict());
    }

    @Test
    void aSingleMediumKeywordCannotForceACheatVerdict() {
        // Regression: a bash process whose command line contained the word
        // "bhop" (a MEDIUM rule) was reported CRITICAL as a running cheat,
        // producing CHEAT/100 on a clean machine. Weak rules must stay weak.
        var db = ru.moon.checker.signatures.SignatureLoader.load(null).db();
        var bhop = db.matchCheatName("bhop").orElseThrow();
        assertEquals(Severity.MEDIUM, bhop.severity(), "bhop must remain a MEDIUM hint");

        ScoreCalculator.Score score = ScoreCalculator.calculate(List.of(f(bhop.severity())));
        assertNotEquals(Verdict.CHEAT, score.verdict(),
                "one MEDIUM keyword must never reach a CHEAT verdict");
    }

    @Test
    void dualUseToolsAreOnlyContext() {
        // CS2-scoped: Cheat Engine & co are context, never decisive on their own
        var db = ru.moon.checker.signatures.SignatureLoader.load(null).db();
        for (String tool : List.of("cheatengine", "x64dbg", "processhacker")) {
            var rule = db.matchCheatName(tool + ".exe").orElseThrow(() -> new AssertionError(tool));
            assertEquals(Severity.LOW, rule.severity(), tool + " must be LOW (context only)");
        }
    }

    @Test
    void scoreCapsAt100() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(
                List.of(f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH)));
        assertEquals(100, score.value());
    }
}

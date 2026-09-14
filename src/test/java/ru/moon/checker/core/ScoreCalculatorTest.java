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
    void scoreCapsAt100() {
        ScoreCalculator.Score score = ScoreCalculator.calculate(
                List.of(f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH), f(Severity.HIGH)));
        assertEquals(100, score.value());
    }
}

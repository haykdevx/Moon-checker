package ru.moon.checker.core;

import java.util.List;

/**
 * Turns a set of findings into a 0-100 score and a verdict.
 *
 * <p>Rules:
 * <ul>
 *   <li>Any single {@link Severity#CRITICAL} finding (hash match, running
 *       cheat process, manual-mapper driver...) forces {@link Verdict#CHEAT}
 *       and a score of 100 — hard evidence needs no accumulation.</li>
 *   <li>Otherwise the score is the summed weight of all findings, capped at
 *       100, and the verdict comes from {@link #SUSPICIOUS_THRESHOLD} /
 *       {@link #CHEAT_THRESHOLD}.</li>
 * </ul>
 */
public final class ScoreCalculator {

    public static final int SUSPICIOUS_THRESHOLD = 30;
    public static final int CHEAT_THRESHOLD = 70;

    private ScoreCalculator() {
    }

    public record Score(int value, Verdict verdict) {
    }

    public static Score calculate(List<Finding> findings) {
        boolean hasCritical = false;
        long sum = 0;
        for (Finding f : findings) {
            if (f.severity() == Severity.CRITICAL) {
                hasCritical = true;
            }
            sum += f.weight();
        }
        if (hasCritical) {
            return new Score(100, Verdict.CHEAT);
        }
        int score = (int) Math.min(100, sum);
        Verdict v;
        if (score >= CHEAT_THRESHOLD) {
            v = Verdict.CHEAT;
        } else if (score >= SUSPICIOUS_THRESHOLD) {
            v = Verdict.SUSPICIOUS;
        } else {
            v = Verdict.CLEAN;
        }
        return new Score(score, v);
    }
}

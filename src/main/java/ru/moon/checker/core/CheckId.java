package ru.moon.checker.core;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * A per-run identifier shown on screen so the admin can tie the live screen
 * share to a specific check. Format: {@code MOON-<date>-<random>}, e.g.
 * {@code MOON-260913-7F3A}.
 */
public record CheckId(String value, LocalDateTime startedAt) {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyMMdd");

    public static CheckId generate() {
        LocalDateTime now = LocalDateTime.now();
        StringBuilder sb = new StringBuilder("MOON-");
        sb.append(now.format(DATE)).append('-');
        for (int i = 0; i < 4; i++) {
            sb.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]);
        }
        return new CheckId(sb.toString(), now);
    }
}

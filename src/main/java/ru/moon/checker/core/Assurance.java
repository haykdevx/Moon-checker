package ru.moon.checker.core;

import java.util.List;

/**
 * Why (or how far) the report itself should be trusted — independent of what
 * it found. The client can only judge what it sees about itself; the server adds
 * its own signals (trusted build list, timing, session binding).
 *
 * @param level   overall level
 * @param reasons what lowered it, as stable codes plus text
 */
public record Assurance(Level level, List<Note> reasons) {

    public enum Level { STANDARD, REDUCED, LOW }

    public record Note(String code, String text) {
    }

    public Assurance {
        reasons = List.copyOf(reasons);
    }
}

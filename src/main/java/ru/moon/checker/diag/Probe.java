package ru.moon.checker.diag;

/**
 * Result of one self-test probe.
 *
 * @param id     stable identifier, e.g. {@code mft.enumerate}
 * @param status outcome
 * @param detail what was observed (counts, paths, error text)
 * @param millis how long the probe took
 */
public record Probe(String id, Status status, String detail, long millis) {

    public enum Status {
        /** The primitive works as the modules expect. */
        PASS,
        /** The primitive is broken: a module relying on it would silently miss evidence. */
        FAIL,
        /** Not applicable here (no driver loaded, feature absent on this edition...). */
        SKIP,
        /** Informational observation, neither good nor bad. */
        INFO
    }

    /** A probe body: returns its verdict, may throw (recorded as FAIL). */
    @FunctionalInterface
    public interface Body {
        Outcome run() throws Exception;
    }

    /** Status + detail produced by a {@link Body}. */
    public record Outcome(Status status, String detail) {
        public static Outcome pass(String detail) {
            return new Outcome(Status.PASS, detail);
        }

        public static Outcome fail(String detail) {
            return new Outcome(Status.FAIL, detail);
        }

        public static Outcome skip(String detail) {
            return new Outcome(Status.SKIP, detail);
        }

        public static Outcome info(String detail) {
            return new Outcome(Status.INFO, detail);
        }

        /** PASS when {@code ok}, otherwise FAIL, with the same detail. */
        public static Outcome check(boolean ok, String detail) {
            return new Outcome(ok ? Status.PASS : Status.FAIL, detail);
        }
    }

    /** Run {@code body}, timing it and converting any throwable into a FAIL. */
    public static Probe run(String id, Body body) {
        long t0 = System.nanoTime();
        Outcome o;
        try {
            o = body.run();
        } catch (Throwable t) {
            o = Outcome.fail(t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        return new Probe(id, o.status(), o.detail(), (System.nanoTime() - t0) / 1_000_000);
    }
}

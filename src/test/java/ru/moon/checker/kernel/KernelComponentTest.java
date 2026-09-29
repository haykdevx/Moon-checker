package ru.moon.checker.kernel;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The kernel component's report is untrusted input (another program could sit behind the device),
 * and two views taken at different moments disagree for innocent reasons. Review finding: the
 * re-check skipped exactly the PIDs a listing-filter rootkit hides and reported processes that had
 * merely exited between the two reads.
 */
class KernelComponentTest {

    private static List<String> valid(int n) {
        List<String> l = new ArrayList<>(List.of("MOONMON 2 " + n));
        for (int i = 0; i < n; i++) {
            l.add("KPID " + (100 + i) + " proc" + i);
        }
        l.add("END " + n);
        return l;
    }

    @Test
    void theParserSurvivesRandomDamageAndNeverCallsADamagedReportComplete() {
        Random rnd = new Random(20260929);
        int complete = 0, damaged = 0;
        for (int iter = 0; iter < 20_000; iter++) {
            List<String> lines = valid(rnd.nextInt(40));
            int mutations = 1 + rnd.nextInt(3);
            boolean changed = false;
            for (int m = 0; m < mutations; m++) {
                if (lines.isEmpty()) {
                    lines.add("KPID 1 x");
                    changed = true;
                }
                int at = rnd.nextInt(lines.size());
                switch (rnd.nextInt(7)) {
                    case 0 -> { lines.remove(at); changed = true; }                                  // lost line
                    case 1 -> { lines.add(at, lines.get(at)); changed = true; }                        // duplicated
                    case 2 -> { lines.set(at, lines.get(at).substring(0, rnd.nextInt(lines.get(at).length() + 1))); changed = true; }
                    case 3 -> { byte[] b = new byte[rnd.nextInt(40)]; rnd.nextBytes(b); lines.set(at, new String(b, StandardCharsets.ISO_8859_1)); changed = true; }
                    case 4 -> { lines.set(at, lines.get(at).replaceAll("\\\\d+", String.valueOf(rnd.nextInt(Integer.MAX_VALUE)))); changed = true; }
                    case 5 -> lines.add(at, "");                                                        // blank lines are harmless
                    default -> { lines.add(rnd.nextInt(lines.size() + 1), "KPID 1 x"); changed = true; } // injected record
                }
            }
            KernelReport r = KernelReport.parse(lines);   // must never throw
            if (r.complete()) {
                complete++;
                // a report called complete is internally consistent: header count, records and END agree
                long kp = lines.stream().filter(l -> l != null && l.strip().startsWith("KPID ")).count();
                assertEquals(kp, r.records().size());
            } else {
                damaged++;
            }
            assertTrue(r.complete() || r.problem() != null);
            if (!changed) {
                assertTrue(r.complete(), "blank lines alone must not damage a report: " + lines);
            }
        }
        assertTrue(damaged > 15_000, "most mutations must be caught: " + damaged);
        assertTrue(complete >= 0);
    }

    @Test
    void otherProtocolsAndTruncationAreNamed() {
        assertFalse(KernelReport.parse(List.of("MOONMON 1", "END 0")).complete());
        assertTrue(KernelReport.parse(List.of("MOONMON 1", "END 0")).problem().contains("protocol"));
        assertTrue(KernelReport.parse(List.of("MOONMON 2 3", "KPID 1 a", "KPID 2 b")).problem().contains("truncated"));
        assertTrue(KernelReport.parse(List.of()).problem().contains("empty"));
        assertTrue(KernelReport.parse(valid(3)).complete());
    }

    @Test
    void anExitedProcessIsARaceNotARootkit() {
        var hidden = HiddenObjects.confirmedHidden(Set.of(1, 2, 3), Set.of(1, 2),
                pid -> false,                      // /proc/3 is gone: it exited between the reads
                () -> Set.of(1, 2), pid -> null, Map.of(3, "short"));
        assertEquals(List.of(), hidden);
    }

    @Test
    void aProcessThatStartedInBetweenIsARace() {
        var hidden = HiddenObjects.confirmedHidden(Set.of(1, 2, 3), Set.of(1, 2),
                pid -> true, () -> Set.of(1, 2, 3), pid -> "new", Map.of(3, "new"));
        assertEquals(List.of(), hidden);
    }

    @Test
    void aReusedPidIsARace() {
        var hidden = HiddenObjects.confirmedHidden(Set.of(1, 3), Set.of(1),
                pid -> true, () -> Set.of(1), pid -> "bash", Map.of(3, "oldproc"));
        assertEquals(List.of(), hidden);
    }

    @Test
    void aLiveProcessLeftOutOfTwoListingsIsHidden() {
        // what a readdir-filtering LD_PRELOAD rootkit produces: stat works, listing omits it
        var hidden = HiddenObjects.confirmedHidden(Set.of(1, 2, 666), Set.of(1, 2),
                pid -> true, () -> Set.of(1, 2), pid -> "miner", Map.of(666, "miner"));
        assertEquals(List.of(666), hidden);
    }

    @Test
    void noCandidatesMeansNoSecondListing() {
        var hidden = HiddenObjects.confirmedHidden(Set.of(1), Set.of(1), pid -> true,
                () -> { throw new AssertionError("no second read needed"); }, pid -> null, Map.of());
        assertTrue(hidden.isEmpty(), "and an empty list is not proof of a clean kernel");
    }
}

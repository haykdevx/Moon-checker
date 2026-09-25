package ru.moon.checker.diag;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.EnvironmentInfo;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DiagnosticsTest {

    @Test
    void throwingProbeBecomesFailNotCrash() {
        Probe p = Probe.run("boom", () -> {
            throw new IllegalStateException("api missing");
        });
        assertEquals(Probe.Status.FAIL, p.status());
        assertTrue(p.detail().contains("api missing"));
    }

    @Test
    void exitCodeReflectsAnyFailure() {
        Probe pass = new Probe("a", Probe.Status.PASS, "", 1);
        Probe skip = new Probe("b", Probe.Status.SKIP, "", 1);
        Probe fail = new Probe("c", Probe.Status.FAIL, "", 1);
        assertEquals(Diagnostics.EXIT_OK, Diagnostics.exitCode(List.of(pass, skip)));
        assertEquals(Diagnostics.EXIT_FAILED, Diagnostics.exitCode(List.of(pass, fail)));
    }

    @Test
    void reportListsEveryProbe() throws Exception {
        List<Probe> probes = List.of(new Probe("mft.enumerate", Probe.Status.PASS, "812345 records", 900),
                new Probe("ads.detect", Probe.Status.FAIL, "stream not listed", 12));
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Diagnostics.print(probes, new PrintStream(buf, true, "UTF-8"));
        String text = buf.toString("UTF-8");
        assertTrue(text.contains("[FAIL] ads.detect"));
        assertTrue(text.contains("1 passed, 1 failed"));
        String json = Diagnostics.toJson(new EnvironmentInfo("pc", "Windows 11", "u", true, "1.0.0", "h", "jvm"), probes);
        assertTrue(json.contains("\"schema\" : \"moon-diagnostics/1\""));
        assertTrue(json.contains("\"id\" : \"mft.enumerate\""));
    }
}

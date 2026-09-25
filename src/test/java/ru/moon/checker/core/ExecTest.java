package ru.moon.checker.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExecTest {

    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void capturesUtf8OutputAndExitCode() {
        Exec.Result r = Exec.run(List.of("sh", "-c", "printf 'Игрок\\n'; exit 3"), Duration.ofSeconds(10));
        assertEquals(3, r.exitCode());
        assertFalse(r.timedOut());
        assertNull(r.error());
        assertEquals("Игрок", r.output().strip());
        assertFalse(r.ok());
    }

    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void hungChildIsKilledAtTheDeadline() {
        long t0 = System.nanoTime();
        // the child keeps its stdout open: a blocking readAllBytes() would hang here
        Exec.Result r = Exec.run(List.of("sh", "-c", "echo started; sleep 30"), Duration.ofMillis(400));
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(r.timedOut());
        assertEquals(-1, r.exitCode());
        assertTrue(ms < 5_000, "took " + ms + "ms");
        assertTrue(r.output().contains("started"));
    }

    @Test
    void missingBinaryReportsErrorInsteadOfThrowing() {
        Exec.Result r = Exec.run(List.of("moon-no-such-binary-xyz"), Duration.ofSeconds(2));
        assertNotNull(r.error());
        assertFalse(r.ok());
    }

    @Test
    void powershellPayloadIsUtf16LeBase64WithUtf8Prelude() {
        String script = "Get-MpThreat | % { 'THREAT|' + $_.ThreatName } # \"quotes\" и кириллица";
        String decoded = new String(Base64.getDecoder().decode(Exec.encodePowershell(script)),
                StandardCharsets.UTF_16LE);
        assertTrue(decoded.startsWith("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"));
        assertTrue(decoded.endsWith(script));
    }
}

package ru.moon.checker.cli;

import org.junit.jupiter.api.Test;
import ru.moon.checker.checks.ModuleRegistry;
import ru.moon.checker.core.CheckModule;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CliModulesTest {

    @Test
    void moduleFilterKeepsOnlyKnownIds() {
        List<CheckModule> all = ModuleRegistry.forCurrentOs();
        assertSame(all, Cli.selectModules(all, null));
        assertSame(all, Cli.selectModules(all, " "));
        String first = all.get(0).id();
        List<CheckModule> one = Cli.selectModules(all, " " + first + " ,");
        assertEquals(1, one.size());
        assertEquals(first, one.get(0).id());
        assertNull(Cli.selectModules(all, first + ",no-such-module"));
    }

    @Test
    void panelFlagsDoNotHijackTheGui() {
        assertFalse(Cli.handles(new String[]{"--server", "https://moon.example.org"}));
        assertFalse(Cli.handles(new String[]{"--offline"}));
        assertTrue(Cli.handles(new String[]{"--cli", "--code", "K7MQ-4X2P"}));
    }
}

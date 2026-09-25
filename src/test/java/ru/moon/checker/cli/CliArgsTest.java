package ru.moon.checker.cli;

import org.junit.jupiter.api.Test;
import ru.moon.checker.checks.ModuleRegistry;
import ru.moon.checker.core.CheckModule;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CliArgsTest {

    @Test
    void noArgumentsMeansGui() {
        CliArgs a = CliArgs.parse(new String[0]);
        assertEquals(CliArgs.Mode.GUI, a.mode());
        assertNull(a.error());
    }

    @Test
    void headlessWithOptions() {
        CliArgs a = CliArgs.parse(new String[]{"--headless", "--out", "reports", "--lang", "EN", "--modules", "files, kernel"});
        assertNull(a.error());
        assertEquals(CliArgs.Mode.HEADLESS, a.mode());
        assertEquals(Path.of("reports"), a.out());
        assertEquals("en", a.lang());
        assertEquals(2, a.moduleList().size());
        assertTrue(a.modules().contains("kernel"));
    }

    @Test
    void invalidCombinationsAreRejected() {
        assertNotNull(CliArgs.parse(new String[]{"--headless", "--diagnose"}).error());
        assertNotNull(CliArgs.parse(new String[]{"--out"}).error());
        assertNotNull(CliArgs.parse(new String[]{"--lang", "de", "--headless"}).error());
        assertNotNull(CliArgs.parse(new String[]{"--diagnose", "--modules", "files"}).error());
        assertNotNull(CliArgs.parse(new String[]{"--bogus"}).error());
        assertEquals(CliArgs.Mode.DIAGNOSE, CliArgs.parse(new String[]{"--diagnose", "--diagnose"}).mode());
    }

    @Test
    void panelFlags() {
        CliArgs gui = CliArgs.parse(new String[]{"--server", "https://moon.example.org"});
        assertNull(gui.error());
        assertEquals(CliArgs.Mode.GUI, gui.mode(), "--server alone still starts the GUI");
        assertEquals("https://moon.example.org", gui.server());

        CliArgs off = CliArgs.parse(new String[]{"--offline"});
        assertEquals(CliArgs.Mode.GUI, off.mode());
        assertTrue(off.offline());

        CliArgs head = CliArgs.parse(new String[]{"--headless", "--code", "K7MQ-4X2P"});
        assertNull(head.error());
        assertEquals("K7MQ-4X2P", head.code());

        assertNotNull(CliArgs.parse(new String[]{"--code", "K7MQ-4X2P"}).error(), "GUI asks for the code itself");
        assertNotNull(CliArgs.parse(new String[]{"--headless", "--offline", "--code", "X"}).error());
        assertNotNull(CliArgs.parse(new String[]{"--offline", "--server", "https://x"}).error());
        assertNotNull(CliArgs.parse(new String[]{"--diagnose", "--server", "https://x"}).error());
    }

    @Test
    void badArgumentsExitWithUsageCode() {
        assertEquals(Cli.EXIT_USAGE, Cli.run(CliArgs.parse(new String[]{"--nope"})));
        assertEquals(0, Cli.run(CliArgs.parse(new String[]{"--help"})));
    }

    @Test
    void moduleSelectionRejectsUnknownIds() {
        List<CheckModule> all = ModuleRegistry.windowsModules();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream err = new PrintStream(buf);
        assertNull(HeadlessScan.select(all, List.of("files", "nope"), err));
        assertTrue(buf.toString().contains("nope"));
        assertEquals(1, HeadlessScan.select(all, List.of("kernel"), err).size());
        assertSame(all, HeadlessScan.select(all, List.of(), err));
    }
}

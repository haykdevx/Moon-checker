package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.CheckModule;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ModuleRegistryTest {

    private void assertUniqueIds(List<CheckModule> modules) {
        Set<String> ids = new HashSet<>();
        for (CheckModule m : modules) {
            assertTrue(ids.add(m.id()), "duplicate module id: " + m.id());
            assertNotNull(m.category());
        }
    }

    @Test
    void windowsSuiteHasUniqueIdsAndKernel() {
        var mods = ModuleRegistry.windowsModules();
        assertUniqueIds(mods);
        assertTrue(mods.stream().anyMatch(m -> m.id().equals("kernel")));
        assertTrue(mods.size() >= 11);
    }

    @Test
    void linuxSuiteHasUniqueIdsAndRunsCrossPlatform() {
        var mods = ModuleRegistry.linuxModules();
        assertUniqueIds(mods);
        assertTrue(mods.stream().anyMatch(m -> m.id().equals("kernel")));
        assertTrue(mods.stream().anyMatch(m -> m.id().equals("linuxproc")));
        // Linux modules must not be gated as windows-only
        for (CheckModule m : mods) {
            assertFalse(m.windowsOnly(), m.id() + " should not be windowsOnly");
        }
    }

    @Test
    void forCurrentOsIsNonEmpty() {
        assertFalse(ModuleRegistry.forCurrentOs().isEmpty());
    }

    @Test
    void everyModuleUnionCoversBoth() {
        var every = ModuleRegistry.everyModule();
        assertTrue(every.stream().anyMatch(m -> m.id().equals("files")));      // windows
        assertTrue(every.stream().anyMatch(m -> m.id().equals("linuxfiles"))); // linux
    }
}

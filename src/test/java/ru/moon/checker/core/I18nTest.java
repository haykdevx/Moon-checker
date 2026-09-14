package ru.moon.checker.core;

import org.junit.jupiter.api.Test;
import ru.moon.checker.checks.ModuleRegistry;

import static org.junit.jupiter.api.Assertions.*;

class I18nTest {

    @Test
    void bothBundlesResolveEveryModuleAndCategoryKey() {
        for (var locale : new java.util.Locale[]{I18n.RUSSIAN, I18n.ENGLISH}) {
            I18n.setLocale(locale);
            for (var m : ModuleRegistry.everyModule()) {
                assertFalse(m.displayName().startsWith("module."),
                        "module name unresolved for " + m.id() + " in " + locale);
            }
            for (Category c : Category.values()) {
                assertFalse(I18n.t(c.key()).equals(c.key()), "category key unresolved: " + c.key());
            }
            for (ModuleStatus s : ModuleStatus.values()) {
                assertFalse(I18n.t(s.key()).equals(s.key()), "status key unresolved: " + s.key());
            }
        }
        I18n.setLocale(I18n.RUSSIAN);
    }

    @Test
    void missingKeyReturnsKey() {
        assertEquals("no.such.key.xyz", I18n.t("no.such.key.xyz"));
    }

    @Test
    void messageFormatArgsWork() {
        I18n.setLocale(I18n.ENGLISH);
        String s = I18n.t("log.mft", "C");
        assertTrue(s.contains("C"));
        assertFalse(s.contains("{0}"));
    }
}

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

    @Test
    void russianCountsUseTheRightWordForm() {
        java.util.Locale ru = I18n.RUSSIAN;
        assertEquals("one", I18n.pluralForm(ru, 1));
        assertEquals("one", I18n.pluralForm(ru, 21));
        assertEquals("few", I18n.pluralForm(ru, 2));
        assertEquals("few", I18n.pluralForm(ru, 34));
        assertEquals("many", I18n.pluralForm(ru, 5));
        assertEquals("many", I18n.pluralForm(ru, 11));
        assertEquals("many", I18n.pluralForm(ru, 12));
        assertEquals("many", I18n.pluralForm(ru, 111));
        assertEquals("one", I18n.pluralForm(I18n.ENGLISH, 1));
        assertEquals("many", I18n.pluralForm(I18n.ENGLISH, 2));
        I18n.setLocale(ru);
        try {
            assertEquals("1 улика", I18n.plural("scan.evidence", 1));
            assertEquals("3 улики", I18n.plural("scan.evidence", 3));
            assertEquals("12 заметок", I18n.plural("scan.notes", 12));
        } finally {
            I18n.setLocale(I18n.RUSSIAN);
        }
    }

    @Test
    void onlyEvidenceMovesTheOutcome() {
        Finding context = Finding.builder(Category.CS2, Severity.INFO, "CS2 is not running").module("cs2live").build();
        Finding weak = Finding.builder(Category.CS2, Severity.LOW, "unsigned").module("cs2").build();
        Finding setting = Finding.builder(Category.CS2, Severity.HIGH, "x").module("k")
                .kind(EvidenceKind.CONFIGURATION).build();
        Finding strong = Finding.builder(Category.CS2, Severity.HIGH, "dll").module("cs2live").build();
        assertFalse(context.movesOutcome());
        assertFalse(weak.movesOutcome());
        assertFalse(setting.movesOutcome());
        assertTrue(strong.movesOutcome());
    }
}

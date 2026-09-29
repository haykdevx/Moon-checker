package ru.moon.checker.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.*;

/** The player reads the checker in Russian; nothing may be missing or garbled in either language. */
class MessagesTest {

    @AfterEach
    void back() {
        I18n.setLocale(I18n.RUSSIAN);
    }

    private static Properties load(String name) throws Exception {
        Properties p = new Properties();
        try (InputStream in = MessagesTest.class.getResourceAsStream("/i18n/" + name)) {
            assertNotNull(in, name);
            p.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return p;
    }

    @Test
    void russianAndEnglishHaveTheSameKeys() throws Exception {
        Set<String> ru = new TreeSet<>(load("messages_ru.properties").stringPropertyNames());
        Set<String> en = new TreeSet<>(load("messages_en.properties").stringPropertyNames());
        Set<String> onlyRu = new TreeSet<>(ru);
        onlyRu.removeAll(en);
        Set<String> onlyEn = new TreeSet<>(en);
        onlyEn.removeAll(ru);
        assertTrue(onlyRu.isEmpty() && onlyEn.isEmpty(), "only in ru: " + onlyRu + "; only in en: " + onlyEn);
    }

    @Test
    void anApostropheDoesNotSwallowTheRestOfAMessage() {
        I18n.setLocale(Locale.ENGLISH);
        String tls = I18n.t("net.err.tls", "moon.example.org");
        assertTrue(tls.contains("PC's date and time"), tls);
        assertTrue(tls.contains("moon.example.org"), tls);
    }

    @Test
    void networkProblemsAreExplainedInRussian() {
        for (String code : new String[]{"dns", "timeout", "tls", "proxy", "captive", "unreachable", "network"}) {
            String text = I18n.t("net.err." + code, "moon.example.org");
            assertFalse(text.startsWith("net.err."), code + " has no message");
            assertTrue(text.chars().anyMatch(c -> Character.UnicodeBlock.of(c) == Character.UnicodeBlock.CYRILLIC),
                    code + " is not Russian: " + text);
        }
    }
}

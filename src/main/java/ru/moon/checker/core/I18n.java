package ru.moon.checker.core;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Tiny localisation helper backed by {@code i18n/messages_*.properties}.
 * Russian is the default; the UI can switch to English at runtime. Missing
 * keys fall back to the key itself so nothing crashes on a typo.
 */
public final class I18n {

    public static final Locale RUSSIAN = new Locale("ru");
    public static final Locale ENGLISH = Locale.ENGLISH;

    private static volatile ResourceBundle bundle = load(RUSSIAN);
    private static volatile Locale locale = RUSSIAN;

    private I18n() {
    }

    private static ResourceBundle load(Locale l) {
        return ResourceBundle.getBundle("i18n.messages", l);
    }

    public static synchronized void setLocale(Locale l) {
        locale = l;
        bundle = load(l);
    }

    public static Locale locale() {
        return locale;
    }

    public static String t(String key) {
        try {
            return bundle.getString(key);
        } catch (MissingResourceException e) {
            return key;
        }
    }

    public static String t(String key, Object... args) {
        String pattern = t(key);
        try {
            return new MessageFormat(pattern, locale).format(args);
        } catch (IllegalArgumentException e) {
            return pattern;
        }
    }
}

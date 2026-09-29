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

    /**
     * "{n} word" with the word in the right form: Russian has three (1 улика, 2 улики, 5 улик,
     * 21 улика, 12 улик), English two. Keys: key.one, key.few, key.many.
     */
    public static String plural(String key, long n) {
        return n + " " + t(key + "." + pluralForm(locale, n));
    }

    static String pluralForm(Locale l, long n) {
        long abs = Math.abs(n);
        if (!"ru".equals(l.getLanguage())) {
            return abs == 1 ? "one" : "many";
        }
        long d = abs % 10, dd = abs % 100;
        if (d == 1 && dd != 11) {
            return "one";
        }
        return d >= 2 && d <= 4 && (dd < 12 || dd > 14) ? "few" : "many";
    }

    public static String t(String key, Object... args) {
        String pattern = t(key);
        try {
            // MessageFormat reads ' as a quote: "PC's" would swallow the rest of the text
            return new MessageFormat(pattern.replace("'", "''"), locale).format(args);
        } catch (IllegalArgumentException e) {
            return pattern;
        }
    }
}

package ru.moon.checker.core;

/**
 * Logical grouping a {@link CheckModule} belongs to. Used to organise the
 * results table and the HTML report. The {@code key} is a stable i18n lookup
 * key; display names come from the message bundles.
 */
public enum Category {
    FILES("cat.files"),
    DELETED("cat.deleted"),
    EXECUTION("cat.execution"),
    PERSISTENCE("cat.persistence"),
    KERNEL("cat.kernel"),
    ENVIRONMENT("cat.environment"),
    BROWSER("cat.browser"),
    STEAM("cat.steam"),
    PERIPHERALS("cat.peripherals"),
    DEFENDER("cat.defender"),
    ANTIFORENSIC("cat.antiforensic");

    private final String key;

    Category(String key) {
        this.key = key;
    }

    public String key() {
        return key;
    }
}

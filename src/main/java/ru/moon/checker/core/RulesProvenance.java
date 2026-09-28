package ru.moon.checker.core;

/**
 * Where the detection rules of a scan came from. Reported with every scan, because
 * a scan with replaced or empty rules would otherwise look like a clean one.
 *
 * @param origin {@code bundled} (inside the signed-off build), {@code signed-override}
 *               (a rule file next to the checker with a valid Moon signature), or
 *               {@code none} (no usable rules)
 * @param digest SHA-256 of the exact rule bytes used
 * @param count  number of rules loaded
 * @param note   anything the reviewer should know (e.g. an unsigned override was ignored), or null
 */
public record RulesProvenance(String origin, String digest, int count, String note) {

    public static RulesProvenance unspecified() {
        return new RulesProvenance("unspecified", "", 0, null);
    }

    public boolean trusted() {
        return origin.equals("bundled") || origin.equals("signed-override");
    }
}

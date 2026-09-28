package ru.moon.checker.core;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * What the scan actually managed to inspect. Kept separate from the evidence:
 * "nothing found" only means something when this says the inspection ran.
 *
 * @param modules           final status of every collector that was scheduled
 * @param required          collectors a trustworthy result depends on on this platform
 * @param elevated          ran with administrator / root rights
 * @param platformSupported the OS/architecture is one the checker is validated on
 * @param platformNote      why not, when unsupported
 * @param errors            collector id → what went wrong (exception, time budget)
 * @param rules             the detection rules the collectors matched against
 */
public record Coverage(
        Map<String, ModuleStatus> modules,
        Set<String> required,
        boolean elevated,
        boolean platformSupported,
        String platformNote,
        Map<String, String> errors,
        RulesProvenance rules
) {
    /** Coverage with a trusted, non-empty rule set (tests and callers that do not track rules). */
    public Coverage(Map<String, ModuleStatus> modules, Set<String> required, boolean elevated,
                    boolean platformSupported, String platformNote, Map<String, String> errors) {
        this(modules, required, elevated, platformSupported, platformNote, errors,
                new RulesProvenance("bundled", "", 1, null));
    }

    public Coverage {
        modules = Map.copyOf(new LinkedHashMap<>(modules));
        required = Set.copyOf(required);
        errors = Map.copyOf(errors);
    }

    /** Required collectors that did not finish (error, timeout, cancelled, skipped). */
    public List<String> missing() {
        Set<String> out = new TreeSet<>();
        for (String id : required) {
            if (modules.get(id) != ModuleStatus.OK) {
                out.add(id);
            }
        }
        return List.copyOf(out);
    }

    public long completed() {
        return required.stream().filter(id -> modules.get(id) == ModuleStatus.OK).count();
    }

    /** Rules were loaded from a trusted source and are not empty — otherwise nothing could match. */
    public boolean rulesOk() {
        return rules.count() > 0 && rules.trusted();
    }

    /** Every required collector finished with the rights it needs, against usable rules. */
    public boolean complete() {
        return elevated && platformSupported && rulesOk() && missing().isEmpty();
    }
}

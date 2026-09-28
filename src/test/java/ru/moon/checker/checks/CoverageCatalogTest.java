package ru.moon.checker.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import ru.moon.checker.core.CheckModule;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * coverage.json documents every collector and every explicitly named rule; the
 * coverage matrix and the panel's rules page are rendered from it. This test
 * keeps it from drifting away from the code.
 */
class CoverageCatalogTest {

    private static JsonNode catalog() throws Exception {
        try (InputStream in = CoverageCatalogTest.class.getResourceAsStream("/coverage.json")) {
            assertNotNull(in, "coverage.json must be on the classpath");
            return new ObjectMapper().readTree(in);
        }
    }

    @Test
    void everyCollectorIsDocumentedWithMatchingFacts() throws Exception {
        Map<String, JsonNode> byId = new HashMap<>();
        for (JsonNode m : catalog().get("modules")) {
            assertNull(byId.put(m.get("id").asText(), m), "duplicate entry " + m.get("id"));
            for (String field : new String[]{"name", "privileges", "window", "lookalikes", "blindSpots"}) {
                assertFalse(m.path(field).asText().isBlank(), m.get("id") + " lacks " + field);
            }
            assertTrue(m.path("sources").size() > 0 && m.path("kinds").size() > 0, m.get("id").asText());
        }
        Set<String> windows = ids(ModuleRegistry.windowsModules());
        Set<String> linux = ids(ModuleRegistry.linuxModules());
        for (CheckModule module : ModuleRegistry.everyModule()) {
            JsonNode entry = byId.get(module.id());
            assertNotNull(entry, "collector '" + module.id() + "' is not documented in coverage.json");
            assertEquals(module.required(), entry.get("required").asBoolean(), module.id() + " required flag");
            Set<String> platforms = new HashSet<>();
            entry.get("platforms").forEach(p -> platforms.add(p.asText()));
            assertEquals(windows.contains(module.id()), platforms.contains("windows"), module.id() + " windows");
            assertEquals(linux.contains(module.id()), platforms.contains("linux"), module.id() + " linux");
        }
        assertEquals(ids(ModuleRegistry.everyModule()), byId.keySet(), "no entries for collectors that do not exist");
    }

    @Test
    void everyExplicitRuleIdIsDocumented() throws Exception {
        Set<String> documented = new HashSet<>();
        for (JsonNode r : catalog().get("rules")) {
            documented.add(r.get("id").asText());
            assertFalse(r.path("meaning").asText().isBlank(), r.get("id").asText());
            assertFalse(r.path("limits").asText().isBlank(), r.get("id").asText());
        }
        Pattern rule = Pattern.compile("\\.rule\\(\\s*\"([a-z0-9]+:[a-z0-9-]+)\"");
        Pattern ternary = Pattern.compile("\\.rule\\([^;]*?\\?\\s*\"([a-z0-9]+:[a-z0-9-]+)\"\\s*:\\s*\"([a-z0-9]+:[a-z0-9-]+)\"");
        Set<String> used = new HashSet<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String src = Files.readString(p);
                Matcher m = rule.matcher(src);
                while (m.find()) {
                    used.add(m.group(1));
                }
                Matcher t = ternary.matcher(src);
                while (t.find()) {
                    used.add(t.group(1));
                    used.add(t.group(2));
                }
            }
        }
        used.remove("steam:account"); // plain account listing, documented under the steam collector
        assertFalse(used.isEmpty());
        used.removeAll(documented);
        assertTrue(used.isEmpty(), "rule ids used in code but missing from coverage.json: " + used);
    }

    private static Set<String> ids(java.util.List<CheckModule> modules) {
        Set<String> out = new HashSet<>();
        modules.forEach(m -> out.add(m.id()));
        return out;
    }
}

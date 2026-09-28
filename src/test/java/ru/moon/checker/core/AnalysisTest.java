package ru.moon.checker.core;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AnalysisTest {

    private Finding f(Severity sev, String module, String title, String detail, Instant when) {
        var b = Finding.builder(Category.FILES, sev, title).module(module).detail(detail);
        if (when != null) {
            b.when(when);
        }
        return b.build();
    }

    @Test
    void groupsEvidenceAboutTheSameCheatAcrossModules() {
        List<Finding> findings = List.of(
                f(Severity.CRITICAL, "files", "Cheat file", "Nixware CS2 cheat", null),
                f(Severity.HIGH, "execution", "Cheat ran", "Nixware CS2 cheat — Prefetch", null),
                f(Severity.HIGH, "amcache", "In AmCache", "Nixware CS2 cheat  [sha1=abc]", null),
                f(Severity.MEDIUM, "peripherals", "Macro tool", "Bloody mouse macro software", null));

        List<Analysis.Group> groups = Analysis.group(findings);
        assertEquals(2, groups.size());

        Analysis.Group first = groups.get(0);
        assertEquals("Nixware CS2 cheat", first.subject());
        assertEquals(3, first.count());
        assertEquals(Severity.CRITICAL, first.topSeverity());
        assertTrue(first.modules().containsAll(List.of("files", "execution", "amcache")));
        // strongest case sorts first
        assertEquals("Bloody mouse macro software", groups.get(1).subject());
    }

    @Test
    void mergesShortSubjectIntoTheMoreSpecificOne() {
        List<Finding> findings = List.of(
                f(Severity.CRITICAL, "files", "Cheat file", "Nixware CS2 cheat", null),
                f(Severity.HIGH, "persistence", "Auto-run", "Nixware — HKCU Run", null));
        List<Analysis.Group> groups = Analysis.group(findings);
        assertEquals(1, groups.size(), "‘Nixware’ and ‘Nixware CS2 cheat’ are one case");
        assertEquals(2, groups.get(0).count());
    }

    @Test
    void timelineIsMostRecentFirstAndDropsUndated() {
        Instant t1 = Instant.parse("2026-01-01T10:00:00Z");
        Instant t2 = Instant.parse("2026-01-01T12:00:00Z");
        List<Finding> findings = List.of(
                f(Severity.HIGH, "a", "older", "x", t1),
                f(Severity.HIGH, "b", "newer", "y", t2),
                f(Severity.HIGH, "c", "undated", "z", null));

        List<Finding> tl = Analysis.timeline(findings);
        assertEquals(2, tl.size());
        assertEquals("newer", tl.get(0).title());
        assertEquals("older", tl.get(1).title());
    }

    @Test
    void explainsADetectionWithTheEvidenceItCites() {
        I18n.setLocale(I18n.ENGLISH);
        Finding hash = TestResults.finding(EvidenceKind.DETECTION, Severity.CRITICAL, "files", "Sample cheat A");
        String text = Analysis.explain(TestResults.of(List.of(hash)));
        assertTrue(text.startsWith("VALIDATED DETECTION"), text);
        assertTrue(text.contains("exact hash: Sample cheat A"), text);
        assertTrue(text.contains("[E1]"), text);
        I18n.setLocale(I18n.RUSSIAN);
    }

    @Test
    void explainsReviewAndIncompleteScans() {
        I18n.setLocale(I18n.ENGLISH);
        ScanResult review = TestResults.of(List.of(
                TestResults.finding(EvidenceKind.INDICATOR, Severity.HIGH, "m", "Cleaner tool")));
        assertTrue(Analysis.explain(review).startsWith("REVIEW REQUIRED"));

        Coverage notElevated = new Coverage(Map.of("files", ModuleStatus.OK), java.util.Set.of("files"),
                false, true, "Windows 11", Map.of());
        String inc = Analysis.explain(TestResults.of(List.of(), notElevated, TestResults.ENV));
        assertTrue(inc.startsWith("INCOMPLETE SCAN"), inc);
        assertTrue(inc.contains("administrator"), inc);
        I18n.setLocale(I18n.RUSSIAN);
    }

    @Test
    void descriptionDetailsFallBackToTheTitle() {
        // real details seen in production that are descriptions, not subjects
        record Case(String detail, String title) { }
        var cases = List.of(
                new Case("Stream \"payload\" (204800 bytes)", "Скрытый поток данных (ADS)"),
                new Case("4 match(es): dwEntityList, dwViewMatrix", "Строки оффсетов CS2"),
                new Case("login=smurf_alt — VAC BANNED", "VAC-бан на аккаунте"),
                new Case("Windows event log cleared (id 1102)", "Журнал событий очищен"),
                new Case("entropy 7.86/8.0 in a user-writable location", "Упакованный бинарник"));
        for (var c : cases) {
            Finding f = Finding.builder(Category.FILES, Severity.HIGH, c.title())
                    .module("m").detail(c.detail()).build();
            assertEquals(c.title(), Analysis.subjectOf(f),
                    "description detail must not become a subject: " + c.detail());
        }
    }

    @Test
    void realSignatureLabelsAreUsedAsSubjects() {
        for (String label : List.of("Nixware CS2 cheat", "Fatality.win", "Bloody mouse macro software")) {
            Finding f = Finding.builder(Category.FILES, Severity.HIGH, "some title")
                    .module("m").detail(label).build();
            assertEquals(label, Analysis.subjectOf(f));
        }
    }

    @Test
    void subjectFallsBackToTitleWhenDetailMissing() {
        Finding noDetail = Finding.builder(Category.FILES, Severity.LOW, "Some finding")
                .module("m").build();
        assertEquals("Some finding", Analysis.subjectOf(noDetail));
    }

}

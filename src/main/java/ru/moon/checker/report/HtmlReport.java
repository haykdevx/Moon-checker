package ru.moon.checker.report;

import ru.moon.checker.core.Category;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.I18n;
import ru.moon.checker.core.ModuleStatus;
import ru.moon.checker.core.ScanResult;
import ru.moon.checker.core.Severity;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Renders a scan into a self-contained dark-themed HTML report in Moon colours.
 * No external resources, so it opens anywhere and can be archived per check.
 */
public final class HtmlReport {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private HtmlReport() {
    }

    public static String render(ScanResult r) {
        StringBuilder sb = new StringBuilder(1 << 16);
        sb.append("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">");
        sb.append("<title>Moon Check — ").append(esc(r.checkId().value())).append("</title>");
        sb.append("<style>").append(css()).append("</style></head><body>");

        sb.append("<div class=\"wrap\">");
        header(sb, r);
        verdict(sb, r);
        summary(sb, r);
        explanation(sb, r);
        evidenceGroups(sb, r);
        timeline(sb, r);
        findings(sb, r);
        modules(sb, r);
        String canonSha = ru.moon.checker.core.Integrity.sha256Hex(JsonReport.canonicalBytes(r));
        sb.append("<footer>Moon Checker • cs2-moon.ru • ")
          .append(esc(r.signatureOrigin())).append(" • ")
          .append("отчёт создан ").append(TS.format(r.finishedAt()))
          .append("<br>Код проверки / Verification: <b>").append(esc(JsonReport.verificationCode(r)))
          .append("</b> • SHA-256 ").append(canonSha.isEmpty() ? "—" : canonSha.substring(0, 32))
          .append("… • целостность подтверждается сервером")
          .append("</footer>");
        sb.append("</div></body></html>");
        return sb.toString();
    }

    private static void header(StringBuilder sb, ScanResult r) {
        var e = r.env();
        sb.append("<div class=\"head\"><div class=\"logo\">MOON<span>CHECK</span></div>");
        sb.append("<table class=\"meta\">");
        row(sb, "Check ID", r.checkId().value());
        row(sb, "PC / ПК", e.hostname());
        row(sb, "Пользователь", e.userName());
        row(sb, "ОС", e.osName());
        row(sb, "Админ-права", e.elevated() ? "да" : "НЕТ");
        row(sb, "Версия / хеш", e.appVersion() + " / " + e.selfHash());
        row(sb, "Длительность", r.duration().toSeconds() + " c");
        row(sb, "Код проверки", JsonReport.verificationCode(r));
        sb.append("</table></div>");
    }

    private static void verdict(StringBuilder sb, ScanResult r) {
        sb.append("<div class=\"verdict\" style=\"border-color:").append(r.verdict().color()).append("\">");
        sb.append("<div class=\"vlabel\" style=\"color:").append(r.verdict().color()).append("\">")
          .append(verdictText(r)).append("</div>");
        sb.append("<div class=\"score\">").append(r.score()).append("<span>/100</span></div>");
        sb.append("</div>");
    }

    private static String verdictText(ScanResult r) {
        return switch (r.verdict()) {
            case CLEAN -> "ЧИСТО / CLEAN";
            case SUSPICIOUS -> "ПОДОЗРИТЕЛЬНО / SUSPICIOUS";
            case CHEAT -> "ЧИТ ОБНАРУЖЕН / CHEAT DETECTED";
            case INCONCLUSIVE -> "НЕ ЗАВЕРШЕНО / INCONCLUSIVE";
        };
    }

    private static void summary(StringBuilder sb, ScanResult r) {
        sb.append("<div class=\"chips\">");
        chip(sb, "CRITICAL", r.countBySeverity(Severity.CRITICAL), "#ff5a5a");
        chip(sb, "HIGH", r.countBySeverity(Severity.HIGH), "#ff8a5a");
        chip(sb, "MEDIUM", r.countBySeverity(Severity.MEDIUM), "#f6b949");
        chip(sb, "LOW", r.countBySeverity(Severity.LOW), "#9aa0ec");
        chip(sb, "INFO", r.countBySeverity(Severity.INFO), "#b6b6b6");
        sb.append("</div>");
    }

    /** Why this verdict — the same explanation the UI shows. */
    private static void explanation(StringBuilder sb, ScanResult r) {
        sb.append("<h2>Почему такой вердикт / Why this verdict</h2>");
        sb.append("<pre class=\"explain\">")
          .append(esc(ru.moon.checker.core.Analysis.explain(r)))
          .append("</pre>");
    }

    /** Evidence correlated per subject, so one cheat reads as one case. */
    private static void evidenceGroups(StringBuilder sb, ScanResult r) {
        var groups = ru.moon.checker.core.Analysis.group(r.findings());
        if (groups.isEmpty()) {
            return;
        }
        sb.append("<h2>Сводка по уликам / Evidence summary</h2>");
        sb.append("<table class=\"find\"><thead><tr><th>Severity</th><th>Субъект</th>")
          .append("<th>Улик</th><th>Вес</th><th>Модули</th></tr></thead><tbody>");
        for (var g : groups) {
            sb.append("<tr class=\"sev-").append(g.topSeverity().name().toLowerCase()).append("\">")
              .append("<td><span class=\"badge b-").append(g.topSeverity().name().toLowerCase())
              .append("\">").append(g.topSeverity()).append("</span></td>")
              .append("<td>").append(esc(g.subject())).append("</td>")
              .append("<td>").append(g.count()).append("</td>")
              .append("<td>").append(g.weight()).append("</td>")
              .append("<td>").append(esc(String.join(", ", g.modules()))).append("</td>")
              .append("</tr>");
        }
        sb.append("</tbody></table>");
    }

    /** Chronological view — most recent first. */
    private static void timeline(StringBuilder sb, ScanResult r) {
        var tl = ru.moon.checker.core.Analysis.timeline(r.findings());
        if (tl.isEmpty()) {
            return;
        }
        sb.append("<h2>Хронология / Timeline (").append(tl.size()).append(")</h2>");
        sb.append("<table class=\"find\"><thead><tr><th>Время</th><th>Severity</th>")
          .append("<th>Событие</th><th>Источник</th></tr></thead><tbody>");
        for (Finding f : tl) {
            sb.append("<tr class=\"sev-").append(f.severity().name().toLowerCase()).append("\">")
              .append("<td>").append(TS.format(f.when())).append("</td>")
              .append("<td><span class=\"badge b-").append(f.severity().name().toLowerCase())
              .append("\">").append(f.severity()).append("</span></td>")
              .append("<td>").append(esc(f.title()));
            if (f.evidence() != null) {
                sb.append("<div class=\"ev\">").append(esc(f.evidence())).append("</div>");
            }
            sb.append("</td><td>").append(esc(nz(f.source()))).append("</td></tr>");
        }
        sb.append("</tbody></table>");
    }

    private static void findings(StringBuilder sb, ScanResult r) {
        sb.append("<h2>Находки / Findings (").append(r.findings().size()).append(")</h2>");
        if (r.findings().isEmpty()) {
            sb.append("<p class=\"empty\">Ничего не найдено.</p>");
            return;
        }
        sb.append("<table class=\"find\"><thead><tr>")
          .append("<th>Severity</th><th>Категория</th><th>Находка</th>")
          .append("<th>Детали</th><th>Источник</th><th>Время</th></tr></thead><tbody>");
        for (Finding f : r.findings()) {
            sb.append("<tr class=\"sev-").append(f.severity().name().toLowerCase()).append("\">");
            sb.append("<td><span class=\"badge b-").append(f.severity().name().toLowerCase())
              .append("\">").append(f.severity()).append("</span></td>");
            sb.append("<td>").append(esc(catName(f.category()))).append("</td>");
            sb.append("<td>").append(esc(f.title()));
            if (f.evidence() != null) {
                sb.append("<div class=\"ev\">").append(esc(f.evidence())).append("</div>");
            }
            sb.append("</td>");
            sb.append("<td>").append(esc(nz(f.detail()))).append("</td>");
            sb.append("<td>").append(esc(nz(f.source()))).append("</td>");
            sb.append("<td>").append(f.when() != null ? TS.format(f.when()) : "—").append("</td>");
            sb.append("</tr>");
        }
        sb.append("</tbody></table>");
    }

    private static void modules(StringBuilder sb, ScanResult r) {
        sb.append("<h2>Модули / Modules</h2><table class=\"mod\"><tbody>");
        for (Map.Entry<String, ModuleStatus> e : r.moduleStatus().entrySet()) {
            sb.append("<tr><td>").append(esc(e.getKey())).append("</td><td>")
              .append(e.getValue().name()).append("</td></tr>");
        }
        sb.append("</tbody></table>");
    }

    private static void row(StringBuilder sb, String k, String v) {
        sb.append("<tr><th>").append(esc(k)).append("</th><td>").append(esc(v)).append("</td></tr>");
    }

    private static void chip(StringBuilder sb, String label, long n, String color) {
        sb.append("<div class=\"chip\" style=\"border-color:").append(color).append("\">")
          .append("<b style=\"color:").append(color).append("\">").append(n).append("</b> ")
          .append(label).append("</div>");
    }

    private static String catName(Category c) {
        return I18n.t(c.key());
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String css() {
        return """
                :root{--bg:#161616;--card:#202020;--line:#2c2c2c;--txt:#e8e8e8;--mut:#9a9a9a;--acc:#6f78ef}
                *{box-sizing:border-box}
                body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}
                .wrap{max-width:1100px;margin:0 auto;padding:28px 20px}
                .head{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-start}
                .logo{font-weight:800;font-size:30px;letter-spacing:2px}
                .logo span{color:var(--acc)}
                table.meta{border-collapse:collapse}
                table.meta th{color:var(--mut);text-align:right;padding:2px 10px;font-weight:500}
                table.meta td{padding:2px 0;font-family:ui-monospace,Consolas,monospace}
                .verdict{margin:24px 0;padding:22px 26px;border:2px solid;border-radius:14px;background:var(--card);
                  display:flex;justify-content:space-between;align-items:center}
                .vlabel{font-size:26px;font-weight:800}
                .score{font-size:40px;font-weight:800}.score span{font-size:16px;color:var(--mut)}
                .chips{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
                .chip{border:1px solid;border-radius:10px;padding:8px 14px;background:var(--card)}
                .chip b{font-size:18px;margin-right:4px}
                h2{margin:26px 0 10px;font-size:16px;border-left:3px solid var(--acc);padding-left:10px}
                table.find,table.mod{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
                table.find th,table.find td,table.mod td{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
                table.find thead th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
                .ev{color:var(--mut);font-family:ui-monospace,Consolas,monospace;font-size:12px;margin-top:4px;word-break:break-all}
                .badge{padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;color:#111}
                .b-critical{background:#ff5a5a}.b-high{background:#ff8a5a}.b-medium{background:#f6b949}
                .b-low{background:#9aa0ec}.b-info{background:#b6b6b6}
                tr.sev-critical td,tr.sev-high td{background:rgba(255,90,90,.06)}
                .empty{color:var(--mut)}
                pre.explain{background:var(--card);border-left:3px solid var(--acc);border-radius:8px;
                  padding:14px 16px;white-space:pre-wrap;font:13px/1.6 Inter,Segoe UI,Arial,sans-serif;margin:0}
                footer{margin-top:30px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
                """;
    }
}

package ru.moon.checker.kernel;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates the framing of a Moon kernel-component report (protocol 2):
 * <pre>
 *   MOONMON 2 [n]          header; the Windows driver states the record count
 *   DRIVER &lt;path&gt;         Windows: one per kernel module
 *   KPID &lt;pid&gt; &lt;comm&gt;     Linux: one per task
 *   END &lt;n&gt;                last line, only when every record was written
 * </pre>
 * Anything else — no header, another protocol, a missing END, counts that
 * disagree, stray lines — makes the report incomplete. The caller turns that into
 * a collection error, so a truncated kernel view can never read as "clean".
 *
 * @param records the DRIVER/KPID lines, in order
 * @param problem why the report cannot be trusted as complete, or null
 */
public record KernelReport(List<String> records, String problem) {

    public static final int PROTOCOL = 2;

    public KernelReport {
        records = List.copyOf(records);
    }

    public boolean complete() {
        return problem == null;
    }

    public static KernelReport parse(List<String> lines) {
        List<String> body = new ArrayList<>();
        for (String l : lines) {
            if (l != null && !l.isBlank()) {
                body.add(l.strip());
            }
        }
        if (body.isEmpty()) {
            return new KernelReport(List.of(), "empty report");
        }
        String[] head = body.get(0).split(" ");
        if (!head[0].equals("MOONMON")) {
            return new KernelReport(List.of(), "no MOONMON header (driver older than protocol 2?)");
        }
        if (head.length < 2 || !head[1].equals(String.valueOf(PROTOCOL))) {
            return new KernelReport(List.of(), "unsupported kernel-component protocol '"
                    + (head.length > 1 ? head[1] : "") + "' (expected " + PROTOCOL + ")");
        }
        Integer declared = head.length > 2 ? parseCount(head[2]) : null;

        List<String> records = new ArrayList<>();
        Integer end = null;
        for (int i = 1; i < body.size(); i++) {
            String l = body.get(i);
            if (l.startsWith("DRIVER ") || l.startsWith("KPID ")) {
                if (end != null) {
                    return new KernelReport(records, "records after END");
                }
                records.add(l);
            } else if (l.startsWith("END ")) {
                if (end != null) {
                    return new KernelReport(records, "duplicate END");
                }
                end = parseCount(l.substring(4));
                if (end == null) {
                    return new KernelReport(records, "malformed END line");
                }
            } else {
                return new KernelReport(records, "unexpected line " + i);
            }
        }
        if (end == null) {
            return new KernelReport(records, "no END line: report truncated after " + records.size() + " records");
        }
        if (end != records.size()) {
            return new KernelReport(records, "END says " + end + " records, received " + records.size());
        }
        if (declared != null && declared != records.size()) {
            return new KernelReport(records, "header says " + declared + " records, received " + records.size());
        }
        return new KernelReport(records, null);
    }

    private static Integer parseCount(String s) {
        try {
            int n = Integer.parseInt(s.strip());
            return n >= 0 ? n : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

package ru.moon.checker.checks;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.Severity;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.win.AlternateStreams;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FileInspectionTest {

    @TempDir
    Path dir;

    @AfterEach
    void restoreStreamLister() {
        FileInspection.streamLister = AlternateStreams::list;
    }

    static List<Finding> inspect(Path file, SignatureDb db) {
        List<Finding> out = new ArrayList<>();
        EnvironmentInfo env = new EnvironmentInfo("PC", "os", "user", true, "1", "h", "jvm");
        ScanContext ctx = new ScanContext(db, CheckId.generate(), env, ScanListener.NOOP, out::add);
        FileInspection.inspect(file, ctx, "files", Category.FILES);
        return out;
    }

    @Test
    void streamOnZeroByteHostFileIsReported() throws Exception {
        // `echo payload > notes.txt:hidden` creates an empty notes.txt carrying the stream
        Path host = Files.createFile(dir.resolve("notes.txt"));
        FileInspection.streamLister = p -> p.equals(host.toString())
                ? List.of(new AlternateStreams.Stream("hidden", 8)) : List.of();

        List<Finding> findings = inspect(host, SignatureDb.empty());

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals(Severity.HIGH, f.severity());
        assertEquals(host + ":hidden", f.evidence());
    }

    @Test
    void streamNamedLikeACheatIsCritical() throws Exception {
        Path host = Files.writeString(dir.resolve("readme.txt"), "hello");
        FileInspection.streamLister = p -> List.of(new AlternateStreams.Stream("nixware.dll", 4096));

        List<Finding> findings = inspect(host, SignatureLoader.load(null).db());

        assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL
                && f.evidence().endsWith(":nixware.dll")), findings.toString());
    }
}

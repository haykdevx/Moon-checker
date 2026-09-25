package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.core.Severity;
import ru.moon.checker.signatures.SignatureLoader;
import ru.moon.checker.win.AmCacheRecords;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AmCacheCheckTest {

    static List<Finding> report(AmCacheRecords.Driver d) {
        List<Finding> out = new ArrayList<>();
        ScanContext ctx = new ScanContext(SignatureLoader.load(null).db(), CheckId.generate(),
                new EnvironmentInfo("pc", "Windows 11", "u", true, "1", "h", "j"), ScanListener.NOOP, out::add);
        AmCacheCheck.reportDriver(ctx, d);
        return out;
    }

    @Test
    void vulnerableDriverInInventoryIsHighNotCritical() {
        List<Finding> f = report(new AmCacheRecords.Driver("c:\\temp\\iqvw64e.sys", "iqvw64e.sys",
                "a9da04d80071dbaf1d10f78e4af3eb77e403d3eb", true, true, "Intel Corporation", "Nal", null));
        assertEquals(1, f.size(), f.toString());
        assertEquals(Severity.HIGH, f.get(0).severity(), "history is not proof the driver is loaded now");
        assertEquals(Category.KERNEL, f.get(0).category());
        assertTrue(f.get(0).detail().contains("sha1=a9da04d8"));
        assertEquals("c:\\temp\\iqvw64e.sys", f.get(0).evidence());
    }

    @Test
    void ordinaryInboxDriverIsIgnored() {
        assertTrue(report(new AmCacheRecords.Driver("c:\\windows\\system32\\cdd.dll", "cdd.dll", null,
                true, true, "Microsoft Corporation", "cdd", null)).isEmpty());
    }
}

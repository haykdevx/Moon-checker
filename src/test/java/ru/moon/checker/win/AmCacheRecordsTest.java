package ru.moon.checker.win;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AmCacheRecordsTest {

    static final String SHA1 = "a9da04d80071dbaf1d10f78e4af3eb77e403d3eb";

    @Test
    void driverFromInventoryDriverBinary() {
        // values as captured from InventoryDriverBinary on Windows 11 25H2
        Map<String, String> v = Map.of("DriverName", "iqvw64e.sys", "DriverId", "0000" + SHA1,
                "DriverSigned", "1", "DriverIsKernelMode", "1", "DriverCompany", "Intel Corporation",
                "Service", "Nal", "DriverLastWriteTime", "03/06/2026 23:48:00");
        AmCacheRecords.Driver d = AmCacheRecords.inventoryDriver("c:/users/p/appdata/local/temp/iqvw64e.sys", v::get);
        assertEquals("c:\\users\\p\\appdata\\local\\temp\\iqvw64e.sys", d.path());
        assertEquals("iqvw64e.sys", d.name());
        assertEquals(SHA1, d.sha1());
        assertTrue(d.signed());
        assertTrue(d.kernelMode());
        assertEquals("Intel Corporation", d.company());
        assertEquals("Nal", d.service());
    }

    @Test
    void driverWithoutNameFallsBackToKeyPath() {
        AmCacheRecords.Driver d = AmCacheRecords.inventoryDriver("c:/windows/system32/drivers/RTCore64.sys",
                Map.<String, String>of("DriverSigned", "0")::get);
        assertEquals("rtcore64.sys", d.name());
        assertFalse(d.signed());
        assertNull(d.sha1());
        assertNull(AmCacheRecords.inventoryDriver(null, Map.<String, String>of()::get));
    }

    @Test
    void legacyRootFileLayout() {
        AmCache.Entry e = AmCacheRecords.legacyFile(Map.of("15", "C:\\Users\\p\\Downloads\\Loader.exe",
                "101", "0000" + SHA1, "0", "Loader")::get);
        assertEquals("C:\\Users\\p\\Downloads\\Loader.exe", e.path());
        assertEquals("loader.exe", e.name());
        assertEquals(SHA1, e.sha1());
        assertNull(AmCacheRecords.legacyFile(Map.of("0", "no path")::get));
    }

    @Test
    void inventoryApplicationFileLayout() {
        AmCache.Entry e = AmCacheRecords.inventoryFile(Map.of("LowerCaseLongPath", "c:\\temp\\nixware.exe",
                "FileId", "0000" + SHA1, "Name", "nixware.exe")::get);
        assertEquals("nixware.exe", e.name());
        assertEquals(SHA1, e.sha1());
        assertNull(AmCacheRecords.inventoryFile(Map.<String, String>of()::get));
    }
}

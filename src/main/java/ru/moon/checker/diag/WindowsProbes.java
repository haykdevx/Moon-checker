package ru.moon.checker.diag;

import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinReg;
import ru.moon.checker.checks.FileInspection;
import ru.moon.checker.core.Category;
import ru.moon.checker.core.CheckId;
import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.core.Exec;
import ru.moon.checker.core.Finding;
import ru.moon.checker.core.Platform;
import ru.moon.checker.core.ScanContext;
import ru.moon.checker.core.ScanListener;
import ru.moon.checker.diag.Probe.Outcome;
import ru.moon.checker.kernel.KernelBridge;
import ru.moon.checker.parse.Usn;
import ru.moon.checker.signatures.SignatureDb;
import ru.moon.checker.win.AlternateStreams;
import ru.moon.checker.win.AmCache;
import ru.moon.checker.win.HiveMount;
import ru.moon.checker.win.Ntfs;
import ru.moon.checker.win.Registry;
import ru.moon.checker.win.UserHives;
import ru.moon.checker.win.Volumes;
import ru.moon.checker.win.WinConsole;
import ru.moon.checker.win.WinInfo;
import ru.moon.checker.win.WinProcess;
import ru.moon.checker.win.WinWindows;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Windows self-test probes. Each one drives the same code path a check module
 * uses, against a known artefact the probe creates itself where possible (a
 * file it deletes for the USN journal, a crafted {@code file.txt:hidden} ADS, a
 * registry key with an unusual value type), so PASS means "the module would
 * have seen it".
 */
final class WindowsProbes {

    private WindowsProbes() {
    }

    static List<Probe> all(EnvironmentInfo env, PrintStream out) {
        List<Probe> list = new ArrayList<>();
        add(list, out, Probe.run("elevation", () -> Outcome.check(env.elevated(),
                env.elevated() ? "running as administrator" : "NOT elevated — most probes below need admin")));
        add(list, out, Probe.run("console.charset", () -> Outcome.info("OEM code page charset " + WinConsole.charset())));
        add(list, out, Probe.run("powershell.utf8", WindowsProbes::powershellUtf8));
        add(list, out, Probe.run("reg.exe.decode", WindowsProbes::regExeDecode));
        add(list, out, Probe.run("registry.read", WindowsProbes::registryRead));
        add(list, out, Probe.run("registry.oddTypes", WindowsProbes::registryOddTypes));
        add(list, out, Probe.run("volumes", () -> {
            List<Character> drives = Volumes.fixedDrives();
            return Outcome.check(!drives.isEmpty(), "fixed drives " + drives);
        }));
        add(list, out, Probe.run("mft.enumerate", WindowsProbes::mft));
        add(list, out, Probe.run("usn.journal", WindowsProbes::usn));
        add(list, out, Probe.run("ads.detect", WindowsProbes::ads));
        add(list, out, Probe.run("amcache.mount", WindowsProbes::amcache));
        add(list, out, Probe.run("userhives", WindowsProbes::userHives));
        add(list, out, Probe.run("processes", WindowsProbes::processes));
        add(list, out, Probe.run("windows.titles", () -> Outcome.info(WinWindows.visibleTitles().size()
                + " visible top-level windows (0 is normal in a non-interactive session)")));
        add(list, out, Probe.run("prefetch", WindowsProbes::prefetch));
        add(list, out, Probe.run("bam", WindowsProbes::bam));
        add(list, out, Probe.run("signing.state", () -> WinInfo.signingState()
                .map(s -> Outcome.pass("testSigning=" + s.testSigning() + " integrityOff=" + s.integrityChecksOff()
                        + " debug=" + s.kernelDebug() + " (" + s.source() + ")"))
                .orElse(Outcome.fail("neither CodeIntegrity query nor SystemStartOptions readable"))));
        add(list, out, Probe.run("vm.detect", () -> Outcome.info(WinInfo.detectVirtualMachine().orElse("no hypervisor detected"))));
        add(list, out, Probe.run("kernel.bridge", () -> {
            KernelBridge.Report r = KernelBridge.read();
            return r.present() ? Outcome.pass(r.lines().size() + " report lines from " + r.source())
                    : Outcome.skip("MoonMon driver not loaded (\\\\.\\MoonMon absent)");
        }));
        add(list, out, Probe.run("defender.query", () -> {
            Exec.Result r = Exec.powershell("(Get-MpComputerStatus -ErrorAction Stop).AMServiceEnabled", Duration.ofSeconds(60));
            return r.ok() ? Outcome.pass("AMServiceEnabled=" + r.output().strip())
                    : Outcome.info("Get-MpComputerStatus unavailable: " + firstLine(r.output()));
        }));
        return list;
    }

    private static void add(List<Probe> list, PrintStream out, Probe p) {
        list.add(p);
        out.printf("  ... %-22s %s%n", p.id(), p.status()); // progress while slow probes run
    }

    private static Outcome powershellUtf8() {
        Exec.Result r = Exec.powershell("Write-Output ('Про' + 'верка')", Duration.ofSeconds(60));
        String got = r.output().strip();
        return Outcome.check(r.ok() && got.equals("Проверка"), "exit=" + r.exitCode() + " output='" + got + "'");
    }

    private static Outcome regExeDecode() {
        Exec.Result r = Exec.run(List.of("reg.exe", "query", "HKLM\\SOFTWARE\\MoonDiagNoSuchKey"),
                Duration.ofSeconds(20), WinConsole.charset());
        String text = r.output().strip();
        return Outcome.check(!text.isEmpty() && text.indexOf('\uFFFD') < 0 && r.exitCode() != 0,
                "exit=" + r.exitCode() + " message='" + text + "'");
    }

    private static Outcome registryRead() {
        String nt = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        String product = Registry.getString(Registry.HKLM, nt, "ProductName");
        String build = Registry.getString(Registry.HKLM, nt, "CurrentBuild");
        String display = Registry.getString(Registry.HKLM, nt, "DisplayVersion");
        return Outcome.check(product != null && build != null,
                product + " build " + build + (display != null ? " (" + display + ")" : ""));
    }

    private static Outcome registryOddTypes() {
        String path = "Software\\MoonCheckerDiag-" + UUID.randomUUID();
        try {
            Advapi32Util.registryCreateKey(WinReg.HKEY_CURRENT_USER, path);
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, path, "plain", "x");
            WinReg.HKEYByReference key = Advapi32Util.registryGetKey(WinReg.HKEY_CURRENT_USER, path, WinNT.KEY_WRITE);
            try {
                byte[] blob = {1, 2, 3, 4};
                Advapi32.INSTANCE.RegSetValueEx(key.getValue(), "resourceList", 0, 8, blob, blob.length);
            } finally {
                Advapi32Util.registryCloseKey(key.getValue());
            }
            Map<String, Object> values = Registry.values(WinReg.HKEY_CURRENT_USER, path);
            return Outcome.check("x".equals(values.get("plain")) && values.containsKey("resourceList"),
                    "values seen with a REG_RESOURCE_LIST sibling: " + values.keySet());
        } finally {
            try {
                Advapi32Util.registryDeleteKey(WinReg.HKEY_CURRENT_USER, path);
            } catch (Exception ignored) {
                // nothing created
            }
        }
    }

    private static Outcome mft() throws Exception {
        // Probe with a file we create: system binaries such as ntoskrnl.exe are hard
        // links into WinSxS, and the MFT enumeration reports one name per record.
        Path marker = Files.createTempFile("moon-diag-mft-", ".bin").toRealPath();
        try {
            char drive = Character.toUpperCase(marker.toString().charAt(0));
            long t0 = System.currentTimeMillis();
            Ntfs.Index index = Ntfs.buildIndex(drive);
            long ms = System.currentTimeMillis() - t0;
            if (index.size() == 0) {
                return Outcome.fail("FSCTL_ENUM_USN_DATA returned no records for " + drive + ": (needs admin + NTFS)");
            }
            String name = marker.getFileName().toString();
            String kernel = null;
            String resolved = null;
            for (var e : index.nodes().entrySet()) {
                String n = e.getValue().name();
                if (name.equalsIgnoreCase(n)) {
                    resolved = index.resolvePath(e.getKey());
                } else if (kernel == null && "ntoskrnl.exe".equalsIgnoreCase(n)) {
                    kernel = index.resolvePath(e.getKey());
                }
            }
            boolean ok = marker.toString().equalsIgnoreCase(resolved);
            return Outcome.check(ok, index.size() + " MFT records in " + ms + " ms; marker resolved to "
                    + resolved + (ok ? "" : " (expected " + marker + ")") + "; ntoskrnl.exe -> " + kernel);
        } finally {
            Files.deleteIfExists(marker);
        }
    }

    private static Outcome usn() throws Exception {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        String name = "moon-diag-usn-" + UUID.randomUUID() + ".tmp";
        Path f = tmp.resolve(name);
        Files.writeString(f, "x");
        Files.delete(f);
        char drive = Character.toUpperCase(tmp.toAbsolutePath().toString().charAt(0));
        List<Usn.Record> changes = Ntfs.readJournalChanges(drive);
        boolean found = changes.stream().anyMatch(r -> name.equals(r.fileName()) && r.isDeleted());
        return Outcome.check(found, changes.size() + " delete/rename records on " + drive
                + ":; own deleted file " + (found ? "found" : "NOT found") + " (" + name + ")");
    }

    private static Outcome ads() throws Exception {
        Path dir = Files.createTempDirectory("moon-diag-ads");
        Path host = dir.resolve("file.txt");
        try {
            // exactly what a player would type; creates an EMPTY file.txt carrying the stream
            Exec.Result mk = Exec.run(List.of("cmd.exe", "/c", "echo payload>\"" + host + ":hidden\""
                    + " && echo [ZoneTransfer]>\"" + host + ":Zone.Identifier\""), Duration.ofSeconds(20));
            if (!mk.ok() || !Files.exists(host)) {
                return Outcome.fail("could not craft the stream: " + mk.output().strip());
            }
            List<AlternateStreams.Stream> streams = AlternateStreams.list(host.toString());
            boolean listed = streams.stream().anyMatch(s -> s.name().equals("hidden"));
            boolean benignHidden = streams.stream().noneMatch(s -> s.name().equalsIgnoreCase("Zone.Identifier"));
            List<Finding> findings = new ArrayList<>();
            ScanContext ctx = new ScanContext(SignatureDb.empty(), CheckId.generate(),
                    new EnvironmentInfo("", "", "", true, "", "", ""), ScanListener.NOOP, findings::add);
            FileInspection.inspect(host, ctx, "diag", Category.FILES);
            boolean reported = findings.stream().anyMatch(fd -> String.valueOf(fd.evidence()).endsWith(":hidden"));
            return Outcome.check(listed && benignHidden && reported, "host size=" + Files.size(host)
                    + " streams=" + streams + " finding=" + reported);
        } finally {
            Files.deleteIfExists(host);
            Files.deleteIfExists(dir);
        }
    }

    private static Outcome amcache() {
        String key = "MoonDiagAmcache";
        int apps;
        int drivers;
        boolean snapshot;
        boolean staleRecovered;
        try (AmCache.Mount m = AmCache.mount(key)) {
            if (!m.loaded()) {
                return Outcome.fail(m.error());
            }
            snapshot = m.fromSnapshot();
            apps = Registry.subKeys(Registry.HKLM, m.root() + "\\InventoryApplicationFile").length;
            drivers = Registry.subKeys(Registry.HKLM, m.root() + "\\InventoryDriverBinary").length;
            // simulate a crashed earlier run that left the key mounted
            HiveMount.LoadResult again = HiveMount.load(HiveMount.Root.HKLM, key, m.hiveFile());
            staleRecovered = again.loaded() && again.staleRemoved();
        }
        boolean gone = !Registry.keyExists(Registry.HKLM, key);
        return Outcome.check(apps > 0 && staleRecovered && gone,
                (snapshot ? "via VSS snapshot" : "live hive") + "; InventoryApplicationFile=" + apps
                        + " InventoryDriverBinary=" + drivers + " staleRecovered=" + staleRecovered
                        + " unmounted=" + gone);
    }

    private static Outcome userHives() {
        List<String> labels = new ArrayList<>();
        try (UserHives.Scope a = UserHives.open(); UserHives.Scope b = UserHives.open()) {
            a.users().forEach(u -> labels.add(u.label()));
            if (a.users().size() != b.users().size()) {
                return Outcome.fail("parallel scopes disagree: " + a.users().size() + " vs " + b.users().size());
            }
        }
        List<String> leftovers = new ArrayList<>();
        for (String k : Registry.subKeys(Registry.HKU, "")) {
            if (k.startsWith("MoonChk_")) {
                leftovers.add(k);
            }
        }
        return Outcome.check(!labels.isEmpty() && leftovers.isEmpty(),
                "users=" + labels + (leftovers.isEmpty() ? "" : " LEFT MOUNTED=" + leftovers));
    }

    private static Outcome processes() {
        List<WinProcess.Proc> procs = WinProcess.list();
        long self = ProcessHandle.current().pid();
        WinProcess.Proc me = procs.stream().filter(p -> p.pid() == self).findFirst().orElse(null);
        boolean ok = procs.size() > 10 && me != null && me.path() != null;
        return Outcome.check(ok, procs.size() + " processes; self=" + (me == null ? "missing" : me.name() + " " + me.path()));
    }

    private static Outcome prefetch() throws Exception {
        Path dir = Platform.prefetchDir();
        int mode = Registry.getIntOr(Registry.HKLM,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
                "EnablePrefetcher", -1);
        if (!Files.isDirectory(dir)) {
            return Outcome.skip("no Prefetch folder (EnablePrefetcher=" + mode + ")");
        }
        try (var s = Files.list(dir)) {
            long pf = s.filter(p -> p.getFileName().toString().toLowerCase().endsWith(".pf")).count();
            return pf > 0 ? Outcome.pass(pf + " .pf files (EnablePrefetcher=" + mode + ")")
                    : Outcome.info("0 .pf files (EnablePrefetcher=" + mode + "; disabled by default on Windows Server)");
        }
    }

    private static Outcome bam() {
        String base = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
        int entries = 0;
        String[] sids = Registry.subKeys(Registry.HKLM, base);
        for (String sid : sids) {
            entries += (int) Registry.values(Registry.HKLM, base + "\\" + sid).keySet().stream()
                    .filter(n -> n.contains("\\")).count();
        }
        return entries > 0 ? Outcome.pass(entries + " executable entries across " + sids.length + " SIDs")
                : Outcome.info("no BAM entries (" + sids.length + " SIDs)");
    }

    private static String firstLine(String s) {
        String t = s.strip();
        int nl = t.indexOf('\n');
        return nl > 0 ? t.substring(0, nl).strip() : t;
    }
}

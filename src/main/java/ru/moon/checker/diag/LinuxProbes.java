package ru.moon.checker.diag;

import ru.moon.checker.core.EnvironmentInfo;
import ru.moon.checker.diag.Probe.Outcome;
import ru.moon.checker.kernel.KernelBridge;
import ru.moon.checker.linux.LinuxInfo;
import ru.moon.checker.linux.Proc;

import java.util.List;

/** Linux self-test probes (procfs, kernel state, optional moonmon module). */
final class LinuxProbes {

    private LinuxProbes() {
    }

    static List<Probe> all(EnvironmentInfo env) {
        return List.of(
                Probe.run("elevation", () -> env.elevated() ? Outcome.pass("running as root")
                        : Outcome.info("not root: other users' processes and maps are unreadable")),
                Probe.run("proc.pids", () -> {
                    List<Integer> pids = Proc.pids();
                    return Outcome.check(pids.size() > 1, pids.size() + " processes");
                }),
                Probe.run("proc.self", () -> {
                    int self = (int) ProcessHandle.current().pid();
                    String exe = Proc.exe(self);
                    return Outcome.check(exe != null && !Proc.maps(self).isEmpty(), "exe=" + exe);
                }),
                Probe.run("kernel.modules", () -> {
                    List<String> mods = LinuxInfo.loadedModules();
                    return mods.isEmpty() ? Outcome.info("/proc/modules empty or unreadable (container?)")
                            : Outcome.pass(mods.size() + " modules");
                }),
                Probe.run("kernel.taint", () -> Outcome.info("taint=" + LinuxInfo.taint()
                        + " (" + LinuxInfo.taintDescription(LinuxInfo.taint()) + ")")),
                Probe.run("kernel.bridge", () -> {
                    KernelBridge.Report r = KernelBridge.read();
                    return r.present() ? Outcome.pass(r.lines().size() + " lines from " + r.source())
                            : Outcome.skip("moonmon module not loaded");
                })
        );
    }
}

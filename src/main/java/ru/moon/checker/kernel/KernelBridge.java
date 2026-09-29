package ru.moon.checker.kernel;

import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import ru.moon.checker.core.Platform;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * User-mode client for the optional Moon kernel component
 * ({@code kernel/windows} KMDF/WDM driver, {@code kernel/linux} module).
 *
 * <p>When the driver is loaded it exposes a report of kernel-enumerated objects
 * (loaded drivers/modules and hidden processes/drivers that user-mode APIs
 * can't see because a rootkit unlinked them). This bridge reads that report:
 * <ul>
 *   <li>Windows: opens {@code \\.\MoonMon} and issues {@code IOCTL_MOON_GET_REPORT}.</li>
 *   <li>Linux: reads {@code /proc/moonmon} (or {@code /dev/moonmon}).</li>
 * </ul>
 * If the driver isn't installed, {@link #read()} returns {@code present=false}
 * and the {@code KernelCheck} module falls back to user-mode inspection.
 */
public final class KernelBridge {

    private static final String WIN_DEVICE = "\\\\.\\MoonMon";
    private static final int GENERIC_READ = 0x80000000;
    private static final int OPEN_EXISTING = 3;
    // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
    private static final int IOCTL_MOON_GET_REPORT = 0x00226000;
    private static final int BUFFER = 256 * 1024;

    private KernelBridge() {
    }

    /** What happened when the checker asked the kernel component for its report. */
    public enum State {
        /** Not installed (no device / no /proc entry). */
        ABSENT,
        /** Installed, but this process may not open it (not elevated). */
        INACCESSIBLE,
        /** Installed and opened, but the request or read failed. */
        FAILED,
        /** A report was read (its framing is checked by KernelReport: incompatible or partial show there). */
        COLLECTED
    }

    public record Report(State state, String source, List<String> lines, String detail) {
        public boolean present() {
            return state == State.COLLECTED;
        }

        static Report absent() {
            return new Report(State.ABSENT, "none", List.of(), "");
        }

        static Report of(State state, String source, String detail) {
            return new Report(state, source, List.of(), detail);
        }
    }

    public static Report read() {
        if (Platform.isWindows()) {
            return readWindows();
        }
        if (Platform.isLinux()) {
            return readLinux();
        }
        return Report.absent();
    }

    private static Report readWindows() {
        HANDLE h = null;
        try {
            h = Kernel32.INSTANCE.CreateFile(WIN_DEVICE, GENERIC_READ, 0, null,
                    OPEN_EXISTING, 0, null);
            if (h == null || h.equals(WinBase.INVALID_HANDLE_VALUE)) {
                int err = Kernel32.INSTANCE.GetLastError();
                return switch (err) {
                    case 2, 3 -> Report.absent();                                 // file / path not found
                    case 5 -> Report.of(State.INACCESSIBLE, "MoonMon.sys", "access denied");
                    default -> Report.of(State.FAILED, "MoonMon.sys", "CreateFile error " + err);
                };
            }
            try (Memory out = new Memory(BUFFER)) {
                IntByReference returned = new IntByReference();
                boolean ok = Kernel32.INSTANCE.DeviceIoControl(h, IOCTL_MOON_GET_REPORT,
                        null, 0, out, (int) out.size(), returned, null);
                if (!ok || returned.getValue() <= 0) {
                    return Report.of(State.FAILED, "MoonMon.sys", "DeviceIoControl error "
                            + (ok ? "(empty answer)" : String.valueOf(Kernel32.INSTANCE.GetLastError())));
                }
                byte[] data = out.getByteArray(0, Math.min(returned.getValue(), BUFFER));
                return new Report(State.COLLECTED, "MoonMon.sys",
                        List.of(new String(data, StandardCharsets.US_ASCII).split("\\R")), "");
            }
        } catch (Throwable t) {
            return Report.of(State.FAILED, "MoonMon.sys", t.getClass().getSimpleName());
        } finally {
            if (h != null && !h.equals(WinBase.INVALID_HANDLE_VALUE)) {
                Kernel32.INSTANCE.CloseHandle(h);
            }
        }
    }

    private static Report readLinux() {
        for (String path : new String[]{"/proc/moonmon", "/dev/moonmon"}) {
            Path p = Path.of(path);
            if (!Files.exists(p)) {
                continue;
            }
            if (!Files.isReadable(p)) {
                return Report.of(State.INACCESSIBLE, path, "not readable (root only)");
            }
            try {
                return new Report(State.COLLECTED, path, Files.readAllLines(p, StandardCharsets.US_ASCII), "");
            } catch (Exception e) {
                return Report.of(State.FAILED, path, e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
        return Report.absent();
    }
}

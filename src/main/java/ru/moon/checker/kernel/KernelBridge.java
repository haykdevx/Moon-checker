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

    public record Report(boolean present, String source, List<String> lines) {
        static Report absent() {
            return new Report(false, "none", List.of());
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
                return Report.absent();
            }
            try (Memory out = new Memory(BUFFER)) {
                IntByReference returned = new IntByReference();
                boolean ok = Kernel32.INSTANCE.DeviceIoControl(h, IOCTL_MOON_GET_REPORT,
                        null, 0, out, (int) out.size(), returned, null);
                if (!ok || returned.getValue() <= 0) {
                    return Report.absent();
                }
                byte[] data = out.getByteArray(0, returned.getValue());
                return new Report(true, "MoonMon.sys",
                        List.of(new String(data, StandardCharsets.UTF_8).split("\\R")));
            }
        } catch (Throwable t) {
            return Report.absent();
        } finally {
            if (h != null && !h.equals(WinBase.INVALID_HANDLE_VALUE)) {
                Kernel32.INSTANCE.CloseHandle(h);
            }
        }
    }

    private static Report readLinux() {
        for (String path : new String[]{"/proc/moonmon", "/dev/moonmon"}) {
            Path p = Path.of(path);
            if (Files.isReadable(p)) {
                try {
                    List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                    return new Report(true, path, lines);
                } catch (Exception ignored) {
                    // try next
                }
            }
        }
        return Report.absent();
    }
}

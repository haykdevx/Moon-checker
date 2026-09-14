package ru.moon.checker.win;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import ru.moon.checker.core.Platform;

import java.util.ArrayList;
import java.util.List;

/**
 * Enumerates running processes and resolves their on-disk image path using the
 * ToolHelp snapshot API. The path lets the checker read the backing binary and
 * flag cheats running from suspicious locations (Temp, Downloads, AppData).
 */
public final class WinProcess {

    private static final int TH32CS_SNAPPROCESS = 0x00000002;
    private static final int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private WinProcess() {
    }

    public record Proc(int pid, String name, String path) {
    }

    public static List<Proc> list() {
        List<Proc> out = new ArrayList<>();
        if (!Platform.isWindows()) {
            return out;
        }
        HANDLE snap = Kernel32.INSTANCE.CreateToolhelp32Snapshot(
                new com.sun.jna.platform.win32.WinDef.DWORD(TH32CS_SNAPPROCESS),
                new com.sun.jna.platform.win32.WinDef.DWORD(0));
        if (snap == null) {
            return out;
        }
        try {
            Tlhelp32.PROCESSENTRY32 pe = new Tlhelp32.PROCESSENTRY32();
            if (Kernel32.INSTANCE.Process32First(snap, pe)) {
                do {
                    int pid = pe.th32ProcessID.intValue();
                    String name = com.sun.jna.Native.toString(pe.szExeFile);
                    String path = queryPath(pid);
                    out.add(new Proc(pid, name, path));
                } while (Kernel32.INSTANCE.Process32Next(snap, pe));
            }
        } catch (Throwable t) {
            // best-effort
        } finally {
            Kernel32.INSTANCE.CloseHandle(snap);
        }
        return out;
    }

    private static String queryPath(int pid) {
        if (pid <= 4) {
            return null; // System / Idle have no readable image path
        }
        HANDLE proc = Kernel32.INSTANCE.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (proc == null) {
            return null;
        }
        try {
            char[] buf = new char[1024];
            IntByReference size = new IntByReference(buf.length);
            boolean ok = Kernel32.INSTANCE.QueryFullProcessImageName(proc, 0, buf, size);
            if (ok) {
                return new String(buf, 0, size.getValue());
            }
        } catch (Throwable t) {
            // ignore
        } finally {
            Kernel32.INSTANCE.CloseHandle(proc);
        }
        return null;
    }
}

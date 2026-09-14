package ru.moon.checker.parse;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Defensive PE (Portable Executable) reader. Parses just enough of the header
 * and import directory to answer: is this a PE, 32- or 64-bit, and which DLLs
 * / functions does it import. Injector-style externals import a recognisable
 * combination (OpenProcess + WriteProcessMemory + VirtualAllocEx / CreateRemoteThread),
 * which {@link #looksLikeInjector()} flags.
 *
 * <p>Every field access is bounds-checked; malformed input yields
 * {@code isPe()==false} rather than an exception.
 */
public final class Pe {

    private final boolean isPe;
    private final boolean is64;
    private final boolean signed;
    private final List<String> importedDlls;
    private final Set<String> importedFunctions;

    private Pe(boolean isPe, boolean is64, boolean signed, List<String> dlls, Set<String> functions) {
        this.isPe = isPe;
        this.is64 = is64;
        this.signed = signed;
        this.importedDlls = dlls;
        this.importedFunctions = functions;
    }

    public boolean isPe() {
        return isPe;
    }

    public boolean is64() {
        return is64;
    }

    /** True if the optional-header security directory points at an embedded
     *  Authenticode certificate (not a full trust verification, but a fast
     *  "is this binary signed at all" check). */
    public boolean signed() {
        return signed;
    }

    public List<String> importedDlls() {
        return importedDlls;
    }

    public Set<String> importedFunctions() {
        return importedFunctions;
    }

    private static final String[] INJECT_FUNCS = {
            "writeprocessmemory", "virtualallocex", "createremotethread",
            "ntwritevirtualmemory", "rtlcreateuserthread", "queueuserapc",
            "setwindowshookex", "loadlibrarya", "loadlibraryw"
    };

    /** Heuristic: imports the classic remote-injection toolkit. */
    public boolean looksLikeInjector() {
        boolean writes = importedFunctions.contains("writeprocessmemory")
                || importedFunctions.contains("ntwritevirtualmemory");
        boolean spawns = importedFunctions.contains("createremotethread")
                || importedFunctions.contains("rtlcreateuserthread")
                || importedFunctions.contains("queueuserapc")
                || importedFunctions.contains("setwindowshookexa")
                || importedFunctions.contains("setwindowshookexw");
        boolean opens = importedFunctions.contains("openprocess");
        return writes && (spawns || opens);
    }

    public static Pe parse(byte[] d) {
        Pe fail = new Pe(false, false, false, List.of(), Set.of());
        try {
            if (d == null || d.length < 0x40 || d[0] != 'M' || d[1] != 'Z') {
                return fail;
            }
            int peOff = u32(d, 0x3C);
            if (peOff <= 0 || peOff + 24 > d.length) {
                return fail;
            }
            if (d[peOff] != 'P' || d[peOff + 1] != 'E' || d[peOff + 2] != 0 || d[peOff + 3] != 0) {
                return fail;
            }
            int coff = peOff + 4;
            int numSections = u16(d, coff + 2);
            int optSize = u16(d, coff + 16);
            int optOff = coff + 20;
            if (optOff + optSize > d.length || optOff + 2 > d.length) {
                return fail;
            }
            int magic = u16(d, optOff);
            boolean is64 = magic == 0x20B;
            boolean is32 = magic == 0x10B;
            if (!is64 && !is32) {
                return fail;
            }

            // data directories: import table is index 1, security (cert) is index 4
            int ddOff = optOff + (is64 ? 112 : 96);
            boolean signed = false;
            int importRva = 0;
            if (ddOff + 40 <= d.length) {
                importRva = u32(d, ddOff + 8);
                int securitySize = u32(d, ddOff + 4 * 8 + 4);
                signed = securitySize > 0;
            }
            if (importRva == 0) {
                return new Pe(true, is64, signed, List.of(), Set.of());
            }

            int sectionTable = optOff + optSize;
            Section[] sections = readSections(d, sectionTable, numSections);

            List<String> dlls = new ArrayList<>();
            Set<String> funcs = new LinkedHashSet<>();
            readImports(d, importRva, sections, dlls, funcs, is64);
            return new Pe(true, is64, signed, dlls, funcs);
        } catch (Exception e) {
            return fail;
        }
    }

    private record Section(int va, int vsize, int rawPtr, int rawSize) {
    }

    private static Section[] readSections(byte[] d, int off, int n) {
        List<Section> list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            int base = off + i * 40;
            if (base + 40 > d.length) {
                break;
            }
            int vsize = u32(d, base + 8);
            int va = u32(d, base + 12);
            int rawSize = u32(d, base + 16);
            int rawPtr = u32(d, base + 20);
            list.add(new Section(va, vsize, rawPtr, rawSize));
        }
        return list.toArray(new Section[0]);
    }

    private static int rvaToOffset(int rva, Section[] sections) {
        for (Section s : sections) {
            if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) {
                return s.rawPtr + (rva - s.va);
            }
        }
        return -1;
    }

    private static void readImports(byte[] d, int importRva, Section[] sections,
                                    List<String> dlls, Set<String> funcs, boolean is64) {
        int off = rvaToOffset(importRva, sections);
        if (off < 0) {
            return;
        }
        // Import Directory Table: 20-byte descriptors, terminated by all-zero
        for (int i = 0; i < 4096; i++) {
            int desc = off + i * 20;
            if (desc + 20 > d.length) {
                return;
            }
            int origThunk = u32(d, desc);
            int nameRva = u32(d, desc + 12);
            int firstThunk = u32(d, desc + 16);
            if (origThunk == 0 && nameRva == 0 && firstThunk == 0) {
                return; // terminator
            }
            String dll = readCString(d, rvaToOffset(nameRva, sections));
            if (dll != null && !dll.isEmpty()) {
                dlls.add(dll.toLowerCase(Locale.ROOT));
            }
            int thunkRva = origThunk != 0 ? origThunk : firstThunk;
            readThunk(d, thunkRva, sections, funcs, is64);
        }
    }

    private static void readThunk(byte[] d, int thunkRva, Section[] sections, Set<String> funcs, boolean is64) {
        int t = rvaToOffset(thunkRva, sections);
        if (t < 0) {
            return;
        }
        int step = is64 ? 8 : 4;
        long ordinalFlag = is64 ? 0x8000000000000000L : 0x80000000L;
        for (int i = 0; i < 8192; i++) {
            int entryOff = t + i * step;
            if (entryOff + step > d.length) {
                return;
            }
            long val = is64 ? u64(d, entryOff) : (u32(d, entryOff) & 0xFFFFFFFFL);
            if (val == 0) {
                return;
            }
            if ((val & ordinalFlag) != 0) {
                continue; // imported by ordinal, no name
            }
            int hintNameRva = (int) (val & 0x7FFFFFFF);
            int hn = rvaToOffset(hintNameRva, sections);
            if (hn >= 0 && hn + 2 <= d.length) {
                String fn = readCString(d, hn + 2); // skip 2-byte hint
                if (fn != null && !fn.isEmpty()) {
                    funcs.add(fn.toLowerCase(Locale.ROOT));
                }
            }
        }
    }

    private static String readCString(byte[] d, int off) {
        if (off < 0 || off >= d.length) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < d.length && i < off + 512; i++) {
            int c = d[i] & 0xFF;
            if (c == 0) {
                break;
            }
            sb.append((char) c);
        }
        return sb.toString();
    }

    private static int u16(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8)
                | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }

    private static long u64(byte[] d, int o) {
        long lo = u32(d, o) & 0xFFFFFFFFL;
        long hi = u32(d, o + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }
}

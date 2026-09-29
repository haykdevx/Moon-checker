package ru.moon.checker.checks;

import java.util.Locale;
import java.util.Set;

/**
 * Decisions for the running game (pure; the collector does the Windows calls).
 *
 * <p>Internal cheats load a DLL into {@code cs2.exe}; external ones read its memory and
 * draw an ESP through a transparent, always-on-top window over the game. Legitimate
 * software does both too — the Steam, Discord, NVIDIA and AMD overlays, RivaTuner
 * (MSI Afterburner's FPS counter), OBS, recording tools — so everything here is
 * weighed by where the DLL lives and whose window it is.
 */
public final class LiveGamePolicy {

    /** Where a module loaded into the game comes from. */
    public enum Place { GAME, SYSTEM, KNOWN_OVERLAY, PROGRAM, USER_WRITABLE, UNUSUAL }

    /** DLLs that overlays, recorders and FPS counters inject into games. */
    static final Set<String> OVERLAY_DLLS = Set.of(
            "gameoverlayrenderer64.dll",   // Steam overlay
            "discordhook64.dll",           // Discord overlay
            "rtsshooks64.dll",             // RivaTuner (MSI Afterburner FPS counter)
            "graphics-hook64.dll",         // OBS game capture
            "nvspcap64.dll", "nvppex.dll", // NVIDIA ShadowPlay / overlay
            "amdow.dll", "amdrsserv.dll",  // AMD overlay
            "fraps64.dll", "bdcamvk64.dll", "bdcam64.dll", "action_x64.dll", "playclawhook64.dll",
            "owclient.dll", "ow-graphics-hook64.dll", "ow-graphics-vulkan64.dll",   // Overwolf
            "medal-hook64.dll", "mh64.dll");                                       // Medal
    /** Folders those tools install to (user-writable ones included: Discord, Overwolf and Medal live in AppData). */
    static final String[] OVERLAY_FOLDERS = {"\\discord\\", "\\overwolf\\", "\\medal\\", "\\rivatuner statistics server\\",
            "\\obs-studio\\", "\\steam\\", "\\nvidia corporation\\", "\\amd\\"};

    /** Processes allowed to put a transparent, always-on-top window over the game. */
    static final Set<String> OVERLAY_PROCESSES = Set.of(
            "cs2.exe", "steam.exe", "steamwebhelper.exe", "gameoverlayui.exe", "gameoverlayui64.exe",
            "discord.exe", "discordptb.exe", "discordcanary.exe",
            "nvidia share.exe", "nvidia overlay.exe", "nvcontainer.exe", "nvsphelper64.exe", "nvidia app.exe",
            "radeonsoftware.exe", "amdrsserv.exe", "amdow.exe",
            "rtss.exe", "msiafterburner.exe", "obs64.exe", "overwolf.exe", "medal.exe", "fraps.exe", "bdcam.exe",
            "action.exe", "playclaw.exe", "teamspeak.exe", "ts3client_win64.exe",
            "gamebar.exe", "gamebarftserver.exe", "gamebarpresencewriter.exe", "xboxpcapp.exe",
            "explorer.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe", "textinputhost.exe",
            "searchhost.exe", "searchapp.exe", "applicationframehost.exe", "lockapp.exe", "dwm.exe",
            "systemsettings.exe", "taskmgr.exe", "snippingtool.exe", "screenclippinghost.exe");

    private static final int WS_EX_TOPMOST = 0x00000008;
    private static final int WS_EX_TRANSPARENT = 0x00000020;
    private static final int WS_EX_LAYERED = 0x00080000;
    /** A window covering at least this share of the game window counts as over it. */
    static final double COVER = 0.5;

    private LiveGamePolicy() {
    }

    /** Where {@code modulePath} (as Windows reports it) lives, given the game's install folder. */
    public static Place place(String modulePath, String gameRoot) {
        if (modulePath == null || modulePath.isBlank()) {
            return Place.UNUSUAL;
        }
        String p = modulePath.replace('/', '\\').toLowerCase(Locale.ROOT);
        if (p.startsWith("\\\\?\\")) {
            p = p.substring(4);
        }
        String name = p.substring(p.lastIndexOf('\\') + 1);
        if (gameRoot != null && !gameRoot.isBlank() && p.startsWith(gameRoot.replace('/', '\\').toLowerCase(Locale.ROOT))) {
            return Place.GAME;
        }
        if (p.matches("^[a-z]:\\\\windows\\\\.*") && !p.contains("\\temp\\")) {
            return Place.SYSTEM;
        }
        if (OVERLAY_DLLS.contains(name)) {
            return Place.KNOWN_OVERLAY;
        }
        // a user-writable folder is trusted only by the exact DLL name above: anything can be
        // dropped into AppData\Local\Discord, so the folder alone proves nothing there
        if (DriverPlacement.of(modulePath) == DriverPlacement.Place.USER_WRITABLE) {
            return Place.USER_WRITABLE;
        }
        for (String folder : OVERLAY_FOLDERS) {
            if (p.contains(folder)) {
                return Place.KNOWN_OVERLAY;
            }
        }
        if (p.matches("^[a-z]:\\\\(program files|program files \\(x86\\)|programdata)\\\\.*")) {
            return Place.PROGRAM;
        }
        return Place.UNUSUAL;
    }

    /** Transparent (layered or click-through) and always on top — the shape of an ESP window. */
    public static boolean overlayStyle(int exStyle) {
        return (exStyle & WS_EX_TOPMOST) != 0 && (exStyle & (WS_EX_LAYERED | WS_EX_TRANSPARENT)) != 0;
    }

    /** Share of the game window's area that {@code other} covers (0..1). Rectangles as left, top, right, bottom. */
    public static double coverage(int[] other, int[] game) {
        long gw = Math.max(0, game[2] - game[0]), gh = Math.max(0, game[3] - game[1]);
        if (gw == 0 || gh == 0) {
            return 0;
        }
        long iw = Math.max(0, Math.min(other[2], game[2]) - Math.max(other[0], game[0]));
        long ih = Math.max(0, Math.min(other[3], game[3]) - Math.max(other[1], game[1]));
        return (double) (iw * ih) / (gw * gh);
    }

    public static boolean knownOverlayProcess(String exeName) {
        return exeName != null && OVERLAY_PROCESSES.contains(exeName.toLowerCase(Locale.ROOT));
    }
}

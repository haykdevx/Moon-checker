package ru.moon.checker.checks;

import java.util.Locale;
import java.util.Set;

/**
 * Decisions for the running game (pure; the collector does the Windows calls).
 *
 * <p>Internal cheats load a DLL into {@code cs2.exe}; external ones read its memory and
 * draw an ESP through a transparent, always-on-top window over the game. Legitimate
 * software does both too — the Steam, Discord, NVIDIA and AMD overlays, RivaTuner
 * (MSI Afterburner's FPS counter), OBS, recording tools. A familiar name or folder is
 * not an identity (anything can be named {@code gameoverlayrenderer64.dll} and dropped
 * into AppData), so a module or window owner passes as such software only when its
 * publisher is verified (signature, pinned root, exact vendor name — see
 * {@link ru.moon.checker.signatures.SignatureDb#isTrustedIdentity}); otherwise it is
 * reported by where it lives.
 */
public final class LiveGamePolicy {

    /** Where a module loaded into the game comes from (location only; identity is decided separately). */
    public enum Place { GAME, SYSTEM, PROGRAM, USER_WRITABLE, UNUSUAL }

    /** How a loaded module is reported. */
    public enum ModuleCall {
        /** Windows' own libraries, and the game's own files. */
        IGNORE,
        /** A known overlay / recorder whose publisher was verified: listed as context. */
        OVERLAY,
        /** A program library with a verified publisher, or an unverified one from a program folder: context. */
        PROGRAM,
        /** A Windows library name loaded from the game folder instead of System32 (DLL proxying). */
        PROXY,
        /** From a user-writable folder, publisher not verified. */
        USER_FOLDER,
        /** From an unusual folder, publisher not verified. */
        UNUSUAL
    }

    /** DLLs that overlays, recorders and FPS counters inject into games (a name is a hint, not an identity). */
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

    /**
     * Windows libraries a program loads by name, which a copy in the program's own folder
     * replaces (the loader looks there first): the classic way to get code into a game
     * without an injector. CS2 itself loads these from System32.
     */
    static final Set<String> PROXY_NAMES = Set.of(
            "version.dll", "winmm.dll", "dinput8.dll", "d3d9.dll", "d3d10.dll", "d3d11.dll", "d3d12.dll",
            "dxgi.dll", "opengl32.dll", "winhttp.dll", "wininet.dll", "xinput1_3.dll", "xinput1_4.dll",
            "hid.dll", "dsound.dll", "ddraw.dll", "iphlpapi.dll", "userenv.dll", "cryptsp.dll", "wtsapi32.dll");

    /** Processes that may put a transparent, always-on-top window over the game — once their publisher is verified. */
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
        return place(modulePath, gameRoot, WINDOWS);
    }

    /** CS2 paths are Windows paths wherever this runs (the policy is tested on Linux too). */
    private static final Locations.Roots WINDOWS = ru.moon.checker.core.Platform.isWindows()
            ? Locations.roots() : Locations.Roots.windows(java.util.Map.of());

    static Place place(String modulePath, String gameRoot, Locations.Roots roots) {
        String p = Locations.normalize(modulePath, roots.windows());
        if (p == null) {
            return Place.UNUSUAL;
        }
        String root = Locations.normalize(gameRoot, roots.windows());
        if (root != null && root.length() > 3 && Locations.under(p, root, roots.windows())) {
            return Place.GAME;   // whole path components: "…\\cs2-cheat\\x.dll" is not in "…\\cs2"
        }
        return switch (Locations.classify(p, roots)) {
            case SYSTEM -> Place.SYSTEM;
            case PROGRAM -> Place.PROGRAM;
            case USER_WRITABLE -> Place.USER_WRITABLE;
            case NETWORK, OTHER, UNKNOWN -> Place.UNUSUAL;
        };
    }

    /**
     * How a module loaded into the game is reported. The name suggests what it might be; only a
     * verified publisher ({@code verified}) lets a module from outside Windows and the game pass as
     * an overlay or program library. A familiar overlay name in Downloads is a user-folder module.
     */
    public static ModuleCall module(String fileName, Place place, boolean verified) {
        String name = fileName == null ? "" : fileName.toLowerCase(java.util.Locale.ROOT);
        return switch (place) {
            case SYSTEM -> ModuleCall.IGNORE;
            case GAME -> PROXY_NAMES.contains(name) && !verified ? ModuleCall.PROXY : ModuleCall.IGNORE;
            case PROGRAM -> verified && OVERLAY_DLLS.contains(name) ? ModuleCall.OVERLAY : ModuleCall.PROGRAM;
            case USER_WRITABLE -> verified ? (OVERLAY_DLLS.contains(name) ? ModuleCall.OVERLAY : ModuleCall.PROGRAM)
                    : ModuleCall.USER_FOLDER;
            case UNUSUAL -> verified ? (OVERLAY_DLLS.contains(name) ? ModuleCall.OVERLAY : ModuleCall.PROGRAM)
                    : ModuleCall.UNUSUAL;
        };
    }

    /** Needs a publisher check before {@link #module} can decide (everything but Windows' own files). */
    public static boolean needsIdentity(Place place) {
        return place != Place.SYSTEM;
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

    /** A window owner may draw over the game only with a known name AND a verified publisher. */
    public static boolean trustedOverlayOwner(String exeName, boolean verified) {
        return verified && knownOverlayProcess(exeName);
    }
}

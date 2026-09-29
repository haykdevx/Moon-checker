package ru.moon.checker.checks;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** What is loaded into and drawn over a running CS2, as real PCs have it. */
class LiveGamePolicyTest {

    private static final String ROOT = "D:\\SteamLibrary\\steamapps\\common\\Counter-Strike Global Offensive";

    @Test
    void theGamesOwnAndWindowsLibrariesAreNotLooked_at() {
        assertEquals(LiveGamePolicy.Place.GAME, LiveGamePolicy.place(ROOT + "\\game\\bin\\win64\\engine2.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.GAME, LiveGamePolicy.place(ROOT + "\\game\\csgo\\bin\\win64\\client.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.SYSTEM, LiveGamePolicy.place("C:\\Windows\\System32\\d3d11.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.SYSTEM, LiveGamePolicy.place(
                "C:\\Windows\\System32\\DriverStore\\FileRepository\\nv_dispi.inf_amd64\\nvwgf2umx.dll", ROOT));
    }

    @Test
    void overlaysAreRecognised() {
        assertEquals(LiveGamePolicy.Place.KNOWN_OVERLAY, LiveGamePolicy.place(
                "C:\\Program Files (x86)\\Steam\\GameOverlayRenderer64.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.KNOWN_OVERLAY, LiveGamePolicy.place(
                "C:\\Users\\Иван\\AppData\\Local\\Discord\\app-1.0.9170\\modules\\discord_hook-1\\discord_hook\\DiscordHook64.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.KNOWN_OVERLAY, LiveGamePolicy.place(
                "C:\\Program Files (x86)\\RivaTuner Statistics Server\\RTSSHooks64.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.KNOWN_OVERLAY, LiveGamePolicy.place(
                "C:\\Program Files\\obs-studio\\data\\obs-plugins\\win-capture\\graphics-hook64.dll", ROOT));
    }

    @Test
    void aDllFromAUserFolderIsTheInternalCheatShape() {
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place(
                "C:\\Users\\Иван\\AppData\\Local\\Temp\\x86f2.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place("C:\\Users\\p\\Downloads\\loader\\core.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place(
                "C:\\Users\\p\\AppData\\Local\\Discord\\evil.dll", ROOT),
                "an overlay's folder in AppData does not vouch for other files in it");
        assertEquals(LiveGamePolicy.Place.PROGRAM, LiveGamePolicy.place(
                "C:\\Program Files\\Kaspersky Lab\\Kaspersky Premium 21.19\\x64\\antimalware_provider.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.UNUSUAL, LiveGamePolicy.place("E:\\tools\\helper.dll", ROOT));
    }

    @Test
    void anEspWindowIsTransparentOnTopAndCoversTheGame() {
        int topmostLayered = 0x00000008 | 0x00080000;
        int topmostClickThrough = 0x00000008 | 0x00000020;
        assertTrue(LiveGamePolicy.overlayStyle(topmostLayered));
        assertTrue(LiveGamePolicy.overlayStyle(topmostClickThrough));
        assertFalse(LiveGamePolicy.overlayStyle(0x00080000), "layered but not on top: an ordinary app");
        assertFalse(LiveGamePolicy.overlayStyle(0x00000008), "on top but opaque: a normal always-on-top window");
        int[] game = {0, 0, 1920, 1080};
        assertEquals(1.0, LiveGamePolicy.coverage(new int[]{0, 0, 1920, 1080}, game), 1e-9);
        assertTrue(LiveGamePolicy.coverage(new int[]{1600, 0, 1920, 200}, game) < LiveGamePolicy.COVER,
                "an FPS counter in a corner is not over the game");
        assertEquals(0, LiveGamePolicy.coverage(new int[]{1920, 0, 3840, 1080}, game), 1e-9, "a second monitor");
        assertTrue(LiveGamePolicy.knownOverlayProcess("Discord.exe"));
        assertTrue(LiveGamePolicy.knownOverlayProcess("gameoverlayui64.exe"));
        assertFalse(LiveGamePolicy.knownOverlayProcess("svchost32.exe"));
    }

    @Test
    void theInstallFolderComesFromTheGamePath() {
        assertEquals(ROOT, LiveGameCheck.installRoot(ROOT + "\\game\\bin\\win64\\cs2.exe"));
        assertEquals("C:\\x", LiveGameCheck.installRoot("C:\\x\\cs2.exe"));
        assertNull(LiveGameCheck.installRoot(null));
    }
}

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
    void anOverlayPassesOnlyWithAVerifiedPublisher() {
        String steam = "C:\\Program Files (x86)\\Steam\\GameOverlayRenderer64.dll";
        String discord = "C:\\Users\\Иван\\AppData\\Local\\Discord\\app-1.0.9170\\modules\\discord_hook-1\\discord_hook\\DiscordHook64.dll";
        assertEquals(LiveGamePolicy.Place.PROGRAM, LiveGamePolicy.place(steam, ROOT));
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place(discord, ROOT));
        assertEquals(LiveGamePolicy.ModuleCall.OVERLAY, LiveGamePolicy.module("GameOverlayRenderer64.dll",
                LiveGamePolicy.Place.PROGRAM, true));
        assertEquals(LiveGamePolicy.ModuleCall.OVERLAY, LiveGamePolicy.module("DiscordHook64.dll",
                LiveGamePolicy.Place.USER_WRITABLE, true), "Discord lives in AppData; its signature vouches for it");
        assertEquals(LiveGamePolicy.ModuleCall.PROGRAM, LiveGamePolicy.module("GameOverlayRenderer64.dll",
                LiveGamePolicy.Place.PROGRAM, false), "unverified in Program Files: context, not an overlay");
    }

    @Test
    void anOverlayNameInAWritableFolderIsNotAnIdentity() {
        // review finding: familiar overlay file names got trusted treatment without file identity
        String fake = "C:\\Users\\p\\Downloads\\x\\steam\\GameOverlayRenderer64.dll";
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place(fake, ROOT));
        assertEquals(LiveGamePolicy.ModuleCall.USER_FOLDER, LiveGamePolicy.module("GameOverlayRenderer64.dll",
                LiveGamePolicy.Place.USER_WRITABLE, false));
        assertEquals(LiveGamePolicy.ModuleCall.UNUSUAL, LiveGamePolicy.module("DiscordHook64.dll",
                LiveGamePolicy.place("E:\\discord\\DiscordHook64.dll", ROOT), false));
        assertFalse(LiveGamePolicy.trustedOverlayOwner("discord.exe", false), "an ESP renamed discord.exe");
        assertTrue(LiveGamePolicy.trustedOverlayOwner("discord.exe", true));
        assertFalse(LiveGamePolicy.trustedOverlayOwner("esp.exe", true), "signed, but not an overlay program");
    }

    @Test
    void theGameFolderIsMatchedByWholeFolderNames() {
        String root = "D:\\Games\\cs2";
        assertEquals(LiveGamePolicy.Place.GAME, LiveGamePolicy.place("D:\\Games\\cs2\\game\\bin\\win64\\engine2.dll", root));
        assertNotEquals(LiveGamePolicy.Place.GAME, LiveGamePolicy.place("D:\\Games\\cs2-cheat\\inject.dll", root),
                "a sibling folder sharing the prefix is not the game");
        assertEquals(LiveGamePolicy.Place.GAME, LiveGamePolicy.place("d:/games/CS2/./game/bin/../bin/x.dll", root),
                "case, slashes and dots are normalised first");
    }

    @Test
    void aWindowsLibraryLoadedFromTheGameFolderIsDllProxying() {
        assertEquals(LiveGamePolicy.ModuleCall.PROXY, LiveGamePolicy.module("version.dll", LiveGamePolicy.Place.GAME, false));
        assertEquals(LiveGamePolicy.ModuleCall.IGNORE, LiveGamePolicy.module("version.dll", LiveGamePolicy.Place.GAME, true),
                "a verified publisher clears it");
        assertEquals(LiveGamePolicy.ModuleCall.IGNORE, LiveGamePolicy.module("client.dll", LiveGamePolicy.Place.GAME, false));
        assertEquals(LiveGamePolicy.ModuleCall.IGNORE, LiveGamePolicy.module("version.dll", LiveGamePolicy.Place.SYSTEM, false));
    }

    @Test
    void aDllFromAUserFolderIsTheInternalCheatShape() {
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place(
                "C:\\Users\\Иван\\AppData\\Local\\Temp\\x86f2.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place("C:\\Users\\p\\Downloads\\loader\\core.dll", ROOT));
        assertEquals(LiveGamePolicy.Place.USER_WRITABLE, LiveGamePolicy.place(
                "C:\\Users\\p\\AppData\\Local\\Discord\\evil.dll", ROOT),
                "an overlay's folder in AppData does not vouch for other files in it");
        assertEquals(LiveGamePolicy.ModuleCall.USER_FOLDER, LiveGamePolicy.module("evil.dll",
                LiveGamePolicy.Place.USER_WRITABLE, false));
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

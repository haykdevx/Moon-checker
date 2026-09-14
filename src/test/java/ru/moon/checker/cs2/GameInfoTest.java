package ru.moon.checker.cs2;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * gameinfo.gi is how a cheat gets Source 2 to load its code without patching a
 * single game binary, so a false negative here is expensive — and a false
 * positive would flag every honest player.
 */
class GameInfoTest {

    /** Shape of a stock CS2 gameinfo.gi SearchPaths block. */
    private static final String STOCK = """
            "GameInfo"
            {
                game     "Counter-Strike 2"
                FileSystem
                {
                    SearchPaths
                    {
                        Game                csgo
                        Game                core
                        Mod                 csgo
                        Write               csgo
                        AddonRoot           csgo_addons
                        Game                |all_source_engine_paths|csgo
                        Game                |gameinfo_path|.
                        Game                platform
                    }
                }
            }
            """;

    @Test
    void stockInstallHasNoForeignPaths() {
        GameInfo gi = GameInfo.parse(STOCK);
        assertFalse(gi.searchPaths().isEmpty(), "should have parsed the block");
        assertEquals(List.of(), gi.foreignSearchPaths(),
                "a stock gameinfo.gi must produce no findings, got " + gi.foreignSearchPaths());
    }

    @Test
    void detectsInjectedAbsolutePath() {
        String tampered = STOCK.replace("Game                platform",
                "Game                C:\\cheats\\nixware\n                        Game                platform");
        List<String> foreign = GameInfo.parse(tampered).foreignSearchPaths();
        assertEquals(1, foreign.size(), "expected exactly the injected path, got " + foreign);
        assertTrue(foreign.get(0).toLowerCase().contains("nixware"));
    }

    @Test
    void detectsParentDirectoryEscape() {
        String tampered = STOCK.replace("Mod                 csgo", "Mod                 ../../loader");
        assertTrue(GameInfo.parse(tampered).foreignSearchPaths().stream()
                .anyMatch(p -> p.contains("..")));
    }

    @Test
    void detectsUnknownFolderName() {
        String tampered = STOCK.replace("Game                core", "Game                cheatpack");
        assertEquals(List.of("cheatpack"), GameInfo.parse(tampered).foreignSearchPaths());
    }

    @Test
    void handlesQuotedKeyValueForm() {
        String quoted = """
                "GameInfo"
                {
                    FileSystem
                    {
                        "SearchPaths"
                        {
                            "Game"    "csgo"
                            "Game"    "D:\\\\inject\\\\payload"
                        }
                    }
                }
                """;
        GameInfo gi = GameInfo.parse(quoted);
        assertEquals(2, gi.searchPaths().size(), "parsed: " + gi.searchPaths());
        assertEquals(1, gi.foreignSearchPaths().size(), "foreign: " + gi.foreignSearchPaths());
    }

    @Test
    void duplicateKeysAreAllKept() {
        // the whole reason this isn't parsed with the generic VDF parser
        GameInfo gi = GameInfo.parse(STOCK);
        long gameEntries = gi.searchPaths().stream().filter(p -> p.contains("csgo") || p.equals("core")).count();
        assertTrue(gameEntries >= 4, "duplicate Game keys must not collapse: " + gi.searchPaths());
    }

    @Test
    void ignoresCommentsAndEmptyInput() {
        assertTrue(GameInfo.parse(null).searchPaths().isEmpty());
        assertTrue(GameInfo.parse("").searchPaths().isEmpty());
        String commented = STOCK.replace("Game                core", "// Game   evilpath\n                        Game                core");
        assertEquals(List.of(), GameInfo.parse(commented).foreignSearchPaths());
    }
}

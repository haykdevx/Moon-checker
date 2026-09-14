package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VdfTest {

    private static final String LOGIN_USERS = """
            "users"
            {
                "76561198000000001"
                {
                    "AccountName"   "player_one"
                    "PersonaName"   "MoonFragger"
                    "MostRecent"    "1"
                    "Timestamp"     "1700000000"
                }
                "76561198000000002"
                {
                    "AccountName"   "smurf_alt"
                    "PersonaName"   "second"
                    "MostRecent"    "0"
                    "Timestamp"     "1699000000"
                }
            }
            """;

    @Test
    void parsesTwoAccounts() {
        List<Vdf.SteamAccount> accounts = Vdf.parseLoginUsers(LOGIN_USERS);
        assertEquals(2, accounts.size());
        assertEquals("76561198000000001", accounts.get(0).steamId64());
        assertEquals("player_one", accounts.get(0).accountName());
        assertEquals("MoonFragger", accounts.get(0).personaName());
        assertTrue(accounts.get(0).mostRecent());
        assertFalse(accounts.get(1).mostRecent());
    }

    @Test
    void handlesNestedBlocksAndComments() {
        String vdf = """
                // top comment
                "root"
                {
                    "a" "1"
                    "nested"
                    {
                        "b" "2"
                    }
                }
                """;
        Vdf.Node root = Vdf.parse(vdf);
        Vdf.Node r = root.child("root");
        assertNotNull(r);
        assertEquals("1", r.child("a").value());
        assertEquals("2", r.child("nested").child("b").value());
    }

    @Test
    void emptyOrMissingUsersYieldsEmptyList() {
        assertTrue(Vdf.parseLoginUsers("").isEmpty());
        assertTrue(Vdf.parseLoginUsers("\"other\" { \"x\" \"1\" }").isEmpty());
    }
}

package ru.moon.checker.win;

import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** Windows output the checker parses, as real Russian and English PCs produce it. */
class WindowsParsingTest {

    @Test
    void consoleOutputOfRussianWindowsIsDecodedFromCp866() {
        Charset oem = WinCommand.charsetForCodePage(866);
        byte[] cp866 = "Пользователь Иван".getBytes(oem);
        assertEquals("Пользователь Иван", new String(cp866, oem));
        assertNotEquals("Пользователь Иван", new String(cp866, StandardCharsets.UTF_8), "UTF-8 garbles it");
        assertEquals(StandardCharsets.UTF_8, WinCommand.charsetForCodePage(65001));
        assertNotNull(WinCommand.charsetForCodePage(437));
    }

    @Test
    void powershellIsToldToWriteUtf8() {
        assertTrue(WinCommand.utf8Prelude().contains("[Console]::OutputEncoding=[Text.Encoding]::UTF8"));
    }

    @Test
    void testSigningComesFromTheBootsOwnSwitches() {
        assertTrue(WinInfo.startOptionsTestSigning(" NOEXECUTE=OPTIN  TESTSIGNING"));
        assertFalse(WinInfo.startOptionsTestSigning(" NOEXECUTE=OPTIN  FVEBOOT=2641920  NOVGA"));
        assertFalse(WinInfo.startOptionsTestSigning(""));
    }

    @Test
    void bcdeditIsReadOnTheTestsigningLineOnly() {
        // the old parser saw "Yes" on recoveryenabled and called every such PC test-signed
        String english = """
                Windows Boot Loader
                -------------------
                identifier              {current}
                device                  partition=C:
                recoveryenabled         Yes
                allowedinmemorysettings 0x15000075
                nx                      OptIn
                """;
        assertEquals(Optional.of(false), WinInfo.bcdeditTestSigning(english));
        assertEquals(Optional.of(true), WinInfo.bcdeditTestSigning(english + "testsigning             Yes\n"));
        String russian = """
                Загрузка Windows
                -------------------
                идентификатор           {current}
                recoveryenabled         Да
                testsigning             Нет
                """;
        assertEquals(Optional.of(false), WinInfo.bcdeditTestSigning(russian));
        assertEquals(Optional.of(true), WinInfo.bcdeditTestSigning(russian.replace("testsigning             Нет",
                "testsigning             Да")));
    }

    @Test
    void benignStreamsAreSkippedOnlyWhileSmall() {
        for (String name : new String[]{"Zone.Identifier", "SmartScreen", "KAVICHS", "com.dropbox.attrs",
                "AFP_AfpInfo", "encryptable", "favicon", "OECustomProperty", "ms-properties"}) {
            assertTrue(AlternateStreams.isBenign(name, 120), name);
        }
        assertFalse(AlternateStreams.isBenign("Zone.Identifier", 400_000), "a program hidden under a benign name");
        assertFalse(AlternateStreams.isBenign("payload", 120));
        assertFalse(AlternateStreams.isBenign(null, 0));
    }

    @Test
    void firstMeaningfulLineOfACommandsOutput() {
        assertEquals("ERROR: The process cannot access the file because it is being used by another process.",
                AmCache.firstLine("\r\nERROR: The process cannot access the file because it is being used by another process.\r\n"));
        assertEquals("", AmCache.firstLine(null));
    }

    @Test
    void amcacheFileIdIsASha1() {
        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
                AmCache.normalizeFileId("0000a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"));
        assertNull(AmCache.normalizeFileId("not-a-hash"));
    }
}

package ru.moon.checker.win;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class WinConsoleTest {

    @Test
    void russianOemCodePageDecodesRegExeOutput() {
        // "Операция успешно завершена." as reg.exe prints it on Russian Windows (cp866)
        byte[] cp866 = {(byte) 0x8E, (byte) 0xAF, (byte) 0xA5, (byte) 0xE0, (byte) 0xA0, (byte) 0xE6,
                (byte) 0xA8, (byte) 0xEF};
        assertEquals("Операция", new String(cp866, WinConsole.forCodePage(866)));
    }

    @Test
    void utf8AndUnknownPagesFallBackToUtf8() {
        assertEquals(StandardCharsets.UTF_8, WinConsole.forCodePage(65001));
        assertEquals(StandardCharsets.UTF_8, WinConsole.forCodePage(99999));
        assertEquals("IBM437", WinConsole.forCodePage(437).name());
    }
}

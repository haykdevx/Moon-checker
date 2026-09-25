package ru.moon.checker.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CodeFilterTest {

    @Test
    void formatsWhateverThePlayerTypesOrPastes() {
        assertEquals("K7MQ-4X2P", StartPanel.CodeFilter.format("k7mq4x2p"));
        assertEquals("K7MQ-4X2P", StartPanel.CodeFilter.format(" K7MQ - 4X2P "));
        assertEquals("K7MQ-4X2P", StartPanel.CodeFilter.format("K7MQ-4X2P-EXTRA"));
        assertEquals("K7M", StartPanel.CodeFilter.format("k7m"));
        assertEquals("K7MQ-4", StartPanel.CodeFilter.format("K7MQ4"));
        assertEquals("", StartPanel.CodeFilter.format("ёжик"));
    }
}

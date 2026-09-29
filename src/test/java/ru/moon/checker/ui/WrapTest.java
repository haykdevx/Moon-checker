package ru.moon.checker.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import java.awt.Font;

import static org.junit.jupiter.api.Assertions.*;

class WrapTest {

    @Test
    void longRussianTextWrapsInsideTheColumn() {
        JLabel label = new JLabel();
        label.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        String text = "Это официальный чекер сервера. Администратор наблюдает за проверкой по демонстрации "
                + "экрана в Discord. Приложение автоматически проверит ваш ПК на признаки читов CS2.";
        StartPanel.wrap(label, text, 400);
        assertEquals(400, label.getPreferredSize().width, "never wider than asked (Windows cut the lines off)");
        int oneLine = label.getFontMetrics(label.getFont()).getHeight();
        assertTrue(label.getPreferredSize().height >= 2 * oneLine, "the text goes onto several lines");
        assertEquals(label.getPreferredSize(), label.getMaximumSize(), "BoxLayout must not stretch it");
    }

    @Test
    void shortTextKeepsItsOwnWidth() {
        JLabel label = new JLabel();
        StartPanel.wrap(label, "OK", 400);
        assertTrue(label.getPreferredSize().width < 100);
    }
}

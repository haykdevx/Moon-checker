package ru.moon.checker.parse;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScheduledTaskTest {

    private static final String TASK_XML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Actions Context="Author">
                <Exec>
                  <Command>C:\\Users\\p\\AppData\\Local\\Temp\\nixware_loader.exe</Command>
                  <Arguments>-inject cs2</Arguments>
                </Exec>
              </Actions>
            </Task>
            """;

    @Test
    void extractsCommandAndArguments() {
        List<String> cmds = ScheduledTask.execCommands(TASK_XML.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, cmds.size());
        assertTrue(cmds.get(0).contains("nixware_loader.exe"));
        assertTrue(cmds.get(0).contains("-inject cs2"));
    }

    @Test
    void handlesGarbageGracefully() {
        assertTrue(ScheduledTask.execCommands("not xml".getBytes()).isEmpty());
        assertTrue(ScheduledTask.execCommands(new byte[0]).isEmpty());
        assertTrue(ScheduledTask.execCommands(null).isEmpty());
    }
}

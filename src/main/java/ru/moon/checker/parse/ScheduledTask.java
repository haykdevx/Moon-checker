package ru.moon.checker.parse;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses a Windows Task Scheduler task definition (the XML files under
 * {@code C:\Windows\System32\Tasks}) and extracts the command each task runs.
 * A scheduled task is a common way to auto-launch a cheat loader or a spoofer.
 */
public final class ScheduledTask {

    private ScheduledTask() {
    }

    /** Every {@code Actions/Exec} command ("command arguments") in the task. */
    public static List<String> execCommands(byte[] xml) {
        List<String> out = new ArrayList<>();
        if (xml == null || xml.length == 0) {
            return out;
        }
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // harden against XXE
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xml));

            NodeList execs = doc.getElementsByTagName("Exec");
            for (int i = 0; i < execs.getLength(); i++) {
                Node n = execs.item(i);
                if (!(n instanceof Element exec)) {
                    continue;
                }
                String command = text(exec, "Command");
                String args = text(exec, "Arguments");
                if (command != null && !command.isBlank()) {
                    out.add(args != null && !args.isBlank() ? command + " " + args : command);
                }
            }
        } catch (Exception e) {
            // malformed / not a task xml
        }
        return out;
    }

    private static String text(Element parent, String tag) {
        NodeList nl = parent.getElementsByTagName(tag);
        if (nl.getLength() == 0) {
            return null;
        }
        return nl.item(0).getTextContent();
    }
}

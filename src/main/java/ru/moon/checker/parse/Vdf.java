package ru.moon.checker.parse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal parser for Valve's text KeyValues (VDF) format, used by Steam's
 * {@code config/loginusers.vdf}. Supports quoted keys/values, nested blocks
 * and {@code //} line comments. Not a general VDF implementation — just enough
 * to read Steam account listings robustly.
 */
public final class Vdf {

    /** A parsed VDF node: either a leaf (value) or a map of children. */
    public static final class Node {
        private final Map<String, Node> children = new LinkedHashMap<>();
        private String value;

        public boolean isLeaf() {
            return value != null && children.isEmpty();
        }

        public String value() {
            return value;
        }

        public Node child(String key) {
            return children.get(key);
        }

        public Map<String, Node> children() {
            return children;
        }

        /** Case-insensitive lookup convenience. */
        public Node childIgnoreCase(String key) {
            for (var e : children.entrySet()) {
                if (e.getKey().equalsIgnoreCase(key)) {
                    return e.getValue();
                }
            }
            return null;
        }
    }

    private final String text;
    private int pos;

    private Vdf(String text) {
        this.text = text;
    }

    public static Node parse(String text) {
        Vdf p = new Vdf(text == null ? "" : text);
        Node root = new Node();
        p.parseInto(root);
        return root;
    }

    private void parseInto(Node parent) {
        while (true) {
            String key = nextToken();
            if (key == null) {
                return; // EOF
            }
            if (key.equals("}")) {
                return; // end of this block
            }
            skipWhitespaceAndComments();
            if (pos < text.length() && text.charAt(pos) == '{') {
                pos++; // consume '{'
                Node block = new Node();
                parseInto(block);
                parent.children.put(key, block);
            } else {
                String val = nextToken();
                Node leaf = new Node();
                leaf.value = val == null ? "" : val;
                parent.children.put(key, leaf);
            }
        }
    }

    /** Returns the next quoted or bare token, "}" for a closing brace, or null at EOF. */
    private String nextToken() {
        skipWhitespaceAndComments();
        if (pos >= text.length()) {
            return null;
        }
        char c = text.charAt(pos);
        if (c == '}') {
            pos++;
            return "}";
        }
        if (c == '{') {
            return null; // handled by caller
        }
        if (c == '"') {
            return readQuoted();
        }
        return readBare();
    }

    private String readQuoted() {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (pos < text.length()) {
            char c = text.charAt(pos++);
            if (c == '\\' && pos < text.length()) {
                char n = text.charAt(pos++);
                switch (n) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case '\\' -> sb.append('\\');
                    case '"' -> sb.append('"');
                    default -> sb.append(n);
                }
            } else if (c == '"') {
                break;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String readBare() {
        int start = pos;
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (Character.isWhitespace(c) || c == '{' || c == '}' || c == '"') {
                break;
            }
            pos++;
        }
        return text.substring(start, pos);
    }

    private void skipWhitespaceAndComments() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (Character.isWhitespace(c)) {
                pos++;
            } else if (c == '/' && pos + 1 < text.length() && text.charAt(pos + 1) == '/') {
                while (pos < text.length() && text.charAt(pos) != '\n') {
                    pos++;
                }
            } else {
                break;
            }
        }
    }

    /**
     * Convenience for {@code loginusers.vdf}: returns each account's steamId64
     * and account/persona name.
     */
    public static List<SteamAccount> parseLoginUsers(String text) {
        List<SteamAccount> out = new ArrayList<>();
        Node root = parse(text);
        Node users = root.childIgnoreCase("users");
        if (users == null) {
            return out;
        }
        for (var e : users.children().entrySet()) {
            String steamId = e.getKey();
            Node acc = e.getValue();
            String accountName = leaf(acc, "AccountName");
            String persona = leaf(acc, "PersonaName");
            String mostRecent = leaf(acc, "MostRecent");
            String timestamp = leaf(acc, "Timestamp");
            out.add(new SteamAccount(steamId, accountName, persona,
                    "1".equals(mostRecent), timestamp));
        }
        return out;
    }

    private static String leaf(Node parent, String key) {
        Node n = parent.childIgnoreCase(key);
        return n != null ? n.value() : null;
    }

    public record SteamAccount(String steamId64, String accountName, String personaName,
                               boolean mostRecent, String timestamp) {
    }
}

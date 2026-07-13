package org.causalontology;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON parser and writer over plain Java collections.
 *
 * The object graph uses exactly: LinkedHashMap&lt;String,Object&gt; for objects
 * (insertion order preserved), ArrayList&lt;Object&gt; for arrays, String,
 * Boolean, null, and numbers as Long when the source token is integral with
 * no decimal point and no exponent, otherwise Double. This mirrors the
 * int/float distinction the Python binding gets from its json module, which
 * the RFC 8785 serializer in Jcs depends on.
 */
public final class Json {

    private final String src;
    private int pos;

    private Json(String src) {
        this.src = src;
        this.pos = 0;
    }

    /** Parse a complete JSON text into the object graph described above. */
    public static Object parse(String text) {
        Json p = new Json(text);
        p.skipWhitespace();
        Object value = p.parseValue();
        p.skipWhitespace();
        if (p.pos != p.src.length()) {
            throw p.error("trailing characters");
        }
        return value;
    }

    /**
     * Structural equality with Python's semantics: numbers compare by value
     * (a Long 1 equals a Double 1.0, as int 1 == float 1.0 in Python), maps
     * by keys and values, lists elementwise.
     */
    public static boolean deepEquals(Object a, Object b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (a instanceof Number && b instanceof Number) {
            if (a instanceof Long && b instanceof Long) {
                return ((Long) a).longValue() == ((Long) b).longValue();
            }
            return Double.compare(((Number) a).doubleValue(),
                                  ((Number) b).doubleValue()) == 0;
        }
        if (a instanceof Map && b instanceof Map) {
            Map<?, ?> ma = (Map<?, ?>) a;
            Map<?, ?> mb = (Map<?, ?>) b;
            if (ma.size() != mb.size()) {
                return false;
            }
            for (Map.Entry<?, ?> e : ma.entrySet()) {
                if (!mb.containsKey(e.getKey())) {
                    return false;
                }
                if (!deepEquals(e.getValue(), mb.get(e.getKey()))) {
                    return false;
                }
            }
            return true;
        }
        if (a instanceof List && b instanceof List) {
            List<?> la = (List<?>) a;
            List<?> lb = (List<?>) b;
            if (la.size() != lb.size()) {
                return false;
            }
            for (int i = 0; i < la.size(); i++) {
                if (!deepEquals(la.get(i), lb.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return a.equals(b);
    }

    /** A plain (non-canonical) JSON writer, for debugging output only. */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(value, sb);
        return sb.toString();
    }

    private static void writeValue(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Boolean) {
            sb.append(((Boolean) value).booleanValue() ? "true" : "false");
        } else if (value instanceof String) {
            sb.append(Jcs.quote((String) value));
        } else if (value instanceof Number) {
            sb.append(value.toString());
        } else if (value instanceof List) {
            sb.append('[');
            List<?> list = (List<?>) value;
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeValue(list.get(i), sb);
            }
            sb.append(']');
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(Jcs.quote((String) e.getKey()));
                sb.append(':');
                writeValue(e.getValue(), sb);
            }
            sb.append('}');
        } else {
            throw new IllegalArgumentException(
                "cannot write value of type " + value.getClass().getName());
        }
    }

    // ------------------------------------------------------------- parsing

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException(
            "JSON parse error at offset " + pos + ": " + message);
    }

    private void skipWhitespace() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= src.length()) {
            throw error("unexpected end of input");
        }
        return src.charAt(pos);
    }

    private void expectWord(String word) {
        if (!src.startsWith(word, pos)) {
            throw error("expected '" + word + "'");
        }
        pos += word.length();
    }

    private Object parseValue() {
        char c = peek();
        switch (c) {
            case '{':
                return parseObject();
            case '[':
                return parseArray();
            case '"':
                return parseString();
            case 't':
                expectWord("true");
                return Boolean.TRUE;
            case 'f':
                expectWord("false");
                return Boolean.FALSE;
            case 'n':
                expectWord("null");
                return null;
            default:
                return parseNumber();
        }
    }

    private Map<String, Object> parseObject() {
        pos++; // consume '{'
        Map<String, Object> out = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return out;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw error("expected string key");
            }
            String key = parseString();
            skipWhitespace();
            if (peek() != ':') {
                throw error("expected ':'");
            }
            pos++;
            skipWhitespace();
            out.put(key, parseValue());
            skipWhitespace();
            char d = peek();
            if (d == ',') {
                pos++;
                continue;
            }
            if (d == '}') {
                pos++;
                return out;
            }
            throw error("expected ',' or '}'");
        }
    }

    private List<Object> parseArray() {
        pos++; // consume '['
        List<Object> out = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return out;
        }
        while (true) {
            skipWhitespace();
            out.add(parseValue());
            skipWhitespace();
            char d = peek();
            if (d == ',') {
                pos++;
                continue;
            }
            if (d == ']') {
                pos++;
                return out;
            }
            throw error("expected ',' or ']'");
        }
    }

    private String parseString() {
        pos++; // consume opening quote
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= src.length()) {
                throw error("unterminated string");
            }
            char c = src.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (pos >= src.length()) {
                    throw error("unterminated escape");
                }
                char e = src.charAt(pos++);
                switch (e) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        if (pos + 4 > src.length()) {
                            throw error("truncated unicode escape");
                        }
                        String hex = src.substring(pos, pos + 4);
                        try {
                            sb.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException nfe) {
                            throw error("bad unicode escape: " + hex);
                        }
                        pos += 4;
                        break;
                    default:
                        throw error("bad escape character: " + e);
                }
            } else {
                sb.append(c);
            }
        }
    }

    private Object parseNumber() {
        int start = pos;
        if (pos < src.length() && src.charAt(pos) == '-') {
            pos++;
        }
        boolean isDouble = false;
        while (pos < src.length() && isDigit(src.charAt(pos))) {
            pos++;
        }
        if (pos < src.length() && src.charAt(pos) == '.') {
            isDouble = true;
            pos++;
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
        }
        if (pos < src.length()
                && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            isDouble = true;
            pos++;
            if (pos < src.length()
                    && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) {
                pos++;
            }
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
        }
        String token = src.substring(start, pos);
        if (token.isEmpty() || token.equals("-")) {
            throw error("invalid number");
        }
        if (!isDouble) {
            try {
                return Long.valueOf(Long.parseLong(token));
            } catch (NumberFormatException nfe) {
                return Double.valueOf(Double.parseDouble(token));
            }
        }
        try {
            return Double.valueOf(Double.parseDouble(token));
        } catch (NumberFormatException nfe) {
            throw error("invalid number: " + token);
        }
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }
}

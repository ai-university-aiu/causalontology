package org.causalontology;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * RFC 8785 (JSON Canonicalization Scheme) serialization over the object
 * graph produced by Json.parse (LinkedHashMap / ArrayList / String /
 * Boolean / Long / Double / null).
 *
 * Object keys are sorted by UTF-16 code units, which is exactly what
 * String.compareTo does. Strings use the minimal-escape rules. Numbers
 * mirror the Python binding's _jcs_number: a Long prints as its decimal
 * string; a Double that is integer-valued with magnitude below 1e21 prints
 * as an integer; other Doubles print via the shortest round-trip decimal
 * (Double.toString) with the exponent normalized to the ECMAScript form
 * (1.0E-7 becomes 1e-7; 1.0E21 becomes 1e+21). As with the Python binding,
 * full ECMAScript formatting for extreme magnitudes outside the range the
 * conformance suite exercises is pinned at the 1.0.0 freeze.
 */
public final class Jcs {

    private Jcs() {
    }

    /** The canonical serialization of a value. */
    public static String serialize(Object value) {
        StringBuilder sb = new StringBuilder();
        append(value, sb);
        return sb.toString();
    }

    private static void append(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
            return;
        }
        if (value instanceof Boolean) {
            sb.append(((Boolean) value).booleanValue() ? "true" : "false");
            return;
        }
        if (value instanceof String) {
            sb.append(quote((String) value));
            return;
        }
        if (value instanceof Number) {
            sb.append(number((Number) value));
            return;
        }
        if (value instanceof List) {
            sb.append('[');
            List<?> list = (List<?>) value;
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                append(list.get(i), sb);
            }
            sb.append(']');
            return;
        }
        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            List<String> keys = new ArrayList<>();
            for (Object key : map.keySet()) {
                if (!(key instanceof String)) {
                    throw new IllegalArgumentException(
                        "cannot canonicalize a non-string key: " + key);
                }
                keys.add((String) key);
            }
            // String.compareTo is comparison by UTF-16 code units,
            // which is the RFC 8785 key ordering.
            Collections.sort(keys);
            sb.append('{');
            boolean first = true;
            for (String key : keys) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(quote(key));
                sb.append(':');
                append(map.get(key), sb);
            }
            sb.append('}');
            return;
        }
        throw new IllegalArgumentException(
            "cannot canonicalize value of type " + value.getClass().getName());
    }

    /** The RFC 8785 minimal-escape string form, including the quotes. */
    static String quote(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /** The RFC 8785 number form, mirroring the Python _jcs_number. */
    static String number(Number n) {
        // Integral types keep their exact decimal representation.
        if (!(n instanceof Double) && !(n instanceof Float)) {
            return n.toString();
        }
        double d = n.doubleValue();
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException(
                "NaN and Infinity are not permitted (RFC 8785)");
        }
        if (d == 0.0) {
            // Covers -0.0 as well: RFC 8785 serializes it as "0".
            return "0";
        }
        if (d == Math.floor(d) && Math.abs(d) < 1e21) {
            // Integer-valued double: print as an integer. BigDecimal is
            // exact for integral doubles and avoids long overflow near 1e21.
            return new BigDecimal(d).toBigInteger().toString();
        }
        // Shortest round-trip decimal.
        String r = Double.toString(d);
        int e = r.indexOf('E');
        if (e < 0) {
            return r;
        }
        // Normalize Java's exponent form to the ECMAScript style:
        // "1.0E-7" -> "1e-7", "1.0E21" -> "1e+21", "1.25E22" -> "1.25e+22".
        String mantissa = r.substring(0, e);
        String exponent = r.substring(e + 1);
        if (mantissa.endsWith(".0")) {
            mantissa = mantissa.substring(0, mantissa.length() - 2);
        }
        String sign = "+";
        if (exponent.startsWith("-")) {
            sign = "-";
            exponent = exponent.substring(1);
        } else if (exponent.startsWith("+")) {
            exponent = exponent.substring(1);
        }
        // Strip any leading zero padding from the exponent digits.
        int firstNonZero = 0;
        while (firstNonZero < exponent.length() - 1
                && exponent.charAt(firstNonZero) == '0') {
            firstNonZero++;
        }
        exponent = exponent.substring(firstNonZero);
        return mantissa + "e" + sign + exponent;
    }
}

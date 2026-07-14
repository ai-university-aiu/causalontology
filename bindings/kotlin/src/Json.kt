// A minimal recursive-descent JSON parser for the conformance vectors and schemas.
//
// Value model (mirrors the Java binding, which mirrors what canonical.py needs):
//   object  -> LinkedHashMap<String, Any?>  (insertion order preserved)
//   array   -> MutableList<Any?>
//   string  -> String
//   number  -> Long when the literal carries no '.', 'e', or 'E'; Double otherwise
//              (so the integer-versus-decimal source distinction survives to JCS)
//   boolean -> Boolean
//   null    -> null
package org.causalontology

object Json {

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.parseValue()
        p.skipWs()
        if (!p.atEnd()) throw RuntimeException("trailing characters at offset ${p.pos}")
        return v
    }

    private class Parser(val s: String) {
        var pos = 0

        fun atEnd() = pos >= s.length

        fun skipWs() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        fun parseValue(): Any? {
            if (atEnd()) throw RuntimeException("unexpected end of JSON")
            return when (s[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> parseNumber()
            }
        }

        fun expect(word: String) {
            if (pos + word.length > s.length || s.substring(pos, pos + word.length) != word)
                throw RuntimeException("bad literal at offset $pos")
            pos += word.length
        }

        fun parseObject(): LinkedHashMap<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            pos++  // consume '{'
            skipWs()
            if (!atEnd() && s[pos] == '}') { pos++; return out }
            while (true) {
                skipWs()
                if (atEnd() || s[pos] != '"') throw RuntimeException("expected string key at offset $pos")
                val key = parseString()
                skipWs()
                if (atEnd() || s[pos] != ':') throw RuntimeException("expected ':' at offset $pos")
                pos++
                skipWs()
                out[key] = parseValue()
                skipWs()
                if (atEnd()) throw RuntimeException("unterminated object")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return out }
                    else -> throw RuntimeException("expected ',' or '}' at offset $pos")
                }
            }
        }

        fun parseArray(): MutableList<Any?> {
            val out = mutableListOf<Any?>()
            pos++  // consume '['
            skipWs()
            if (!atEnd() && s[pos] == ']') { pos++; return out }
            while (true) {
                skipWs()
                out.add(parseValue())
                skipWs()
                if (atEnd()) throw RuntimeException("unterminated array")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return out }
                    else -> throw RuntimeException("expected ',' or ']' at offset $pos")
                }
            }
        }

        fun parseString(): String {
            pos++  // consume opening quote
            val sb = StringBuilder()
            while (true) {
                if (atEnd()) throw RuntimeException("unterminated string")
                val c = s[pos]
                when {
                    c == '"' -> { pos++; return sb.toString() }
                    c == '\\' -> {
                        pos++
                        if (atEnd()) throw RuntimeException("unterminated escape")
                        when (val e = s[pos]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 >= s.length) throw RuntimeException("bad \\u escape")
                                val hex = s.substring(pos + 1, pos + 5)
                                sb.append(hex.toInt(16).toChar())
                                pos += 4
                            }
                            else -> throw RuntimeException("bad escape \\$e")
                        }
                        pos++
                    }
                    else -> { sb.append(c); pos++ }
                }
            }
        }

        fun parseNumber(): Any {
            val start = pos
            if (!atEnd() && s[pos] == '-') pos++
            while (!atEnd() && (s[pos] in '0'..'9' || s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E' || s[pos] == '+' || s[pos] == '-')) pos++
            val lit = s.substring(start, pos)
            if (lit.isEmpty()) throw RuntimeException("expected value at offset $start")
            // A literal with no '.', 'e', or 'E' is an integer (Long); otherwise a Double.
            return if (lit.none { it == '.' || it == 'e' || it == 'E' })
                lit.toLong()
            else
                lit.toDouble()
        }
    }
}

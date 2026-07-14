// RFC 8785 (JSON Canonicalization Scheme) serialization.
//
// Mirrors _jcs / _jcs_number / _jcs_string in the Python binding's
// canonical.py: sorted keys (UTF-16 code-unit order, identical to Python's
// code-point sort for the ASCII keys the standard uses), minimal string
// escaping, and ECMAScript-style canonical numbers (1.0 -> "1", 0.7 -> "0.7",
// exponents normalized to ES6's e+NN / e-N form).
package org.causalontology

import kotlin.math.abs

object Jcs {

    fun serialize(value: Any?): String = when (value) {
        null -> "null"
        is Boolean -> if (value) "true" else "false"
        is Long -> value.toString()
        is Int -> value.toString()
        is Double -> number(value)
        is String -> string(value)
        is List<*> -> "[" + value.joinToString(",") { serialize(it) } + "]"
        is Map<*, *> -> {
            val entries = value.entries.map { Pair(it.key as String, it.value) }
                .sortedWith(compareBy { it.first })  // UTF-16 code-unit lexicographic
            "{" + entries.joinToString(",") { string(it.first) + ":" + serialize(it.second) } + "}"
        }
        else -> throw IllegalArgumentException("cannot canonicalize ${value::class}")
    }

    fun string(s: String): String {
        val sb = StringBuilder("\"")
        for (ch in s) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\t' -> sb.append("\\t")
                '\n' -> sb.append("\\n")
                '\u000C' -> sb.append("\\f")
                '\r' -> sb.append("\\r")
                else -> {
                    if (ch.code < 0x20) {
                        sb.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
                    } else sb.append(ch)
                }
            }
        }
        sb.append("\"")
        return sb.toString()
    }

    // The RFC 8785 number rules for a Double (Longs serialize verbatim above):
    // integral values below 1e21 print as exact integers; everything else
    // prints as the shortest round-trip decimal in ES6 format.
    fun number(n: Double): String {
        if (n.isNaN() || n.isInfinite())
            throw IllegalArgumentException("NaN and Infinity are not permitted (RFC 8785)")
        if (n == 0.0) return "0"  // covers -0.0 as well, as RFC 8785 requires
        val neg = n < 0
        val a = abs(n)
        if (a == kotlin.math.floor(a) && a < 1e21) {
            return (if (neg) "-" else "") + integralDoubleToString(a)
        }
        return (if (neg) "-" else "") + es6Shortest(a)
    }

    // Exact decimal rendering of an integral double: direct Long conversion up
    // to 2^53 (always exact), the bignum route above it (still exact, because
    // an integral double is mantissa * 2^exponent).
    private fun integralDoubleToString(a: Double): String {
        if (a <= 9007199254740992.0) return a.toLong().toString()
        val bits = a.toRawBits()
        val exp = ((bits ushr 52) and 0x7FF).toInt()
        val frac = bits and 0xFFFFFFFFFFFFFL
        val mant = frac or (1L shl 52)
        val e2 = exp - 1075  // >= 1 for any integral double above 2^53
        return Bignum.toDecimalString(Bignum.shl(Bignum.fromLong(mant), e2))
    }

    // Shortest round-trip decimal, formatted exactly as Python's repr (the
    // reference _jcs_number) formats it: decimal notation from 1e-4 up to the
    // integer cutover, exponent notation outside, with the exponent normalized
    // to ES6's e+NN / e-N form. Kotlin/Native's Double.toString supplies the
    // digits; minimizeDigits() then guarantees they are the shortest (and
    // nearest) round-tripping digit string, matching Python's algorithm even
    // on edge values such as denormals.
    private fun es6Shortest(a: Double): String {
        val s = a.toString()
        var mant = s
        var exp10 = 0
        val ei = s.indexOfFirst { it == 'e' || it == 'E' }
        if (ei >= 0) {
            exp10 = s.substring(ei + 1).toInt()
            mant = s.substring(0, ei)
        }
        val dot = mant.indexOf('.')
        var digits: String
        var n: Int  // value = 0.digits * 10^n
        if (dot >= 0) {
            digits = mant.substring(0, dot) + mant.substring(dot + 1)
            n = dot + exp10
        } else {
            digits = mant
            n = mant.length + exp10
        }
        while (digits.length > 1 && digits[0] == '0') { digits = digits.substring(1); n -= 1 }
        while (digits.length > 1 && digits[digits.length - 1] == '0') digits = digits.dropLast(1)
        if (digits == "0") return "0"
        val (d2, n2) = minimizeDigits(a, digits, n)
        digits = d2; n = n2
        val k = digits.length
        return when {
            n in k..16 -> digits + "0".repeat(n - k)
            n in 1..16 && n < k -> digits.substring(0, n) + "." + digits.substring(n)
            n in -3..0 -> "0." + "0".repeat(-n) + digits
            else -> {
                val e = n - 1
                val head = if (k == 1) digits else digits.substring(0, 1) + "." + digits.substring(1)
                head + "e" + (if (e >= 0) "+" else "-") + abs(e)
            }
        }
    }

    // The shortest digit string (with its decimal exponent) that parses back
    // to exactly a. Tries, for each shorter length, the nearest (round-half-up)
    // candidate first and the truncated candidate second, keeping the first
    // that round-trips; falls back to the input digits.
    private fun minimizeDigits(a: Double, digitsIn: String, nIn: Int): Pair<String, Int> {
        fun roundTrips(digits: String, n: Int): Boolean =
            ("0." + digits + "e" + n).toDouble() == a
        for (kp in 1 until digitsIn.length) {
            // Candidate 1: round half up at kp digits.
            var cand = digitsIn.substring(0, kp)
            var n = nIn
            if (digitsIn[kp] >= '5') {
                val arr = cand.toCharArray()
                var i = kp - 1
                var carry = true
                while (i >= 0 && carry) {
                    if (arr[i] == '9') { arr[i] = '0'; i-- } else { arr[i] = arr[i] + 1; carry = false }
                }
                cand = if (carry) { n += 1; "1" + arr.concatToString() } else arr.concatToString()
            }
            var trimmed = cand
            while (trimmed.length > 1 && trimmed.last() == '0') trimmed = trimmed.dropLast(1)
            if (roundTrips(trimmed, n)) return Pair(trimmed, n)
            // Candidate 2: plain truncation at kp digits.
            var trunc = digitsIn.substring(0, kp)
            while (trunc.length > 1 && trunc.last() == '0') trunc = trunc.dropLast(1)
            if (roundTrips(trunc, nIn)) return Pair(trunc, nIn)
        }
        return Pair(digitsIn, nIn)
    }
}

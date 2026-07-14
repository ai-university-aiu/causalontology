// Arbitrary-precision non-negative integers for Ed25519 and exact JCS integers.
//
// Representation: IntArray of base-2^16 limbs, little-endian, normalized (no
// leading zero limbs; zero is the empty array). Base 2^16 keeps every Long
// product safely inside 64 bits: 32 limbs x 32 limbs accumulates at most
// 32 * (2^16-1)^2 < 2^37 per column, far from overflow.
package org.causalontology

object Bignum {

    val ZERO = IntArray(0)
    val ONE = intArrayOf(1)

    // Trim leading (high-order) zero limbs so every value has one canonical form.
    fun norm(a: IntArray): IntArray {
        var n = a.size
        while (n > 0 && a[n - 1] == 0) n--
        return if (n == a.size) a else a.copyOf(n)
    }

    fun isZero(a: IntArray): Boolean = a.isEmpty()

    fun fromLong(v: Long): IntArray {
        require(v >= 0) { "Bignum is non-negative" }
        var x = v
        val out = mutableListOf<Int>()
        while (x != 0L) {
            out.add((x and 0xFFFF).toInt())
            x = x ushr 16
        }
        return out.toIntArray()
    }

    // Parse a big-endian hexadecimal string (no sign, no prefix).
    fun fromHex(hex: String): IntArray {
        var acc = ZERO
        val sixteen = intArrayOf(16)
        for (c in hex) {
            val d = when (c) {
                in '0'..'9' -> c - '0'
                in 'a'..'f' -> c - 'a' + 10
                in 'A'..'F' -> c - 'A' + 10
                else -> throw IllegalArgumentException("bad hex digit $c")
            }
            acc = add(mul(acc, sixteen), fromLong(d.toLong()))
        }
        return acc
    }

    // Little-endian byte decoding (the Ed25519 wire order).
    fun fromBytesLE(b: ByteArray): IntArray {
        val limbs = IntArray((b.size + 1) / 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xFF
            if (i % 2 == 0) limbs[i / 2] = limbs[i / 2] or v
            else limbs[i / 2] = limbs[i / 2] or (v shl 8)
        }
        return norm(limbs)
    }

    // Little-endian byte encoding, zero-padded to exactly len bytes.
    fun toBytesLE(a: IntArray, len: Int): ByteArray {
        val out = ByteArray(len)
        for (i in 0 until len) {
            val limb = i / 2
            if (limb >= a.size) break
            val v = if (i % 2 == 0) a[limb] and 0xFF else (a[limb] ushr 8) and 0xFF
            out[i] = v.toByte()
        }
        return out
    }

    fun cmp(a: IntArray, b: IntArray): Int {
        if (a.size != b.size) return if (a.size > b.size) 1 else -1
        for (i in a.size - 1 downTo 0) {
            if (a[i] != b[i]) return if (a[i] > b[i]) 1 else -1
        }
        return 0
    }

    fun add(a: IntArray, b: IntArray): IntArray {
        val n = maxOf(a.size, b.size)
        val out = IntArray(n + 1)
        var carry = 0
        for (i in 0 until n) {
            val s = (if (i < a.size) a[i] else 0) + (if (i < b.size) b[i] else 0) + carry
            out[i] = s and 0xFFFF
            carry = s ushr 16
        }
        out[n] = carry
        return norm(out)
    }

    // Subtraction; requires a >= b (the caller keeps everything non-negative).
    fun sub(a: IntArray, b: IntArray): IntArray {
        require(cmp(a, b) >= 0) { "Bignum.sub underflow" }
        val out = IntArray(a.size)
        var borrow = 0
        for (i in a.indices) {
            var s = a[i] - (if (i < b.size) b[i] else 0) - borrow
            if (s < 0) { s += 0x10000; borrow = 1 } else borrow = 0
            out[i] = s
        }
        return norm(out)
    }

    // Schoolbook multiplication with a Long accumulator per column.
    fun mul(a: IntArray, b: IntArray): IntArray {
        if (a.isEmpty() || b.isEmpty()) return ZERO
        val acc = LongArray(a.size + b.size)
        for (i in a.indices) {
            val ai = a[i].toLong()
            for (j in b.indices) {
                acc[i + j] += ai * b[j]
            }
            // Propagate partial carries every row so columns never overflow Long.
            if (i % 16 == 15) {
                var carry = 0L
                for (k in acc.indices) {
                    val t = acc[k] + carry
                    acc[k] = t and 0xFFFF
                    carry = t ushr 16
                }
            }
        }
        var carry = 0L
        val out = IntArray(acc.size)
        for (k in acc.indices) {
            val t = acc[k] + carry
            out[k] = (t and 0xFFFF).toInt()
            carry = t ushr 16
        }
        require(carry == 0L)
        return norm(out)
    }

    fun bitLen(a: IntArray): Int {
        if (a.isEmpty()) return 0
        var top = a[a.size - 1]
        var bits = (a.size - 1) * 16
        while (top != 0) { bits++; top = top ushr 1 }
        return bits
    }

    fun testBit(a: IntArray, i: Int): Boolean {
        val limb = i / 16
        if (limb >= a.size) return false
        return (a[limb] ushr (i % 16)) and 1 == 1
    }

    fun shl(a: IntArray, bits: Int): IntArray {
        if (a.isEmpty() || bits == 0) return a
        val limbShift = bits / 16
        val bitShift = bits % 16
        val out = IntArray(a.size + limbShift + 1)
        for (i in a.indices) {
            val v = a[i] shl bitShift
            out[i + limbShift] = out[i + limbShift] or (v and 0xFFFF)
            out[i + limbShift + 1] = out[i + limbShift + 1] or (v ushr 16)
        }
        return norm(out)
    }

    fun shr(a: IntArray, bits: Int): IntArray {
        if (a.isEmpty() || bits == 0) return a
        val limbShift = bits / 16
        val bitShift = bits % 16
        if (limbShift >= a.size) return ZERO
        val out = IntArray(a.size - limbShift)
        for (i in out.indices) {
            var v = a[i + limbShift] ushr bitShift
            if (bitShift != 0 && i + limbShift + 1 < a.size) {
                v = v or ((a[i + limbShift + 1] shl (16 - bitShift)) and 0xFFFF)
            }
            out[i] = v
        }
        return norm(out)
    }

    // General modulus by binary shift-and-subtract (used for the group order q;
    // the field prime p has its own fast fold in Ed25519).
    fun mod(x: IntArray, m: IntArray): IntArray {
        require(!isZero(m)) { "modulus is zero" }
        if (cmp(x, m) < 0) return x
        var r = x
        var shift = bitLen(x) - bitLen(m)
        var t = shl(m, shift)
        while (shift >= 0) {
            if (cmp(r, t) >= 0) r = sub(r, t)
            t = shr(t, 1)
            shift--
        }
        return r
    }

    // Divide by a small positive divisor; returns quotient and remainder.
    fun divSmall(a: IntArray, d: Int): Pair<IntArray, Int> {
        require(d in 1..0xFFFF)
        val out = IntArray(a.size)
        var rem = 0L
        for (i in a.size - 1 downTo 0) {
            val cur = (rem shl 16) or a[i].toLong()
            out[i] = (cur / d).toInt()
            rem = cur % d
        }
        return Pair(norm(out), rem.toInt())
    }

    // Exact decimal rendering (used by JCS for integral doubles beyond 2^63).
    fun toDecimalString(a: IntArray): String {
        if (isZero(a)) return "0"
        val sb = StringBuilder()
        var cur = a
        while (!isZero(cur)) {
            val (q, r) = divSmall(cur, 10000)
            cur = q
            if (isZero(cur)) sb.append(r.toString().reversed())
            else sb.append(r.toString().padStart(4, '0').reversed())
        }
        return sb.toString().reversed()
    }
}

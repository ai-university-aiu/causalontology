// Ed25519 digital signatures (RFC 8032), pure Kotlin, ported line-for-line
// from the Python binding's ed25519.py over the Bignum layer.
//
// Slow but correct: intended for the conformance suite and small tools.
// All field arithmetic stays non-negative (a - b mod p is computed as
// a + p - b), and reduction mod p = 2^255 - 19 uses the limb-aligned fold
// 2^256 = 38 (mod p). Gated on the RFC 8032 TEST 1 known answer by
// checkKnownAnswer() (called from the conformance runner's internal checks).
package org.causalontology

object Ed25519 {

    // p = 2^255 - 19 (the field prime).
    private val P = Bignum.fromHex(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
    // q = 2^252 + 27742317777372353535851937790883648493 (the group order).
    private val Q = Bignum.fromHex(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")

    private val THIRTY_EIGHT = intArrayOf(38)

    // ------------------------------------------------------ field arithmetic
    // Reduce an arbitrary product to [0, p) by folding at the 16-limb (2^256)
    // boundary: x = hi * 2^256 + lo = hi * 38 + lo (mod p).
    private fun reduceP(xIn: IntArray): IntArray {
        var x = xIn
        while (x.size > 16) {
            val lo = Bignum.norm(x.copyOf(16))
            val hi = x.copyOfRange(16, x.size)
            x = Bignum.add(lo, Bignum.mul(hi, THIRTY_EIGHT))
        }
        while (Bignum.cmp(x, P) >= 0) x = Bignum.sub(x, P)
        return x
    }

    private fun addP(a: IntArray, b: IntArray): IntArray = reduceP(Bignum.add(a, b))

    // a - b mod p, computed non-negatively as (a + p) - b.
    private fun subP(a: IntArray, b: IntArray): IntArray =
        reduceP(Bignum.sub(Bignum.add(a, P), b))

    private fun mulP(a: IntArray, b: IntArray): IntArray = reduceP(Bignum.mul(a, b))

    // Modular exponentiation mod p by square-and-multiply over exp's bits.
    private fun powP(base: IntArray, exp: IntArray): IntArray {
        var result = Bignum.ONE
        var b = reduceP(base)
        val bits = Bignum.bitLen(exp)
        for (i in 0 until bits) {
            if (Bignum.testBit(exp, i)) result = mulP(result, b)
            b = mulP(b, b)
        }
        return result
    }

    // Modular inverse by Fermat's little theorem: x^(p-2) mod p.
    private fun invP(x: IntArray): IntArray = powP(x, Bignum.sub(P, Bignum.fromLong(2)))

    // ------------------------------------------------------- curve constants
    // d = -121665 * inv(121666) mod p.
    private val D = mulP(
        Bignum.sub(P, Bignum.fromLong(121665)),
        invP(Bignum.fromLong(121666)))

    // sqrt(-1) = 2^((p-1)/4) mod p.
    private val SQRT_M1 = powP(
        Bignum.fromLong(2),
        Bignum.shr(Bignum.sub(P, Bignum.ONE), 2))

    // (p + 3) / 8, the exponent used in x-recovery.
    private val PP3_D8 = Bignum.shr(Bignum.add(P, Bignum.fromLong(3)), 3)

    // A point is (X, Y, Z, T) in extended homogeneous coordinates.
    private class Point(val x: IntArray, val y: IntArray, val z: IntArray, val t: IntArray)

    // The neutral element (0, 1, 1, 0).
    private val NEUTRAL = Point(Bignum.ZERO, Bignum.ONE, Bignum.ONE, Bignum.ZERO)

    // The base point G: y = 4 * inv(5) mod p, x recovered with sign 0.
    private val G: Point = run {
        val gy = mulP(Bignum.fromLong(4), invP(Bignum.fromLong(5)))
        val gx = recoverX(gy, 0) ?: throw IllegalStateException("base point recovery failed")
        Point(gx, gy, Bignum.ONE, mulP(gx, gy))
    }

    // ------------------------------------------------------------ point ops
    private fun pointAdd(p1: Point, p2: Point): Point {
        val a = mulP(subP(p1.y, p1.x), subP(p2.y, p2.x))
        val b = mulP(addP(p1.y, p1.x), addP(p2.y, p2.x))
        val c = mulP(mulP(Bignum.fromLong(2), mulP(p1.t, p2.t)), D)
        val d2 = mulP(Bignum.fromLong(2), mulP(p1.z, p2.z))
        val e = subP(b, a)
        val f = subP(d2, c)
        val g = addP(d2, c)
        val h = addP(b, a)
        return Point(mulP(e, f), mulP(g, h), mulP(f, g), mulP(e, h))
    }

    private fun pointMul(sIn: IntArray, pIn: Point): Point {
        var q = NEUTRAL
        var p1 = pIn
        val bits = Bignum.bitLen(sIn)
        for (i in 0 until bits) {
            if (Bignum.testBit(sIn, i)) q = pointAdd(q, p1)
            p1 = pointAdd(p1, p1)
        }
        return q
    }

    private fun pointEqual(p1: Point, p2: Point): Boolean {
        // Cross-multiplied comparison avoids inversions; both sides are in [0, p).
        if (Bignum.cmp(mulP(p1.x, p2.z), mulP(p2.x, p1.z)) != 0) return false
        if (Bignum.cmp(mulP(p1.y, p2.z), mulP(p2.y, p1.z)) != 0) return false
        return true
    }

    // ------------------------------------------------- compression / recovery
    private fun recoverX(y: IntArray, sign: Int): IntArray? {
        if (Bignum.cmp(y, P) >= 0) return null
        val y2 = mulP(y, y)
        val x2 = mulP(subP(y2, Bignum.ONE), invP(addP(mulP(D, y2), Bignum.ONE)))
        if (Bignum.isZero(x2)) {
            return if (sign != 0) null else Bignum.ZERO
        }
        var x = powP(x2, PP3_D8)
        if (!Bignum.isZero(subP(mulP(x, x), x2))) {
            x = mulP(x, SQRT_M1)
        }
        if (!Bignum.isZero(subP(mulP(x, x), x2))) return null
        if ((if (Bignum.testBit(x, 0)) 1 else 0) != sign) {
            x = Bignum.sub(P, x)
        }
        return x
    }

    private fun pointCompress(p1: Point): ByteArray {
        val zinv = invP(p1.z)
        val x = mulP(p1.x, zinv)
        val y = mulP(p1.y, zinv)
        val out = Bignum.toBytesLE(y, 32)
        if (Bignum.testBit(x, 0)) {
            out[31] = (out[31].toInt() or 0x80).toByte()
        }
        return out
    }

    private fun pointDecompress(s: ByteArray): Point? {
        if (s.size != 32) return null
        val sign = (s[31].toInt() ushr 7) and 1
        val yBytes = s.copyOf()
        yBytes[31] = (yBytes[31].toInt() and 0x7F).toByte()
        val y = Bignum.fromBytesLE(yBytes)
        val x = recoverX(y, sign) ?: return null
        return Point(x, y, Bignum.ONE, mulP(x, y))
    }

    // ------------------------------------------------------ scalars and keys
    private fun secretExpand(secret: ByteArray): Pair<IntArray, ByteArray> {
        if (secret.size != 32) throw IllegalArgumentException("secret key must be 32 bytes")
        val h = Sha2.sha512(secret)
        val a = h.copyOfRange(0, 32)
        // Clamp: clear bits 0..2 and bit 255, set bit 254 (RFC 8032).
        a[0] = (a[0].toInt() and 0xF8).toByte()
        a[31] = (a[31].toInt() and 0x3F).toByte()
        a[31] = (a[31].toInt() or 0x40).toByte()
        return Pair(Bignum.fromBytesLE(a), h.copyOfRange(32, 64))
    }

    private fun sha512ModQ(msg: ByteArray): IntArray =
        Bignum.mod(Bignum.fromBytesLE(Sha2.sha512(msg)), Q)

    // ------------------------------------------------------------ public API
    fun secretToPublic(secret: ByteArray): ByteArray {
        val (a, _) = secretExpand(secret)
        return pointCompress(pointMul(a, G))
    }

    fun sign(secret: ByteArray, msg: ByteArray): ByteArray {
        val (a, prefix) = secretExpand(secret)
        val aPub = pointCompress(pointMul(a, G))
        val r = sha512ModQ(prefix + msg)
        val rs = pointCompress(pointMul(r, G))
        val h = sha512ModQ(rs + aPub + msg)
        val s = Bignum.mod(Bignum.add(r, Bignum.mul(h, a)), Q)
        return rs + Bignum.toBytesLE(s, 32)
    }

    fun verify(public: ByteArray, msg: ByteArray, signature: ByteArray): Boolean {
        if (public.size != 32 || signature.size != 64) return false
        val aPoint = pointDecompress(public) ?: return false
        val rs = signature.copyOfRange(0, 32)
        val rPoint = pointDecompress(rs) ?: return false
        val s = Bignum.fromBytesLE(signature.copyOfRange(32, 64))
        if (Bignum.cmp(s, Q) >= 0) return false
        val h = sha512ModQ(rs + public + msg)
        val sB = pointMul(s, G)
        val hA = pointMul(h, aPoint)
        return pointEqual(sB, pointAdd(rPoint, hA))
    }

    // --------------------------------------------------- known-answer gate
    // RFC 8032 section 7.1 TEST 1: seed, public key, and the exact signature
    // of the empty message; plus rejection of a wrong message.
    fun checkKnownAnswer() {
        val seed = hexToBytes(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")!!
        val pub = secretToPublic(seed)
        check(bytesToHex(pub) ==
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") {
            "RFC 8032 TEST 1 public key mismatch: ${bytesToHex(pub)}"
        }
        val sig = sign(seed, ByteArray(0))
        check(bytesToHex(sig) ==
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b") {
            "RFC 8032 TEST 1 signature mismatch: ${bytesToHex(sig)}"
        }
        check(verify(pub, ByteArray(0), sig)) { "RFC 8032 TEST 1 signature must verify" }
        check(!verify(pub, "x".encodeToByteArray(), sig)) {
            "RFC 8032 TEST 1 signature must not verify a different message"
        }
    }
}

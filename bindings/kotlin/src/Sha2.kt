// SHA-256 and SHA-512 (FIPS 180-4), pure Kotlin.
//
// SHA-256 runs in Int words; SHA-512 runs in Long words with Kotlin's naturally
// wrapping adds and ushr for the logical shifts. Both are gated on the
// empty-string known answers by checkKnownAnswers() (called from the
// conformance runner's internal checks).
package org.causalontology

object Sha2 {

    // ------------------------------------------------------------- SHA-256
    private val K256 = longArrayOf(
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ).map { it.toInt() }.toIntArray()

    private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32 - n))

    fun sha256(msg: ByteArray): ByteArray {
        // Pad: 0x80, zeros, then the 64-bit bit length, to a multiple of 64 bytes.
        val bitLen = msg.size.toLong() * 8
        var padded = msg + byteArrayOf(0x80.toByte())
        while (padded.size % 64 != 56) padded += 0.toByte()
        for (i in 7 downTo 0) padded += ((bitLen ushr (i * 8)) and 0xFF).toByte()

        var h0 = 0x6a09e667; var h1 = 0xbb67ae85.toInt(); var h2 = 0x3c6ef372; var h3 = 0xa54ff53a.toInt()
        var h4 = 0x510e527f; var h5 = 0x9b05688c.toInt(); var h6 = 0x1f83d9ab; var h7 = 0x5be0cd19

        val w = IntArray(64)
        var block = 0
        while (block < padded.size) {
            for (t in 0 until 16) {
                val o = block + t * 4
                w[t] = ((padded[o].toInt() and 0xFF) shl 24) or
                       ((padded[o + 1].toInt() and 0xFF) shl 16) or
                       ((padded[o + 2].toInt() and 0xFF) shl 8) or
                       (padded[o + 3].toInt() and 0xFF)
            }
            for (t in 16 until 64) {
                val s0 = rotr(w[t - 15], 7) xor rotr(w[t - 15], 18) xor (w[t - 15] ushr 3)
                val s1 = rotr(w[t - 2], 17) xor rotr(w[t - 2], 19) xor (w[t - 2] ushr 10)
                w[t] = w[t - 16] + s0 + w[t - 7] + s1
            }
            var a = h0; var b = h1; var c = h2; var d = h3
            var e = h4; var f = h5; var g = h6; var h = h7
            for (t in 0 until 64) {
                val s1 = rotr(e, 6) xor rotr(e, 11) xor rotr(e, 25)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = h + s1 + ch + K256[t] + w[t]
                val s0 = rotr(a, 2) xor rotr(a, 13) xor rotr(a, 22)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj
                h = g; g = f; f = e; e = d + temp1
                d = c; c = b; b = a; a = temp1 + temp2
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h
            block += 64
        }

        val out = ByteArray(32)
        val hs = intArrayOf(h0, h1, h2, h3, h4, h5, h6, h7)
        for (i in 0 until 8) {
            out[i * 4] = (hs[i] ushr 24).toByte()
            out[i * 4 + 1] = (hs[i] ushr 16).toByte()
            out[i * 4 + 2] = (hs[i] ushr 8).toByte()
            out[i * 4 + 3] = hs[i].toByte()
        }
        return out
    }

    fun sha256Hex(msg: ByteArray): String = bytesToHex(sha256(msg))

    // ------------------------------------------------------------- SHA-512
    private val K512 = ulongArrayOf(
        0x428a2f98d728ae22uL, 0x7137449123ef65cduL, 0xb5c0fbcfec4d3b2fuL, 0xe9b5dba58189dbbcuL,
        0x3956c25bf348b538uL, 0x59f111f1b605d019uL, 0x923f82a4af194f9buL, 0xab1c5ed5da6d8118uL,
        0xd807aa98a3030242uL, 0x12835b0145706fbeuL, 0x243185be4ee4b28cuL, 0x550c7dc3d5ffb4e2uL,
        0x72be5d74f27b896fuL, 0x80deb1fe3b1696b1uL, 0x9bdc06a725c71235uL, 0xc19bf174cf692694uL,
        0xe49b69c19ef14ad2uL, 0xefbe4786384f25e3uL, 0x0fc19dc68b8cd5b5uL, 0x240ca1cc77ac9c65uL,
        0x2de92c6f592b0275uL, 0x4a7484aa6ea6e483uL, 0x5cb0a9dcbd41fbd4uL, 0x76f988da831153b5uL,
        0x983e5152ee66dfabuL, 0xa831c66d2db43210uL, 0xb00327c898fb213fuL, 0xbf597fc7beef0ee4uL,
        0xc6e00bf33da88fc2uL, 0xd5a79147930aa725uL, 0x06ca6351e003826fuL, 0x142929670a0e6e70uL,
        0x27b70a8546d22ffcuL, 0x2e1b21385c26c926uL, 0x4d2c6dfc5ac42aeduL, 0x53380d139d95b3dfuL,
        0x650a73548baf63deuL, 0x766a0abb3c77b2a8uL, 0x81c2c92e47edaee6uL, 0x92722c851482353buL,
        0xa2bfe8a14cf10364uL, 0xa81a664bbc423001uL, 0xc24b8b70d0f89791uL, 0xc76c51a30654be30uL,
        0xd192e819d6ef5218uL, 0xd69906245565a910uL, 0xf40e35855771202auL, 0x106aa07032bbd1b8uL,
        0x19a4c116b8d2d0c8uL, 0x1e376c085141ab53uL, 0x2748774cdf8eeb99uL, 0x34b0bcb5e19b48a8uL,
        0x391c0cb3c5c95a63uL, 0x4ed8aa4ae3418acbuL, 0x5b9cca4f7763e373uL, 0x682e6ff3d6b2b8a3uL,
        0x748f82ee5defb2fcuL, 0x78a5636f43172f60uL, 0x84c87814a1f0ab72uL, 0x8cc702081a6439ecuL,
        0x90befffa23631e28uL, 0xa4506cebde82bde9uL, 0xbef9a3f7b2c67915uL, 0xc67178f2e372532buL,
        0xca273eceea26619cuL, 0xd186b8c721c0c207uL, 0xeada7dd6cde0eb1euL, 0xf57d4f7fee6ed178uL,
        0x06f067aa72176fbauL, 0x0a637dc5a2c898a6uL, 0x113f9804bef90daeuL, 0x1b710b35131c471buL,
        0x28db77f523047d84uL, 0x32caab7b40c72493uL, 0x3c9ebe0a15c9bebcuL, 0x431d67c49c100d4cuL,
        0x4cc5d4becb3e42b6uL, 0x597f299cfc657e2auL, 0x5fcb6fab3ad6faecuL, 0x6c44198c4a475817uL
    ).map { it.toLong() }.toLongArray()

    private fun rotrL(x: Long, n: Int): Long = (x ushr n) or (x shl (64 - n))

    fun sha512(msg: ByteArray): ByteArray {
        // Pad: 0x80, zeros, then the 128-bit bit length, to a multiple of 128 bytes
        // (the high 64 bits of the length are zero for any message we can hold).
        val bitLen = msg.size.toLong() * 8
        var padded = msg + byteArrayOf(0x80.toByte())
        while (padded.size % 128 != 112) padded += 0.toByte()
        for (i in 0 until 8) padded += 0.toByte()  // high 64 bits of the length
        for (i in 7 downTo 0) padded += ((bitLen ushr (i * 8)) and 0xFF).toByte()

        var h0 = 0x6a09e667f3bcc908uL.toLong(); var h1 = 0xbb67ae8584caa73buL.toLong()
        var h2 = 0x3c6ef372fe94f82buL.toLong(); var h3 = 0xa54ff53a5f1d36f1uL.toLong()
        var h4 = 0x510e527fade682d1uL.toLong(); var h5 = 0x9b05688c2b3e6c1fuL.toLong()
        var h6 = 0x1f83d9abfb41bd6buL.toLong(); var h7 = 0x5be0cd19137e2179uL.toLong()

        val w = LongArray(80)
        var block = 0
        while (block < padded.size) {
            for (t in 0 until 16) {
                var v = 0L
                for (b in 0 until 8) v = (v shl 8) or (padded[block + t * 8 + b].toLong() and 0xFF)
                w[t] = v
            }
            for (t in 16 until 80) {
                val s0 = rotrL(w[t - 15], 1) xor rotrL(w[t - 15], 8) xor (w[t - 15] ushr 7)
                val s1 = rotrL(w[t - 2], 19) xor rotrL(w[t - 2], 61) xor (w[t - 2] ushr 6)
                w[t] = w[t - 16] + s0 + w[t - 7] + s1
            }
            var a = h0; var b = h1; var c = h2; var d = h3
            var e = h4; var f = h5; var g = h6; var h = h7
            for (t in 0 until 80) {
                val s1 = rotrL(e, 14) xor rotrL(e, 18) xor rotrL(e, 41)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = h + s1 + ch + K512[t] + w[t]
                val s0 = rotrL(a, 28) xor rotrL(a, 34) xor rotrL(a, 39)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj
                h = g; g = f; f = e; e = d + temp1
                d = c; c = b; b = a; a = temp1 + temp2
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h
            block += 128
        }

        val out = ByteArray(64)
        val hs = longArrayOf(h0, h1, h2, h3, h4, h5, h6, h7)
        for (i in 0 until 8) {
            for (b in 0 until 8) out[i * 8 + b] = (hs[i] ushr ((7 - b) * 8)).toByte()
        }
        return out
    }

    // --------------------------------------------------- known-answer gates
    fun checkKnownAnswers() {
        val e256 = sha256Hex(ByteArray(0))
        check(e256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
            "SHA-256 empty-string known answer failed: $e256"
        }
        val e512 = bytesToHex(sha512(ByteArray(0)))
        check(e512.startsWith("cf83e1357eefb8bd") &&
              e512 == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") {
            "SHA-512 empty-string known answer failed: $e512"
        }
    }
}

// ------------------------------------------------------------- hex helpers
private val HEX_CHARS = "0123456789abcdef"

fun bytesToHex(b: ByteArray): String {
    val sb = StringBuilder(b.size * 2)
    for (x in b) {
        val v = x.toInt() and 0xFF
        sb.append(HEX_CHARS[v ushr 4]).append(HEX_CHARS[v and 0xF])
    }
    return sb.toString()
}

// Strict lowercase/uppercase hex decoding; null on any malformed input
// (mirrors Python's bytes.fromhex raising ValueError).
fun hexToBytes(s: String): ByteArray? {
    if (s.length % 2 != 0) return null
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
        val hi = hexVal(s[i * 2]) ?: return null
        val lo = hexVal(s[i * 2 + 1]) ?: return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

private fun hexVal(c: Char): Int? = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> null
}

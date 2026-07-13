package org.causalontology;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Ed25519 digital signatures (RFC 8032), JDK standard library only.
 *
 * Signing and verification use java.security's "Ed25519" Signature (JDK 15
 * and newer). The one operation the JDK does not expose - deriving the
 * public key from a 32-byte seed - is computed here with BigInteger point
 * arithmetic, ported line for line from the RFC 8032 reference procedure
 * (the same port the Python binding uses). The raw public key encoding is
 * the RFC 8032 compressed form: the y coordinate as 32 little-endian bytes
 * with the x-parity bit stored in the top bit of the last byte.
 *
 * selfTest() checks the whole path against the RFC 8032 TEST 1 known
 * answer at startup.
 */
public final class Ed25519 {

    // The field prime p = 2^255 - 19.
    private static final BigInteger P =
        BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

    // The twisted Edwards curve constant d = -121665 / 121666 mod p.
    private static final BigInteger D =
        BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P))
            .mod(P);

    // A square root of -1 mod p: 2^((p-1)/4) mod p.
    private static final BigInteger SQRT_M1 =
        BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    // The base point G in extended homogeneous coordinates (X, Y, Z, T).
    private static final BigInteger[] G;

    static {
        BigInteger gy = BigInteger.valueOf(4)
            .multiply(BigInteger.valueOf(5).modInverse(P)).mod(P);
        BigInteger gx = recoverX(gy, 0);
        if (gx == null) {
            throw new IllegalStateException(
                "Ed25519 base point recovery failed");
        }
        G = new BigInteger[] {gx, gy, BigInteger.ONE,
                              gx.multiply(gy).mod(P)};
    }

    private Ed25519() {
    }

    // -------------------------------------------------- point arithmetic

    /** Recover the x coordinate for a y coordinate and a parity bit. */
    private static BigInteger recoverX(BigInteger y, int sign) {
        if (y.compareTo(P) >= 0) {
            return null;
        }
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger denominator = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger x2 = y2.subtract(BigInteger.ONE)
            .multiply(denominator.modInverse(P)).mod(P);
        if (x2.signum() == 0) {
            return sign != 0 ? null : BigInteger.ZERO;
        }
        // Candidate square root: x = x2 ^ ((p+3)/8) mod p.
        BigInteger x = x2.modPow(
            P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) {
            x = x.multiply(SQRT_M1).mod(P);
        }
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) {
            return null;
        }
        boolean xIsOdd = x.testBit(0);
        if (xIsOdd != (sign == 1)) {
            x = P.subtract(x);
        }
        return x;
    }

    /** Point addition in extended homogeneous coordinates. */
    private static BigInteger[] pointAdd(BigInteger[] a, BigInteger[] b) {
        BigInteger valueA =
            a[1].subtract(a[0]).multiply(b[1].subtract(b[0])).mod(P);
        BigInteger valueB =
            a[1].add(a[0]).multiply(b[1].add(b[0])).mod(P);
        BigInteger valueC =
            BigInteger.TWO.multiply(a[3]).multiply(b[3]).multiply(D).mod(P);
        BigInteger valueD =
            BigInteger.TWO.multiply(a[2]).multiply(b[2]).mod(P);
        BigInteger e = valueB.subtract(valueA);
        BigInteger f = valueD.subtract(valueC);
        BigInteger g = valueD.add(valueC);
        BigInteger h = valueB.add(valueA);
        return new BigInteger[] {
            e.multiply(f).mod(P),
            g.multiply(h).mod(P),
            f.multiply(g).mod(P),
            e.multiply(h).mod(P)
        };
    }

    /** Scalar multiplication by repeated doubling. */
    private static BigInteger[] pointMul(BigInteger scalar, BigInteger[] point) {
        BigInteger[] q = new BigInteger[] {BigInteger.ZERO, BigInteger.ONE,
                                           BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] current = point;
        BigInteger k = scalar;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                q = pointAdd(q, current);
            }
            current = pointAdd(current, current);
            k = k.shiftRight(1);
        }
        return q;
    }

    /** The RFC 8032 compressed 32-byte encoding of a point. */
    private static byte[] pointCompress(BigInteger[] point) {
        BigInteger zInverse = point[2].modInverse(P);
        BigInteger x = point[0].multiply(zInverse).mod(P);
        BigInteger y = point[1].multiply(zInverse).mod(P);
        BigInteger encoded = x.testBit(0) ? y.setBit(255) : y;
        return toLittleEndian32(encoded);
    }

    // --------------------------------------------------- byte utilities

    private static BigInteger fromLittleEndian(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return new BigInteger(1, reversed);
    }

    private static byte[] toLittleEndian32(BigInteger value) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = value.shiftRight(8 * i).byteValue();
        }
        return out;
    }

    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }

    // ---------------------------------------------------- key operations

    /** The 32-byte public key for a 32-byte secret key (the seed). */
    public static byte[] secretToPublic(byte[] secret) {
        if (secret.length != 32) {
            throw new IllegalArgumentException("secret key must be 32 bytes");
        }
        byte[] h = sha512(secret);
        BigInteger a = fromLittleEndian(Arrays.copyOfRange(h, 0, 32));
        // RFC 8032 clamping: clear the low 3 bits and bit 255, set bit 254.
        a = a.and(BigInteger.ONE.shiftLeft(254).subtract(BigInteger.valueOf(8)))
             .or(BigInteger.ONE.shiftLeft(254));
        return pointCompress(pointMul(a, G));
    }

    /** The 64-byte Ed25519 signature of msg under the 32-byte secret key. */
    public static byte[] sign(byte[] secret, byte[] msg) {
        if (secret.length != 32) {
            throw new IllegalArgumentException("secret key must be 32 bytes");
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = keyFactory.generatePrivate(
                new EdECPrivateKeySpec(NamedParameterSpec.ED25519, secret));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(msg);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    /** True iff signature is a valid signature of msg under public. */
    public static boolean verify(byte[] publicRaw, byte[] msg,
                                 byte[] signature) {
        if (publicRaw == null || signature == null) {
            return false;
        }
        if (publicRaw.length != 32 || signature.length != 64) {
            return false;
        }
        try {
            // Decode the compressed form: y little-endian with the
            // x-parity bit in the top bit of the last byte.
            byte[] yBytes = publicRaw.clone();
            boolean xOdd = (yBytes[31] & 0x80) != 0;
            yBytes[31] = (byte) (yBytes[31] & 0x7F);
            BigInteger y = fromLittleEndian(yBytes);
            if (y.compareTo(P) >= 0) {
                return false;
            }
            EdECPoint point = new EdECPoint(xOdd, y);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            PublicKey publicKey = keyFactory.generatePublic(
                new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(msg);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ------------------------------------------------------ known answer

    /** RFC 8032, TEST 1: fail loudly if this JDK path is not conformant. */
    public static void selfTest() {
        byte[] seed = HexFormat.of().parseHex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] publicKey = secretToPublic(seed);
        String publicHex = HexFormat.of().formatHex(publicKey);
        String expected =
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        if (!publicHex.equals(expected)) {
            throw new IllegalStateException(
                "Ed25519 known-answer public key mismatch: " + publicHex);
        }
        byte[] emptyMessage = new byte[0];
        byte[] signature = sign(seed, emptyMessage);
        if (signature.length != 64) {
            throw new IllegalStateException(
                "Ed25519 signature is not 64 bytes");
        }
        if (!verify(publicKey, emptyMessage, signature)) {
            throw new IllegalStateException(
                "Ed25519 known-answer signature did not verify");
        }
        byte[] otherMessage = new byte[] {(byte) 'x'};
        if (verify(publicKey, otherMessage, signature)) {
            throw new IllegalStateException(
                "Ed25519 verified a signature over the wrong message");
        }
    }
}

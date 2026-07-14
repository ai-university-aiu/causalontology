// Ed25519 digital signatures (RFC 8032), pure C#, BCL only.
//
// The BCL has no Ed25519, so this is a faithful port of the Python
// binding's ed25519.py onto System.Numerics.BigInteger. Slow but
// correct: intended for the conformance suite and for small tools.
// Production stores should use an optimized library; the signatures are
// byte-compatible either way (Ed25519 is deterministic, RFC 8032).
//
// CRITICAL porting note: C#'s % operator can return negatives, unlike
// Python's; every reduction goes through Mod(), which normalizes with
// ((a % p) + p) % p. The whole module is gated on the RFC 8032 TEST 1
// known answer by the conformance runner before any vector runs.

using System.Numerics;
using System.Security.Cryptography;

namespace Causalontology;

public static class Ed25519
{
    // the field prime p = 2^255 - 19
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    // the group order q = 2^252 + 27742317777372353535851937790883648493
    private static readonly BigInteger Q = BigInteger.Pow(2, 252)
        + BigInteger.Parse("27742317777372353535851937790883648493");

    // ((a % p) + p) % p — a nonnegative residue even when a is negative
    private static BigInteger Mod(BigInteger a) => ((a % P) + P) % P;

    private static BigInteger ModpInv(BigInteger x)
        => BigInteger.ModPow(Mod(x), P - 2, P);

    // the curve constant d = -121665 / 121666 (mod p)
    private static readonly BigInteger D = Mod(-121665 * ModpInv(121666));

    private static readonly BigInteger ModpSqrtM1
        = BigInteger.ModPow(2, (P - 1) / 4, P);

    // extended homogeneous coordinates (X, Y, Z, T)
    private readonly record struct Point(
        BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    private static Point PointAdd(Point p, Point q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X));
        var b = Mod((p.Y + p.X) * (q.Y + q.X));
        var c = Mod(2 * p.T * q.T * D);
        var d = Mod(2 * p.Z * q.Z);
        BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point PointMul(BigInteger s, Point p)
    {
        var q = new Point(0, 1, 1, 0); // the neutral element
        while (s > 0)
        {
            if (!s.IsEven)
                q = PointAdd(q, p);
            p = PointAdd(p, p);
            s >>= 1;
        }
        return q;
    }

    private static bool PointEqual(Point p, Point q)
    {
        if (Mod(p.X * q.Z - q.X * p.Z) != 0)
            return false;
        if (Mod(p.Y * q.Z - q.Y * p.Z) != 0)
            return false;
        return true;
    }

    private static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y >= P)
            return null;
        var x2 = Mod((y * y - 1) * ModpInv(D * y * y + 1));
        if (x2.IsZero)
            return sign != 0 ? null : BigInteger.Zero;
        var x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (Mod(x * x - x2) != 0)
            x = Mod(x * ModpSqrtM1);
        if (Mod(x * x - x2) != 0)
            return null;
        if ((int)(x & 1) != sign)
            x = P - x;
        return x;
    }

    // the base point G
    private static readonly Point G = MakeBasePoint();

    private static Point MakeBasePoint()
    {
        var gy = Mod(4 * ModpInv(5));
        var gx = RecoverX(gy, 0)!.Value;
        return new Point(gx, gy, 1, Mod(gx * gy));
    }

    private static byte[] PointCompress(Point p)
    {
        var zinv = ModpInv(p.Z);
        var x = Mod(p.X * zinv);
        var y = Mod(p.Y * zinv);
        var value = y | ((x & 1) << 255);
        var bytes = new byte[32];
        value.TryWriteBytes(bytes, out _, isUnsigned: true, isBigEndian: false);
        return bytes;
    }

    private static Point? PointDecompress(byte[] s)
    {
        if (s.Length != 32)
            return null;
        var y = new BigInteger(s, isUnsigned: true, isBigEndian: false);
        var sign = (int)(y >> 255);
        y &= (BigInteger.One << 255) - 1;
        var x = RecoverX(y, sign);
        if (x is null)
            return null;
        return new Point(x.Value, y, 1, Mod(x.Value * y));
    }

    private static (BigInteger A, byte[] Prefix) SecretExpand(byte[] secret)
    {
        if (secret.Length != 32)
            throw new ArgumentException("secret key must be 32 bytes");
        var h = SHA512.HashData(secret);
        var a = new BigInteger(h.AsSpan(0, 32),
                               isUnsigned: true, isBigEndian: false);
        a &= (BigInteger.One << 254) - 8;
        a |= BigInteger.One << 254;
        return (a, h[32..]);
    }

    private static BigInteger Sha512ModQ(byte[] s)
    {
        var h = SHA512.HashData(s);
        return new BigInteger(h, isUnsigned: true, isBigEndian: false) % Q;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var joined = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            Buffer.BlockCopy(part, 0, joined, offset, part.Length);
            offset += part.Length;
        }
        return joined;
    }

    /// <summary>The 32-byte public key for a 32-byte secret key.</summary>
    public static byte[] SecretToPublic(byte[] secret)
    {
        var (a, _) = SecretExpand(secret);
        return PointCompress(PointMul(a, G));
    }

    /// <summary>The 64-byte Ed25519 signature of msg under the 32-byte secret key.</summary>
    public static byte[] Sign(byte[] secret, byte[] msg)
    {
        var (a, prefix) = SecretExpand(secret);
        var publicKey = PointCompress(PointMul(a, G));
        var r = Sha512ModQ(Concat(prefix, msg));
        var rs = PointCompress(PointMul(r, G));
        var h = Sha512ModQ(Concat(rs, publicKey, msg));
        var s = ((r + h * a) % Q + Q) % Q;
        var sBytes = new byte[32];
        s.TryWriteBytes(sBytes, out _, isUnsigned: true, isBigEndian: false);
        return Concat(rs, sBytes);
    }

    /// <summary>True iff signature is a valid Ed25519 signature of msg under publicKey.</summary>
    public static bool Verify(byte[] publicKey, byte[] msg, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64)
            return false;
        var a = PointDecompress(publicKey);
        if (a is null)
            return false;
        var rs = signature[..32];
        var r = PointDecompress(rs);
        if (r is null)
            return false;
        var s = new BigInteger(signature.AsSpan(32),
                               isUnsigned: true, isBigEndian: false);
        if (s >= Q)
            return false;
        var h = Sha512ModQ(Concat(rs, publicKey, msg));
        var sB = PointMul(s, G);
        var hA = PointMul(h, a.Value);
        return PointEqual(sB, PointAdd(r.Value, hA));
    }
}

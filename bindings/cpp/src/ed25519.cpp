// ed25519.cpp - RFC 8032 over the magnitude bignum layer.

#include "ed25519.hpp"

#include <mutex>
#include <optional>
#include <stdexcept>

#include "bignum.hpp"
#include "sha2.hpp"

namespace co {
namespace ed25519 {

namespace {

// The curve constants, computed once on first use.
struct Curve {
    Big p;        // 2^255 - 19
    Big q;        // the group order (2^252 + 27742317...)
    Big d;        // -121665 / 121666 mod p
    Big sqrt_m1;  // 2^((p-1)/4) mod p
    Big p_minus_2;
    Big p_plus_3_div_8;
};

struct Pt {
    Big x, y, z, t;  // extended twisted Edwards coordinates
};

Curve* g_curve = nullptr;
Pt* g_G = nullptr;
std::once_flag g_once;

// ---- field arithmetic mod p ---------------------------------------------

// Fast reduction mod 2^255 - 19: fold the high part times 19 into the low.
Big mod_p(Big a) {
    const Big& p = g_curve->p;
    const Big nineteen = big_from_u64(19);
    while (big_bitlen(a) > 255) {
        Big hi = big_shr(a, 255);
        Big lo = big_lowbits(a, 255);
        a = big_add(lo, big_mul(hi, nineteen));
    }
    while (big_cmp(a, p) >= 0) a = big_sub(a, p);
    return a;
}

Big fadd(const Big& a, const Big& b) { return mod_p(big_add(a, b)); }

// a - b mod p with a, b already reduced: computed as a + p - b (the
// magnitude layer has no negatives; this mirrors Python's floored %).
Big fsub(const Big& a, const Big& b) {
    return mod_p(big_sub(big_add(a, g_curve->p), b));
}

Big fmul(const Big& a, const Big& b) { return mod_p(big_mul(a, b)); }

// Square-and-multiply, reducing with the fast p fold at every step.
Big modpow_p(const Big& b, const Big& e) {
    Big result = big_from_u64(1);
    Big base = mod_p(b);
    for (size_t i = big_bitlen(e); i-- > 0;) {
        result = fmul(result, result);
        if (big_bit(e, i)) result = fmul(result, base);
    }
    return result;
}

// Fermat inversion: x^(p-2) mod p.
Big inv_p(const Big& x) { return modpow_p(x, g_curve->p_minus_2); }

// ---- the point group ------------------------------------------------------

Pt point_add(const Pt& P, const Pt& Q) {
    const Big two = big_from_u64(2);
    Big A = fmul(fsub(P.y, P.x), fsub(Q.y, Q.x));
    Big B = fmul(fadd(P.y, P.x), fadd(Q.y, Q.x));
    Big C = fmul(fmul(fmul(two, P.t), Q.t), g_curve->d);
    Big D = fmul(fmul(two, P.z), Q.z);
    Big E = fsub(B, A);
    Big F = fsub(D, C);
    Big G = fadd(D, C);
    Big H = fadd(B, A);
    return Pt{fmul(E, F), fmul(G, H), fmul(F, G), fmul(E, H)};
}

Pt point_mul(const Big& s, Pt P) {
    // The neutral element (0, 1, 1, 0).
    Pt Q{Big{}, big_from_u64(1), big_from_u64(1), Big{}};
    size_t bits = big_bitlen(s);
    for (size_t i = 0; i < bits; ++i) {
        if (big_bit(s, i)) Q = point_add(Q, P);
        P = point_add(P, P);
    }
    return Q;
}

bool point_equal(const Pt& P, const Pt& Q) {
    // Cross-multiplied projective comparison, kept non-negative.
    if (big_cmp(fmul(P.x, Q.z), fmul(Q.x, P.z)) != 0) return false;
    if (big_cmp(fmul(P.y, Q.z), fmul(Q.y, P.z)) != 0) return false;
    return true;
}

std::optional<Big> recover_x(const Big& y, bool sign) {
    if (big_cmp(y, g_curve->p) >= 0) return std::nullopt;
    const Big one = big_from_u64(1);
    Big y2 = fmul(y, y);
    Big x2 = fmul(fsub(y2, one), inv_p(fadd(fmul(g_curve->d, y2), one)));
    if (x2.isZero()) {
        if (sign) return std::nullopt;
        return Big{};
    }
    Big x = modpow_p(x2, g_curve->p_plus_3_div_8);
    if (!fsub(fmul(x, x), x2).isZero()) x = fmul(x, g_curve->sqrt_m1);
    if (!fsub(fmul(x, x), x2).isZero()) return std::nullopt;
    if (big_bit(x, 0) != sign) x = big_sub(g_curve->p, x);
    return x;
}

std::string point_compress(const Pt& P) {
    Big zinv = inv_p(P.z);
    Big x = fmul(P.x, zinv);
    Big y = fmul(P.y, zinv);
    std::string out = big_to_bytes_le(y, 32);
    if (big_bit(x, 0))
        out[31] = static_cast<char>(static_cast<unsigned char>(out[31]) | 0x80);
    return out;
}

std::optional<Pt> point_decompress(const std::string& s) {
    if (s.size() != 32) return std::nullopt;
    Big raw = big_from_bytes_le(s);
    bool sign = big_bit(raw, 255);
    Big y = big_lowbits(raw, 255);
    std::optional<Big> x = recover_x(y, sign);
    if (!x) return std::nullopt;
    return Pt{*x, y, big_from_u64(1), fmul(*x, y)};
}

// ---- setup ---------------------------------------------------------------

void init_curve() {
    g_curve = new Curve();
    // p = 2^255 - 19.
    g_curve->p = big_sub(big_shl(big_from_u64(1), 255), big_from_u64(19));
    // q = 2^252 + 27742317777372353535851937790883648493.
    g_curve->q = big_from_hex(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
    g_curve->p_minus_2 = big_sub(g_curve->p, big_from_u64(2));
    g_curve->p_plus_3_div_8 = big_shr(big_add(g_curve->p, big_from_u64(3)), 3);
    // d = -121665 * inv(121666) mod p, kept non-negative as (p - 121665)/121666.
    g_curve->d = fmul(big_sub(g_curve->p, big_from_u64(121665)),
                      inv_p(big_from_u64(121666)));
    // sqrt(-1) = 2^((p-1)/4) mod p.
    g_curve->sqrt_m1 = modpow_p(
        big_from_u64(2), big_shr(big_sub(g_curve->p, big_from_u64(1)), 2));
    // The base point: y = 4/5, x recovered with the even sign.
    Big g_y = fmul(big_from_u64(4), inv_p(big_from_u64(5)));
    std::optional<Big> g_x = recover_x(g_y, false);
    if (!g_x) throw std::runtime_error("ed25519: base point recovery failed");
    g_G = new Pt{*g_x, g_y, big_from_u64(1), fmul(*g_x, g_y)};
}

void ensure_init() { std::call_once(g_once, init_curve); }

// ---- scalars and hashing --------------------------------------------------

// (a, prefix): the clamped secret scalar and the 32-byte nonce prefix.
std::pair<Big, std::string> secret_expand(const std::string& secret) {
    if (secret.size() != 32)
        throw std::runtime_error("secret key must be 32 bytes");
    std::string h = sha512(secret);
    std::string scalar = h.substr(0, 32);
    // The RFC 8032 clamp: clear bits 0-2 and bit 255, set bit 254.
    scalar[0] = static_cast<char>(static_cast<unsigned char>(scalar[0]) & 248);
    scalar[31] = static_cast<char>(static_cast<unsigned char>(scalar[31]) & 127);
    scalar[31] = static_cast<char>(static_cast<unsigned char>(scalar[31]) | 64);
    return {big_from_bytes_le(scalar), h.substr(32)};
}

Big sha512_modq(const std::string& s) {
    return big_mod(big_from_bytes_le(sha512(s)), g_curve->q);
}

}  // namespace

std::string secret_to_public(const std::string& secret) {
    ensure_init();
    auto [a, prefix] = secret_expand(secret);
    (void)prefix;
    return point_compress(point_mul(a, *g_G));
}

std::string sign(const std::string& secret, const std::string& msg) {
    ensure_init();
    auto [a, prefix] = secret_expand(secret);
    std::string A = point_compress(point_mul(a, *g_G));
    Big r = sha512_modq(prefix + msg);
    std::string Rs = point_compress(point_mul(r, *g_G));
    Big h = sha512_modq(Rs + A + msg);
    Big s = big_mod(big_add(r, big_mul(h, a)), g_curve->q);
    return Rs + big_to_bytes_le(s, 32);
}

bool verify(const std::string& public_key, const std::string& msg,
            const std::string& signature) {
    ensure_init();
    if (public_key.size() != 32 || signature.size() != 64) return false;
    std::optional<Pt> A = point_decompress(public_key);
    if (!A) return false;
    std::string Rs = signature.substr(0, 32);
    std::optional<Pt> R = point_decompress(Rs);
    if (!R) return false;
    Big s = big_from_bytes_le(signature.substr(32));
    if (big_cmp(s, g_curve->q) >= 0) return false;
    Big h = sha512_modq(Rs + public_key + msg);
    Pt sB = point_mul(s, *g_G);
    Pt hA = point_mul(h, *A);
    return point_equal(sB, point_add(*R, hA));
}

}  // namespace ed25519
}  // namespace co

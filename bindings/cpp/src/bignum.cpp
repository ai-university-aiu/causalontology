// bignum.cpp - the magnitude bignum over uint64_t limbs.

#include "bignum.hpp"

#include <algorithm>
#include <stdexcept>

namespace co {

int big_cmp(const Big& a, const Big& b) {
    if (a.l.size() != b.l.size())
        return a.l.size() < b.l.size() ? -1 : 1;
    for (size_t i = a.l.size(); i-- > 0;) {
        if (a.l[i] != b.l[i]) return a.l[i] < b.l[i] ? -1 : 1;
    }
    return 0;
}

Big big_from_u64(uint64_t v) {
    Big r;
    if (v) r.l.push_back(v);
    return r;
}

Big big_add(const Big& a, const Big& b) {
    Big r;
    size_t n = std::max(a.l.size(), b.l.size());
    r.l.resize(n + 1, 0);
    unsigned __int128 carry = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned __int128 s = carry;
        if (i < a.l.size()) s += a.l[i];
        if (i < b.l.size()) s += b.l[i];
        r.l[i] = static_cast<uint64_t>(s);
        carry = s >> 64;
    }
    r.l[n] = static_cast<uint64_t>(carry);
    r.norm();
    return r;
}

Big big_sub(const Big& a, const Big& b) {
    if (big_cmp(a, b) < 0)
        throw std::runtime_error("big_sub: negative result (magnitude only)");
    Big r;
    r.l.assign(a.l.size(), 0);
    uint64_t borrow = 0;
    for (size_t i = 0; i < a.l.size(); ++i) {
        uint64_t bi = i < b.l.size() ? b.l[i] : 0;
        unsigned __int128 lhs = a.l[i];
        unsigned __int128 rhs = static_cast<unsigned __int128>(bi) + borrow;
        if (lhs >= rhs) {
            r.l[i] = static_cast<uint64_t>(lhs - rhs);
            borrow = 0;
        } else {
            r.l[i] = static_cast<uint64_t>(
                (static_cast<unsigned __int128>(1) << 64) + lhs - rhs);
            borrow = 1;
        }
    }
    r.norm();
    return r;
}

Big big_mul(const Big& a, const Big& b) {
    Big r;
    if (a.isZero() || b.isZero()) return r;
    r.l.assign(a.l.size() + b.l.size(), 0);
    for (size_t i = 0; i < a.l.size(); ++i) {
        unsigned __int128 carry = 0;
        for (size_t j = 0; j < b.l.size(); ++j) {
            unsigned __int128 cur =
                static_cast<unsigned __int128>(a.l[i]) * b.l[j] +
                r.l[i + j] + carry;
            r.l[i + j] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
        }
        size_t k = i + b.l.size();
        while (carry) {
            unsigned __int128 cur = static_cast<unsigned __int128>(r.l[k]) + carry;
            r.l[k] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
            ++k;
        }
    }
    r.norm();
    return r;
}

Big big_shl(const Big& a, size_t bits) {
    if (a.isZero()) return a;
    size_t limbShift = bits / 64, bitShift = bits % 64;
    Big r;
    r.l.assign(a.l.size() + limbShift + 1, 0);
    for (size_t i = 0; i < a.l.size(); ++i) {
        r.l[i + limbShift] |= bitShift ? (a.l[i] << bitShift) : a.l[i];
        if (bitShift)
            r.l[i + limbShift + 1] |= a.l[i] >> (64 - bitShift);
    }
    r.norm();
    return r;
}

Big big_shr(const Big& a, size_t bits) {
    size_t limbShift = bits / 64, bitShift = bits % 64;
    Big r;
    if (limbShift >= a.l.size()) return r;
    r.l.assign(a.l.size() - limbShift, 0);
    for (size_t i = 0; i < r.l.size(); ++i) {
        uint64_t lo = a.l[i + limbShift];
        uint64_t hi = (i + limbShift + 1 < a.l.size()) ? a.l[i + limbShift + 1] : 0;
        r.l[i] = bitShift ? ((lo >> bitShift) | (hi << (64 - bitShift))) : lo;
    }
    r.norm();
    return r;
}

Big big_lowbits(const Big& a, size_t bits) {
    size_t limbCount = (bits + 63) / 64;
    Big r;
    r.l.assign(a.l.begin(),
               a.l.begin() + static_cast<long>(std::min(limbCount, a.l.size())));
    size_t rem = bits % 64;
    if (rem && r.l.size() == limbCount)
        r.l.back() &= (uint64_t(1) << rem) - 1;
    r.norm();
    return r;
}

size_t big_bitlen(const Big& a) {
    if (a.isZero()) return 0;
    uint64_t top = a.l.back();
    size_t bits = (a.l.size() - 1) * 64;
    while (top) {
        ++bits;
        top >>= 1;
    }
    return bits;
}

bool big_bit(const Big& a, size_t i) {
    size_t limb = i / 64;
    if (limb >= a.l.size()) return false;
    return (a.l[limb] >> (i % 64)) & 1;
}

Big big_mod(const Big& a, const Big& m) {
    if (m.isZero()) throw std::runtime_error("big_mod: modulus is zero");
    if (big_cmp(a, m) < 0) return a;
    // Shift-subtract long division: align m to a's magnitude, walk down.
    size_t shift = big_bitlen(a) - big_bitlen(m);
    Big r = a;
    Big t = big_shl(m, shift);
    for (size_t i = 0; i <= shift; ++i) {
        if (big_cmp(r, t) >= 0) r = big_sub(r, t);
        t = big_shr(t, 1);
    }
    return r;
}

Big big_modpow(const Big& b, const Big& e, const Big& m) {
    Big result = big_from_u64(1);
    result = big_mod(result, m);
    Big base = big_mod(b, m);
    size_t bits = big_bitlen(e);
    // Left-to-right square-and-multiply.
    for (size_t i = bits; i-- > 0;) {
        result = big_mod(big_mul(result, result), m);
        if (big_bit(e, i)) result = big_mod(big_mul(result, base), m);
    }
    return result;
}

Big big_from_bytes_le(const std::string& bytes) {
    Big r;
    r.l.assign((bytes.size() + 7) / 8, 0);
    for (size_t i = 0; i < bytes.size(); ++i)
        r.l[i / 8] |= static_cast<uint64_t>(
                          static_cast<unsigned char>(bytes[i]))
                      << (8 * (i % 8));
    r.norm();
    return r;
}

std::string big_to_bytes_le(const Big& a, size_t n) {
    if (big_bitlen(a) > n * 8)
        throw std::runtime_error("big_to_bytes_le: value too large");
    std::string out(n, '\0');
    for (size_t i = 0; i < n; ++i) {
        size_t limb = i / 8;
        if (limb < a.l.size())
            out[i] = static_cast<char>((a.l[limb] >> (8 * (i % 8))) & 0xff);
    }
    return out;
}

Big big_from_hex(const std::string& hex) {
    Big r;
    for (char c : hex) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else throw std::runtime_error("big_from_hex: bad digit");
        r = big_add(big_shl(r, 4), big_from_u64(static_cast<uint64_t>(d)));
    }
    return r;
}

std::string big_to_hex(const Big& a) {
    if (a.isZero()) return "0";
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (size_t i = a.l.size(); i-- > 0;) {
        for (int nib = 15; nib >= 0; --nib) {
            int d = static_cast<int>((a.l[i] >> (4 * nib)) & 0xf);
            if (out.empty() && d == 0) continue;
            out.push_back(digits[d]);
        }
    }
    if (out.empty()) out = "0";
    return out;
}

}  // namespace co

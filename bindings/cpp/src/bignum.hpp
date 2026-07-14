// bignum.hpp - arbitrary-precision unsigned (magnitude-only) integers.
//
// std::vector<uint64_t> limbs, little-endian, normalized (no leading zero
// limbs; zero is the empty vector). Products go through unsigned __int128.
// Correctness first: schoolbook multiplication, shift-subtract modular
// reduction, Fermat inversion (done by the caller via modpow). The layer
// is cross-checked against Python's big integers by tools/check_bignum.py.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace co {

struct Big {
    std::vector<uint64_t> l;  // little-endian limbs, normalized

    void norm() {
        while (!l.empty() && l.back() == 0) l.pop_back();
    }
    bool isZero() const { return l.empty(); }
};

// Comparison: -1, 0, +1 as a <, ==, > b.
int big_cmp(const Big& a, const Big& b);

Big big_from_u64(uint64_t v);
Big big_add(const Big& a, const Big& b);
// Subtraction requires a >= b (magnitude-only layer).
Big big_sub(const Big& a, const Big& b);
Big big_mul(const Big& a, const Big& b);
Big big_shl(const Big& a, size_t bits);
Big big_shr(const Big& a, size_t bits);
// The lowest `bits` bits of a.
Big big_lowbits(const Big& a, size_t bits);
size_t big_bitlen(const Big& a);
bool big_bit(const Big& a, size_t i);

// Generic modular reduction by shift-subtract long division; m > 0.
Big big_mod(const Big& a, const Big& m);
// Modular exponentiation (b ** e) mod m via square-and-multiply.
Big big_modpow(const Big& b, const Big& e, const Big& m);

// Byte and hex conversions (little-endian bytes, like Python's "little").
Big big_from_bytes_le(const std::string& bytes);
std::string big_to_bytes_le(const Big& a, size_t n);
Big big_from_hex(const std::string& hex);
std::string big_to_hex(const Big& a);

}  // namespace co

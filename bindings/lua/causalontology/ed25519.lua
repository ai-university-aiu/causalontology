-- ed25519.lua - Ed25519 digital signatures (RFC 8032), pure Lua 5.4.
--
-- A faithful port of bindings/python/causalontology/ed25519.py.  Python has
-- native big integers; Lua does not, so this module carries a small bignum
-- layer: non-negative integers as little-endian arrays of base-2**24 limbs.
-- Base 2**24 keeps every schoolbook-multiplication column far below 2**63
-- (24+24 bits per product, at most ~44 products per column), so all limb
-- arithmetic stays in Lua 5.4's native 64-bit integers with no overflow.
--
-- Field arithmetic mod p = 2**255 - 19 reduces by folding: a = hi*2**255 + lo
-- implies a = 19*hi + lo (mod p).  Scalar arithmetic mod the group order q
-- uses generic shift-aligned trial-subtraction long division.  Modular
-- inversion is Fermat: x**(p-2) mod p.  Slow but correct - intended for the
-- conformance suite and small tools, exactly like the Python original.
--
-- Gated at module load on the RFC 8032 TEST 1 known answer (seed
-- 9d61b19d... -> public d75a9801...511a, empty-message signature verifies).

local sha2 = require("causalontology.sha2")

local ed25519 = {}

-- ------------------------------------------------------------- bignum core

local BASE_BITS = 24
local BASE = 1 << BASE_BITS          -- 2**24
local LIMB_MASK = BASE - 1

-- Strip trailing zero limbs; zero is the empty array.
local function bn_norm(a)
  local n = #a
  while n > 0 and a[n] == 0 do a[n] = nil; n = n - 1 end
  return a
end

local function bn_is_zero(a)
  return #a == 0
end

local function bn_from_int(v)
  local a = {}
  while v > 0 do
    a[#a + 1] = v & LIMB_MASK
    v = v >> BASE_BITS
  end
  return a
end

local function bn_copy(a)
  local out = {}
  for i = 1, #a do out[i] = a[i] end
  return out
end

-- Little-endian byte string -> bignum (3 bytes per limb).
local function bn_from_bytes_le(s)
  local a = {}
  local i = 1
  while i <= #s do
    local b0 = s:byte(i) or 0
    local b1 = s:byte(i + 1) or 0
    local b2 = s:byte(i + 2) or 0
    a[#a + 1] = b0 | (b1 << 8) | (b2 << 16)
    i = i + 3
  end
  return bn_norm(a)
end

-- Bignum -> exactly n little-endian bytes (the value must fit).
local function bn_to_bytes_le(a, n)
  local bytes = {}
  local limb_i, acc, acc_bits = 1, 0, 0
  for _ = 1, n do
    if acc_bits < 8 then
      acc = acc | ((a[limb_i] or 0) << acc_bits)
      acc_bits = acc_bits + BASE_BITS
      limb_i = limb_i + 1
    end
    bytes[#bytes + 1] = string.char(acc & 0xff)
    acc = acc >> 8
    acc_bits = acc_bits - 8
  end
  return table.concat(bytes)
end

local function bn_from_hex(hex)
  return bn_from_bytes_le(sha2.from_hex(hex):reverse())
end

local function bn_to_hex(a, nbytes)
  return sha2.to_hex(bn_to_bytes_le(a, nbytes):reverse())
end

-- -1, 0, or 1 as a < b, a == b, a > b.
local function bn_cmp(a, b)
  if #a ~= #b then return #a < #b and -1 or 1 end
  for i = #a, 1, -1 do
    if a[i] ~= b[i] then return a[i] < b[i] and -1 or 1 end
  end
  return 0
end

local function bn_add(a, b)
  local out, carry = {}, 0
  local n = math.max(#a, #b)
  for i = 1, n do
    local s = (a[i] or 0) + (b[i] or 0) + carry
    out[i] = s & LIMB_MASK
    carry = s >> BASE_BITS
  end
  if carry > 0 then out[n + 1] = carry end
  return out
end

-- a - b; requires a >= b.
local function bn_sub(a, b)
  local out, borrow = {}, 0
  for i = 1, #a do
    local d = a[i] - (b[i] or 0) - borrow
    if d < 0 then d = d + BASE; borrow = 1 else borrow = 0 end
    out[i] = d
  end
  assert(borrow == 0, "bn_sub underflow")
  return bn_norm(out)
end

-- Schoolbook multiplication; column sums stay far below 2**63.
local function bn_mul(a, b)
  if bn_is_zero(a) or bn_is_zero(b) then return {} end
  local out = {}
  for i = 1, #a + #b do out[i] = 0 end
  for i = 1, #a do
    local ai = a[i]
    if ai ~= 0 then
      local carry = 0
      for j = 1, #b do
        local t = out[i + j - 1] + ai * b[j] + carry
        out[i + j - 1] = t & LIMB_MASK
        carry = t >> BASE_BITS
      end
      local k = i + #b
      while carry > 0 do
        local t = out[k] + carry
        out[k] = t & LIMB_MASK
        carry = t >> BASE_BITS
        k = k + 1
      end
    end
  end
  return bn_norm(out)
end

-- Multiplication by a small (< 2**32) scalar.
local function bn_muls(a, s)
  if s == 0 or bn_is_zero(a) then return {} end
  local out, carry = {}, 0
  for i = 1, #a do
    local t = a[i] * s + carry
    out[i] = t & LIMB_MASK
    carry = t >> BASE_BITS
  end
  while carry > 0 do
    out[#out + 1] = carry & LIMB_MASK
    carry = carry >> BASE_BITS
  end
  return out
end

local function bn_bitlen(a)
  if #a == 0 then return 0 end
  local top = a[#a]
  local bits = 0
  while top > 0 do bits = bits + 1; top = top >> 1 end
  return (#a - 1) * BASE_BITS + bits
end

-- Bit i (0-based) of a.
local function bn_bit(a, i)
  local limb = a[(i // BASE_BITS) + 1]
  if not limb then return 0 end
  return (limb >> (i % BASE_BITS)) & 1
end

-- a << k bits.
local function bn_shl(a, k)
  if bn_is_zero(a) then return {} end
  local limb_shift, bit_shift = k // BASE_BITS, k % BASE_BITS
  local out = {}
  for i = 1, limb_shift do out[i] = 0 end
  local carry = 0
  for i = 1, #a do
    local t = (a[i] << bit_shift) | carry
    out[limb_shift + i] = t & LIMB_MASK
    carry = t >> BASE_BITS
  end
  if carry > 0 then out[limb_shift + #a + 1] = carry end
  return bn_norm(out)
end

-- a >> k bits.
local function bn_shr(a, k)
  local limb_shift, bit_shift = k // BASE_BITS, k % BASE_BITS
  local out = {}
  for i = limb_shift + 1, #a do
    local v = a[i] >> bit_shift
    if bit_shift > 0 then
      v = v | (((a[i + 1] or 0) << (BASE_BITS - bit_shift)) & LIMB_MASK)
    end
    out[i - limb_shift] = v
  end
  return bn_norm(out)
end

-- a mod 2**k.
local function bn_lowbits(a, k)
  local limbs, bits = k // BASE_BITS, k % BASE_BITS
  local out = {}
  for i = 1, math.min(limbs, #a) do out[i] = a[i] end
  if bits > 0 and a[limbs + 1] then
    out[limbs + 1] = a[limbs + 1] & ((1 << bits) - 1)
  end
  return bn_norm(out)
end

-- a mod m by shift-aligned trial subtraction (binary long division).
local function bn_mod(a, m)
  assert(not bn_is_zero(m), "bn_mod by zero")
  if bn_cmp(a, m) < 0 then return bn_copy(a) end
  local r = bn_copy(a)
  local shift = bn_bitlen(r) - bn_bitlen(m)
  local ms = bn_shl(m, shift)
  while shift >= 0 do
    if bn_cmp(r, ms) >= 0 then r = bn_sub(r, ms) end
    ms = bn_shr(ms, 1)
    shift = shift - 1
  end
  return r
end

-- --------------------------------------------------------------- constants

local BN_ZERO = {}
local BN_ONE = { 1 }

-- p = 2**255 - 19, the field prime.
local P = bn_sub(bn_shl(BN_ONE, 255), bn_from_int(19))
local P2 = bn_add(P, P)                                  -- 2p, for fe_sub
local P_MINUS_2 = bn_sub(P, bn_from_int(2))              -- Fermat exponent
local P_PLUS_3_DIV_8 = bn_shr(bn_add(P, bn_from_int(3)), 3)
local P_MINUS_1_DIV_4 = bn_shr(bn_sub(P, BN_ONE), 2)

-- q = 2**252 + 27742317777372353535851937790883648493, the group order.
local Q = bn_from_hex(
  "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")

-- --------------------------------------------- field arithmetic modulo p

-- Fold r down below p: repeatedly rewrite hi*2**255 + lo as 19*hi + lo,
-- then subtract p while r >= p.
local function fe_reduce(r)
  while bn_bitlen(r) > 255 do
    local hi = bn_shr(r, 255)
    local lo = bn_lowbits(r, 255)
    r = bn_add(bn_muls(hi, 19), lo)
  end
  while bn_cmp(r, P) >= 0 do r = bn_sub(r, P) end
  return r
end

local function fe_add(a, b) return fe_reduce(bn_add(a, b)) end

-- (a - b) mod p, computed as a + 2p - b so the subtraction never underflows.
local function fe_sub(a, b) return fe_reduce(bn_sub(bn_add(a, P2), b)) end

local function fe_mul(a, b) return fe_reduce(bn_mul(a, b)) end

local function fe_muls(a, s) return fe_reduce(bn_muls(a, s)) end

-- x**e mod p by square-and-multiply, most significant bit first.
local function fe_pow(x, e)
  local result = bn_copy(BN_ONE)
  for i = bn_bitlen(e) - 1, 0, -1 do
    result = fe_mul(result, result)
    if bn_bit(e, i) == 1 then result = fe_mul(result, x) end
  end
  return result
end

-- Fermat inversion: x**(p-2) mod p.
local function modp_inv(x)
  return fe_pow(x, P_MINUS_2)
end

-- ---------------------------------------------------- curve constants

-- d = -121665 * inv(121666) mod p (the twisted Edwards curve constant).
local D = fe_sub(BN_ZERO, fe_muls(modp_inv(bn_from_int(121666)), 121665))

-- sqrt(-1) mod p = 2**((p-1)/4) mod p.
local SQRT_M1 = fe_pow(bn_from_int(2), P_MINUS_1_DIV_4)

-- ------------------------------------------------------------ point group
-- Points are extended homogeneous coordinates {X, Y, Z, T} with T = XY/Z.

local function point_add(Pt, Qt)
  local A = fe_mul(fe_sub(Pt[2], Pt[1]), fe_sub(Qt[2], Qt[1]))
  local B = fe_mul(fe_add(Pt[2], Pt[1]), fe_add(Qt[2], Qt[1]))
  local C = fe_muls(fe_mul(fe_mul(Pt[4], Qt[4]), D), 2)
  local Dv = fe_muls(fe_mul(Pt[3], Qt[3]), 2)
  local E, F = fe_sub(B, A), fe_sub(Dv, C)
  local G, H = fe_add(Dv, C), fe_add(B, A)
  return { fe_mul(E, F), fe_mul(G, H), fe_mul(F, G), fe_mul(E, H) }
end

-- Scalar multiplication, least significant bit first (as the Python does).
local function point_mul(s, Pt)
  local Qt = { bn_copy(BN_ZERO), bn_copy(BN_ONE), bn_copy(BN_ONE), bn_copy(BN_ZERO) }
  for i = 0, bn_bitlen(s) - 1 do
    if bn_bit(s, i) == 1 then Qt = point_add(Qt, Pt) end
    Pt = point_add(Pt, Pt)
  end
  return Qt
end

-- Projective equality: X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1 (mod p).
local function point_equal(Pt, Qt)
  if bn_cmp(fe_mul(Pt[1], Qt[3]), fe_mul(Qt[1], Pt[3])) ~= 0 then return false end
  if bn_cmp(fe_mul(Pt[2], Qt[3]), fe_mul(Qt[2], Pt[3])) ~= 0 then return false end
  return true
end

-- Recover the x coordinate from y and the sign bit (nil on failure).
local function recover_x(y, sign)
  if bn_cmp(y, P) >= 0 then return nil end
  local y2 = fe_mul(y, y)
  local x2 = fe_mul(fe_sub(y2, bn_copy(BN_ONE)),
                    modp_inv(fe_add(fe_mul(D, y2), bn_copy(BN_ONE))))
  if bn_is_zero(x2) then
    if sign == 1 then return nil end
    return bn_copy(BN_ZERO)
  end
  local x = fe_pow(x2, P_PLUS_3_DIV_8)
  if bn_cmp(fe_mul(x, x), x2) ~= 0 then
    x = fe_mul(x, SQRT_M1)
  end
  if bn_cmp(fe_mul(x, x), x2) ~= 0 then return nil end
  if bn_bit(x, 0) ~= sign then
    x = bn_sub(P, x)
  end
  return x
end

-- The base point G: y = 4/5 mod p, x recovered with sign 0.
local G_Y = fe_muls(modp_inv(bn_from_int(5)), 4)
local G_X = recover_x(G_Y, 0)
local G = { G_X, G_Y, bn_copy(BN_ONE), fe_mul(G_X, G_Y) }

-- Compress a point to 32 bytes: y little-endian with the x parity on top.
local function point_compress(Pt)
  local zinv = modp_inv(Pt[3])
  local x = fe_mul(Pt[1], zinv)
  local y = fe_mul(Pt[2], zinv)
  local bytes = bn_to_bytes_le(y, 32)
  local top = bytes:byte(32) | (bn_bit(x, 0) << 7)
  return bytes:sub(1, 31) .. string.char(top)
end

-- Decompress 32 bytes to a point (nil on failure).
local function point_decompress(s)
  if #s ~= 32 then return nil end
  local y = bn_from_bytes_le(s)
  local sign = bn_bit(y, 255)
  y = bn_lowbits(y, 255)
  local x = recover_x(y, sign)
  if x == nil then return nil end
  return { x, y, bn_copy(BN_ONE), fe_mul(x, y) }
end

-- ------------------------------------------------------------- key schedule

-- Expand a 32-byte secret into the clamped scalar and the signing prefix.
local function secret_expand(secret)
  if #secret ~= 32 then error("secret key must be 32 bytes", 0) end
  local h = sha2.sha512(secret)
  local a = bn_from_bytes_le(h:sub(1, 32))
  a = bn_lowbits(a, 254)                    -- clear bits 254 and 255
  a = bn_sub(a, bn_lowbits(a, 3))           -- clear bits 0, 1, 2
  a = bn_add(a, bn_shl(BN_ONE, 254))        -- set bit 254
  return a, h:sub(33, 64)
end

-- SHA-512 of a byte string, taken little-endian, reduced mod q.
local function sha512_modq(s)
  return bn_mod(bn_from_bytes_le(sha2.sha512(s)), Q)
end

-- ---------------------------------------------------------------- the API

-- The 32-byte public key for a 32-byte secret key.
function ed25519.secret_to_public(secret)
  local a = secret_expand(secret)
  return point_compress(point_mul(a, G))
end

-- The 64-byte Ed25519 signature of msg under the 32-byte secret key.
function ed25519.sign(secret, msg)
  local a, prefix = secret_expand(secret)
  local A = point_compress(point_mul(a, G))
  local r = sha512_modq(prefix .. msg)
  local Rs = point_compress(point_mul(r, G))
  local h = sha512_modq(Rs .. A .. msg)
  local s = bn_mod(bn_add(r, bn_mul(h, a)), Q)
  return Rs .. bn_to_bytes_le(s, 32)
end

-- True iff signature is a valid Ed25519 signature of msg under public.
function ed25519.verify(public, msg, signature)
  if #public ~= 32 or #signature ~= 64 then return false end
  local A = point_decompress(public)
  if A == nil then return false end
  local Rs = signature:sub(1, 32)
  local R = point_decompress(Rs)
  if R == nil then return false end
  local s = bn_from_bytes_le(signature:sub(33, 64))
  if bn_cmp(s, Q) >= 0 then return false end
  local h = sha512_modq(Rs .. public .. msg)
  local sB = point_mul(s, G)
  local hA = point_mul(h, A)
  return point_equal(sB, point_add(R, hA))
end

-- Internal handles for the cross-check test harness (not part of the API).
ed25519._bn = {
  from_hex = bn_from_hex, to_hex = bn_to_hex,
  from_bytes_le = bn_from_bytes_le, to_bytes_le = bn_to_bytes_le,
  from_int = bn_from_int,
  add = bn_add, sub = bn_sub, mul = bn_mul, muls = bn_muls, mod = bn_mod,
  cmp = bn_cmp, shl = bn_shl, shr = bn_shr, lowbits = bn_lowbits,
  bitlen = bn_bitlen, bit = bn_bit,
  fe_add = fe_add, fe_sub = fe_sub, fe_mul = fe_mul, fe_pow = fe_pow,
  modp_inv = modp_inv, P = P, Q = Q, D = D, SQRT_M1 = SQRT_M1,
  G = G, point_add = point_add, point_mul = point_mul,
  point_compress = point_compress, point_decompress = point_decompress,
  recover_x = recover_x,
}

-- --------------------------------------------- load-time known-answer gate
-- RFC 8032, section 7.1, TEST 1.

do
  local sk = sha2.from_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  local pk = ed25519.secret_to_public(sk)
  assert(sha2.to_hex(pk) ==
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ed25519.lua: RFC 8032 TEST 1 public key failed: " .. sha2.to_hex(pk))
  local sig = ed25519.sign(sk, "")
  assert(sha2.to_hex(sig) ==
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" ..
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "ed25519.lua: RFC 8032 TEST 1 signature failed")
  assert(ed25519.verify(pk, "", sig),
    "ed25519.lua: RFC 8032 TEST 1 signature does not verify")
  assert(not ed25519.verify(pk, "x", sig),
    "ed25519.lua: RFC 8032 TEST 1 verified a wrong message")
end

return ed25519

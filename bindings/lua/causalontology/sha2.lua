-- sha2.lua - SHA-256 and SHA-512 (FIPS 180-4), pure Lua 5.4.
--
-- Uses Lua 5.4's native 64-bit integers and bitwise operators.  SHA-512
-- works directly in the signed 64-bit machine word: additions wrap
-- naturally mod 2**64, and Lua's >> is already a logical (zero-filling)
-- shift on integers, which is exactly what the rotations need.  SHA-256
-- masks its 32-bit words after every widening step.
--
-- Both digests are gated by empty-string known answers at module load
-- (sha256("") = e3b0c442..., sha512("") = cf83e135...), so a broken port
-- cannot run silently.

local sha2 = {}

-- --------------------------------------------------------------- SHA-256

-- The 64 SHA-256 round constants (fractional parts of cube roots of primes).
local K256 = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local M32 = 0xffffffff

local function rotr32(x, n)
  return ((x >> n) | (x << (32 - n))) & M32
end

-- Pad a message per FIPS 180-4 with a 64-bit big-endian bit length.
local function pad64(msg)
  local len = #msg
  local padlen = 64 - ((len + 9) % 64)
  if padlen == 64 then padlen = 0 end
  return msg .. "\x80" .. string.rep("\0", padlen) .. string.pack(">I8", len * 8)
end

function sha2.sha256(msg)
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  local data = pad64(msg)
  local w = {}
  for block = 1, #data, 64 do
    -- the sixteen big-endian message words of this block
    for i = 1, 16 do
      w[i] = string.unpack(">I4", data, block + (i - 1) * 4)
    end
    -- the expanded message schedule
    for i = 17, 64 do
      local s0 = rotr32(w[i - 15], 7) ~ rotr32(w[i - 15], 18) ~ (w[i - 15] >> 3)
      local s1 = rotr32(w[i - 2], 17) ~ rotr32(w[i - 2], 19) ~ (w[i - 2] >> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M32
    end
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for i = 1, 64 do
      local S1 = rotr32(e, 6) ~ rotr32(e, 11) ~ rotr32(e, 25)
      local ch = (e & f) ~ ((~e) & g)
      local t1 = (h + S1 + ch + K256[i] + w[i]) & M32
      local S0 = rotr32(a, 2) ~ rotr32(a, 13) ~ rotr32(a, 22)
      local maj = (a & b) ~ (a & c) ~ (b & c)
      local t2 = (S0 + maj) & M32
      h, g, f, e = g, f, e, (d + t1) & M32
      d, c, b, a = c, b, a, (t1 + t2) & M32
    end
    h0 = (h0 + a) & M32; h1 = (h1 + b) & M32
    h2 = (h2 + c) & M32; h3 = (h3 + d) & M32
    h4 = (h4 + e) & M32; h5 = (h5 + f) & M32
    h6 = (h6 + g) & M32; h7 = (h7 + h) & M32
  end
  return string.pack(">I4I4I4I4I4I4I4I4", h0, h1, h2, h3, h4, h5, h6, h7)
end

-- --------------------------------------------------------------- SHA-512

-- The 80 SHA-512 round constants, given as two 32-bit halves so the source
-- carries no integer literal at or above 2**63 (they are joined at load).
local K512_HALVES = {
  {0x428a2f98,0xd728ae22},{0x71374491,0x23ef65cd},{0xb5c0fbcf,0xec4d3b2f},{0xe9b5dba5,0x8189dbbc},
  {0x3956c25b,0xf348b538},{0x59f111f1,0xb605d019},{0x923f82a4,0xaf194f9b},{0xab1c5ed5,0xda6d8118},
  {0xd807aa98,0xa3030242},{0x12835b01,0x45706fbe},{0x243185be,0x4ee4b28c},{0x550c7dc3,0xd5ffb4e2},
  {0x72be5d74,0xf27b896f},{0x80deb1fe,0x3b1696b1},{0x9bdc06a7,0x25c71235},{0xc19bf174,0xcf692694},
  {0xe49b69c1,0x9ef14ad2},{0xefbe4786,0x384f25e3},{0x0fc19dc6,0x8b8cd5b5},{0x240ca1cc,0x77ac9c65},
  {0x2de92c6f,0x592b0275},{0x4a7484aa,0x6ea6e483},{0x5cb0a9dc,0xbd41fbd4},{0x76f988da,0x831153b5},
  {0x983e5152,0xee66dfab},{0xa831c66d,0x2db43210},{0xb00327c8,0x98fb213f},{0xbf597fc7,0xbeef0ee4},
  {0xc6e00bf3,0x3da88fc2},{0xd5a79147,0x930aa725},{0x06ca6351,0xe003826f},{0x14292967,0x0a0e6e70},
  {0x27b70a85,0x46d22ffc},{0x2e1b2138,0x5c26c926},{0x4d2c6dfc,0x5ac42aed},{0x53380d13,0x9d95b3df},
  {0x650a7354,0x8baf63de},{0x766a0abb,0x3c77b2a8},{0x81c2c92e,0x47edaee6},{0x92722c85,0x1482353b},
  {0xa2bfe8a1,0x4cf10364},{0xa81a664b,0xbc423001},{0xc24b8b70,0xd0f89791},{0xc76c51a3,0x0654be30},
  {0xd192e819,0xd6ef5218},{0xd6990624,0x5565a910},{0xf40e3585,0x5771202a},{0x106aa070,0x32bbd1b8},
  {0x19a4c116,0xb8d2d0c8},{0x1e376c08,0x5141ab53},{0x2748774c,0xdf8eeb99},{0x34b0bcb5,0xe19b48a8},
  {0x391c0cb3,0xc5c95a63},{0x4ed8aa4a,0xe3418acb},{0x5b9cca4f,0x7763e373},{0x682e6ff3,0xd6b2b8a3},
  {0x748f82ee,0x5defb2fc},{0x78a5636f,0x43172f60},{0x84c87814,0xa1f0ab72},{0x8cc70208,0x1a6439ec},
  {0x90befffa,0x23631e28},{0xa4506ceb,0xde82bde9},{0xbef9a3f7,0xb2c67915},{0xc67178f2,0xe372532b},
  {0xca273ece,0xea26619c},{0xd186b8c7,0x21c0c207},{0xeada7dd6,0xcde0eb1e},{0xf57d4f7f,0xee6ed178},
  {0x06f067aa,0x72176fba},{0x0a637dc5,0xa2c898a6},{0x113f9804,0xbef90dae},{0x1b710b35,0x131c471b},
  {0x28db77f5,0x23047d84},{0x32caab7b,0x40c72493},{0x3c9ebe0a,0x15c9bebc},{0x431d67c4,0x9c100d4c},
  {0x4cc5d4be,0xcb3e42b6},{0x597f299c,0xfc657e2a},{0x5fcb6fab,0x3ad6faec},{0x6c44198c,0x4a475817},
}

local K512 = {}
for i, halves in ipairs(K512_HALVES) do
  K512[i] = (halves[1] << 32) | halves[2]
end

-- 64-bit right rotation; Lua's shifts on integers are logical, so no mask.
local function rotr64(x, n)
  return (x >> n) | (x << (64 - n))
end

-- Pad a message with a 128-bit big-endian bit length (high half zero here:
-- Lua strings cannot reach 2**61 bytes).
local function pad128(msg)
  local len = #msg
  local padlen = 128 - ((len + 17) % 128)
  if padlen == 128 then padlen = 0 end
  return msg .. "\x80" .. string.rep("\0", padlen + 8)
             .. string.pack(">I8", len * 8)
end

function sha2.sha512(msg)
  local h0, h1, h2, h3 = (0x6a09e667 << 32) | 0xf3bcc908,
                         (0xbb67ae85 << 32) | 0x84caa73b,
                         (0x3c6ef372 << 32) | 0xfe94f82b,
                         (0xa54ff53a << 32) | 0x5f1d36f1
  local h4, h5, h6, h7 = (0x510e527f << 32) | 0xade682d1,
                         (0x9b05688c << 32) | 0x2b3e6c1f,
                         (0x1f83d9ab << 32) | 0xfb41bd6b,
                         (0x5be0cd19 << 32) | 0x137e2179
  local data = pad128(msg)
  local w = {}
  for block = 1, #data, 128 do
    -- the sixteen big-endian 64-bit message words of this block
    for i = 1, 16 do
      w[i] = string.unpack(">i8", data, block + (i - 1) * 8)
    end
    -- the expanded message schedule (wrapping adds are free in 64-bit)
    for i = 17, 80 do
      local s0 = rotr64(w[i - 15], 1) ~ rotr64(w[i - 15], 8) ~ (w[i - 15] >> 7)
      local s1 = rotr64(w[i - 2], 19) ~ rotr64(w[i - 2], 61) ~ (w[i - 2] >> 6)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
    end
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for i = 1, 80 do
      local S1 = rotr64(e, 14) ~ rotr64(e, 18) ~ rotr64(e, 41)
      local ch = (e & f) ~ ((~e) & g)
      local t1 = h + S1 + ch + K512[i] + w[i]
      local S0 = rotr64(a, 28) ~ rotr64(a, 34) ~ rotr64(a, 39)
      local maj = (a & b) ~ (a & c) ~ (b & c)
      local t2 = S0 + maj
      h, g, f, e = g, f, e, d + t1
      d, c, b, a = c, b, a, t1 + t2
    end
    h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d
    h4 = h4 + e; h5 = h5 + f; h6 = h6 + g; h7 = h7 + h
  end
  return string.pack(">i8i8i8i8i8i8i8i8", h0, h1, h2, h3, h4, h5, h6, h7)
end

-- ------------------------------------------------------------ hex helpers

function sha2.to_hex(bytes)
  return (bytes:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

function sha2.from_hex(hex)
  if #hex % 2 ~= 0 or hex:find("[^0-9a-fA-F]") then return nil end
  return (hex:gsub("%x%x", function(pair)
    return string.char(tonumber(pair, 16))
  end))
end

function sha2.sha256_hex(msg) return sha2.to_hex(sha2.sha256(msg)) end
function sha2.sha512_hex(msg) return sha2.to_hex(sha2.sha512(msg)) end

-- --------------------------------------------- load-time known-answer gate

assert(sha2.sha256_hex("") ==
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha2.lua: SHA-256 empty-string known answer failed")
assert(sha2.sha512_hex("") ==
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ..
  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  "sha2.lua: SHA-512 empty-string known answer failed")

return sha2

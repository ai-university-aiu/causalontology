# frozen_string_literal: false

# Ed25519 digital signatures (RFC 8032), pure Ruby, standard library only.
#
# Slow but correct: intended for the conformance suite and for small tools.
# Production stores should use an optimized library; the signatures are
# byte-compatible either way (Ed25519 is deterministic, RFC 8032).
#
# Ruby's native bignums make this a direct port of the Python reference:
# Integer#pow(exp, mod) is Python's three-argument pow, and Ruby's % on a
# positive modulus is floored (always non-negative), exactly like Python's.
# All byte strings handled here are forced to ASCII-8BIT (binary), so
# byteslice/reverse operate on bytes, never on multibyte characters.

require "digest"

module Causalontology
  module Ed25519
    P = 2**255 - 19
    Q = 2**252 + 27742317777372353535851937790883648493

    module_function

    def sha512(s)
      Digest::SHA512.digest(s)
    end

    def modp_inv(x)
      x.pow(P - 2, P)
    end

    # A 32-byte little-endian string for a non-negative integer below 2**256.
    def int_to_le32(n)
      hex = n.to_s(16).rjust(64, "0")
      [hex].pack("H*").reverse
    end

    # The non-negative integer encoded by a little-endian byte string.
    def le_to_int(s)
      s.dup.force_encoding(Encoding::BINARY).reverse.unpack1("H*").to_i(16)
    end

    # The curve constant d = -121665 / 121666 (mod p).
    CURVE_D = -121665 * modp_inv(121666) % P
    # A square root of -1 (mod p), used in point decompression.
    SQRT_M1 = 2.pow((P - 1) / 4, P)

    # Points are [x, y, z, t] in extended homogeneous coordinates.
    def point_add(pt, qt)
      a = (pt[1] - pt[0]) * (qt[1] - qt[0]) % P
      b = (pt[1] + pt[0]) * (qt[1] + qt[0]) % P
      c = 2 * pt[3] * qt[3] * CURVE_D % P
      d = 2 * pt[2] * qt[2] % P
      e = b - a
      f = d - c
      g = d + c
      h = b + a
      [e * f % P, g * h % P, f * g % P, e * h % P]
    end

    def point_mul(s, pt)
      q = [0, 1, 1, 0] # the neutral element
      while s > 0
        q = point_add(q, pt) if s & 1 == 1
        pt = point_add(pt, pt)
        s >>= 1
      end
      q
    end

    def point_equal(pt, qt)
      return false if (pt[0] * qt[2] - qt[0] * pt[2]) % P != 0
      return false if (pt[1] * qt[2] - qt[1] * pt[2]) % P != 0
      true
    end

    def recover_x(y, sign)
      return nil if y >= P
      x2 = (y * y - 1) * modp_inv(CURVE_D * y * y + 1) % P
      return (sign == 1 ? nil : 0) if x2 == 0
      x = x2.pow((P + 3) / 8, P)
      x = x * SQRT_M1 % P if (x * x - x2) % P != 0
      return nil if (x * x - x2) % P != 0
      x = P - x if (x & 1) != sign
      x
    end

    # The base point G.
    BASE_Y = 4 * modp_inv(5) % P
    BASE_X = recover_x(BASE_Y, 0)
    BASE_POINT = [BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P].freeze

    def point_compress(pt)
      zinv = modp_inv(pt[2])
      x = pt[0] * zinv % P
      y = pt[1] * zinv % P
      int_to_le32(y | ((x & 1) << 255))
    end

    def point_decompress(s)
      return nil if s.bytesize != 32
      y = le_to_int(s)
      sign = y >> 255
      y &= (1 << 255) - 1
      x = recover_x(y, sign)
      return nil if x.nil?
      [x, y, 1, x * y % P]
    end

    def secret_expand(secret)
      raise ArgumentError, "secret key must be 32 bytes" if secret.bytesize != 32
      h = sha512(secret)
      a = le_to_int(h.byteslice(0, 32))
      a &= (1 << 254) - 8
      a |= (1 << 254)
      [a, h.byteslice(32, 32)]
    end

    def sha512_modq(s)
      le_to_int(sha512(s)) % Q
    end

    # The 32-byte public key for a 32-byte secret key.
    def secret_to_public(secret)
      a, _prefix = secret_expand(secret)
      point_compress(point_mul(a, BASE_POINT))
    end

    # The 64-byte Ed25519 signature of msg under the 32-byte secret key.
    def sign(secret, msg)
      msg = msg.dup.force_encoding(Encoding::BINARY)
      a, prefix = secret_expand(secret)
      public_key = point_compress(point_mul(a, BASE_POINT))
      r = sha512_modq(prefix + msg)
      rs = point_compress(point_mul(r, BASE_POINT))
      h = sha512_modq(rs + public_key + msg)
      s = (r + h * a) % Q
      rs + int_to_le32(s)
    end

    # True iff signature is a valid Ed25519 signature of msg under public.
    def verify(public_key, msg, signature)
      msg = msg.dup.force_encoding(Encoding::BINARY)
      return false if public_key.bytesize != 32 || signature.bytesize != 64
      a_point = point_decompress(public_key)
      return false if a_point.nil?
      rs = signature.byteslice(0, 32)
      r_point = point_decompress(rs)
      return false if r_point.nil?
      s = le_to_int(signature.byteslice(32, 32))
      return false if s >= Q
      h = sha512_modq(rs + public_key + msg)
      sb = point_mul(s, BASE_POINT)
      ha = point_mul(h, a_point)
      point_equal(sb, point_add(r_point, ha))
    end
  end
end

# ed25519.jl - Ed25519 digital signatures (RFC 8032), pure Julia, stdlib only.
#
# A faithful port of the Python reference (bindings/python/causalontology/
# ed25519.py) over Julia's native BigInt.  All modular reduction uses mod()
# (floored, non-negative for a positive modulus, matching Python's %), never
# rem().  Slow but correct: intended for the conformance suite and small
# tools; production stores should use an optimized library (the signatures
# are byte-compatible either way, since Ed25519 is deterministic).

module Ed25519

using SHA

const _p = big(2)^255 - 19
const _q = big(2)^252 + parse(BigInt, "27742317777372353535851937790883648493")

_sha512(s::Vector{UInt8}) = sha512(s)

_modp_inv(x::BigInt) = powermod(x, _p - 2, _p)

const _d = mod(big(-121665) * _modp_inv(big(121666)), _p)
const _modp_sqrt_m1 = powermod(big(2), (_p - 1) ÷ 4, _p)

"Little-endian bytes to BigInt."
function le_to_int(bytes::AbstractVector{UInt8})
    n = big(0)
    for i in length(bytes):-1:1
        n = (n << 8) | bytes[i]
    end
    return n
end

"BigInt to len little-endian bytes."
function int_to_le(n::BigInt, len::Int)
    out = Vector{UInt8}(undef, len)
    for i in 1:len
        out[i] = UInt8((n >> (8 * (i - 1))) & 0xff)
    end
    return out
end

# Points are extended homogeneous coordinates (X, Y, Z, T);
# Python's P[0..3] becomes Julia's P[1..4].
function _point_add(P, Q)
    A = mod((P[2] - P[1]) * (Q[2] - Q[1]), _p)
    B = mod((P[2] + P[1]) * (Q[2] + Q[1]), _p)
    C = mod(2 * P[4] * Q[4] * _d, _p)
    D = mod(2 * P[3] * Q[3], _p)
    E, F, G, H = B - A, D - C, D + C, B + A
    return (mod(E * F, _p), mod(G * H, _p), mod(F * G, _p), mod(E * H, _p))
end

function _point_mul(s::BigInt, P)
    Q = (big(0), big(1), big(1), big(0))  # the neutral element
    while s > 0
        if s & 1 == 1
            Q = _point_add(Q, P)
        end
        P = _point_add(P, P)
        s >>= 1
    end
    return Q
end

function _point_equal(P, Q)
    mod(P[1] * Q[3] - Q[1] * P[3], _p) == 0 || return false
    mod(P[2] * Q[3] - Q[2] * P[3], _p) == 0 || return false
    return true
end

function _recover_x(y::BigInt, sign::Integer)
    y >= _p && return nothing
    x2 = mod((y * y - 1) * _modp_inv(mod(_d * y * y + 1, _p)), _p)
    if x2 == 0
        return sign != 0 ? nothing : big(0)
    end
    x = powermod(x2, (_p + 3) ÷ 8, _p)
    if mod(x * x - x2, _p) != 0
        x = mod(x * _modp_sqrt_m1, _p)
    end
    if mod(x * x - x2, _p) != 0
        return nothing
    end
    if (x & 1) != sign
        x = _p - x
    end
    return x
end

const _g_y = mod(4 * _modp_inv(big(5)), _p)
const _g_x = _recover_x(_g_y, 0)::BigInt
const _G = (_g_x, _g_y, big(1), mod(_g_x * _g_y, _p))

function _point_compress(P)
    zinv = _modp_inv(P[3])
    x = mod(P[1] * zinv, _p)
    y = mod(P[2] * zinv, _p)
    return int_to_le(y | ((x & 1) << 255), 32)
end

function _point_decompress(s::AbstractVector{UInt8})
    length(s) == 32 || return nothing
    y = le_to_int(s)
    sign = Int(y >> 255)
    y &= (big(1) << 255) - 1
    x = _recover_x(y, sign)
    x === nothing && return nothing
    return (x, y, big(1), mod(x * y, _p))
end

function _secret_expand(secret::AbstractVector{UInt8})
    length(secret) == 32 || error("secret key must be 32 bytes")
    h = _sha512(Vector{UInt8}(secret))
    a = le_to_int(h[1:32])
    a &= (big(1) << 254) - 8
    a |= big(1) << 254
    return a, h[33:64]
end

_sha512_modq(s::Vector{UInt8}) = mod(le_to_int(_sha512(s)), _q)

"The 32-byte public key for a 32-byte secret key."
function secret_to_public(secret::AbstractVector{UInt8})
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, _G))
end

"The 64-byte Ed25519 signature of msg under the 32-byte secret key."
function sign(secret::AbstractVector{UInt8}, msg::AbstractVector{UInt8})
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, _G))
    r = _sha512_modq(vcat(prefix, msg))
    Rs = _point_compress(_point_mul(r, _G))
    h = _sha512_modq(vcat(Rs, A, msg))
    s = mod(r + h * a, _q)
    return vcat(Rs, int_to_le(s, 32))
end

"True iff signature is a valid Ed25519 signature of msg under public."
function verify(public::AbstractVector{UInt8}, msg::AbstractVector{UInt8},
                signature::AbstractVector{UInt8})
    (length(public) == 32 && length(signature) == 64) || return false
    A = _point_decompress(public)
    A === nothing && return false
    Rs = signature[1:32]
    R = _point_decompress(Rs)
    R === nothing && return false
    s = le_to_int(signature[33:64])
    s >= _q && return false
    h = _sha512_modq(vcat(Vector{UInt8}(Rs), Vector{UInt8}(public),
                          Vector{UInt8}(msg)))
    sB = _point_mul(s, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))
end

end # module Ed25519

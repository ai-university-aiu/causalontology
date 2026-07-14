# jcs.jl - RFC 8785 (JSON Canonicalization Scheme) serialization.
#
# Sorted keys, minimal string escaping (only '"', '\\', and code points below
# 0x20 are escaped), and ECMAScript-style canonical numbers: 1.0 -> "1",
# 0.7 stays "0.7", exponents are normalized to the ES6 shape (e-7, not e-07;
# a bare mantissa, not 1.0e-7).  Mirrors _jcs in the Python reference.

function _jcs_string(s::AbstractString)
    io = IOBuffer()
    write(io, '"')
    for ch in s
        if ch == '"'
            write(io, "\\\"")
        elseif ch == '\\'
            write(io, "\\\\")
        elseif ch == '\b'
            write(io, "\\b")
        elseif ch == '\t'
            write(io, "\\t")
        elseif ch == '\n'
            write(io, "\\n")
        elseif ch == '\f'
            write(io, "\\f")
        elseif ch == '\r'
            write(io, "\\r")
        elseif UInt32(ch) < 0x20
            write(io, "\\u", string(UInt32(ch), base=16, pad=4))
        else
            write(io, ch)
        end
    end
    write(io, '"')
    return String(take!(io))
end

function _jcs_float(n::Float64)
    isfinite(n) || error("NaN and Infinity are not permitted (RFC 8785)")
    n == 0 && return "0"
    if isinteger(n) && abs(n) < 1e21
        # an integral float prints as an exact integer, via BigInt
        return string(BigInt(n))
    end
    r = string(n)  # Julia's shortest-round-trip decimal
    if occursin('e', r)
        mant, expo = split(r, 'e')
        # ES6 prints a bare integral mantissa: 1.0e-7 -> 1e-7
        endswith(mant, ".0") && (mant = mant[1:end-2])
        sign = startswith(expo, "-") ? "-" : "+"
        digits = lstrip(lstrip(expo, ['+', '-']), '0')
        isempty(digits) && (digits = "0")
        r = mant * "e" * sign * digits
    end
    return r
end

_jcs(::Nothing) = "null"
_jcs(v::Bool) = v ? "true" : "false"
_jcs(v::Int64) = string(v)
_jcs(v::Float64) = _jcs_float(v)
_jcs(v::AbstractString) = _jcs_string(v)
_jcs(v::AbstractVector) = "[" * join((_jcs(x) for x in v), ",") * "]"

function _jcs(v::JObj)
    # RFC 8785 sorts properties by code point (Julia string order for our keys)
    items = sort(v.pairs, by=first)
    return "{" * join((_jcs_string(k) * ":" * _jcs(val) for (k, val) in items),
                      ",") * "}"
end

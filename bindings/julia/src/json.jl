# json.jl - a lossless, order-preserving JSON layer (standard library only).
#
# Julia's Dict is unordered, so JSON objects are held as association vectors
# (Vector{Pair{String,Any}}) wrapped in JObj: key order is preserved exactly
# as parsed or inserted, mirroring Python's insertion-ordered dict semantics
# in the reference binding.  Numbers keep their source literal distinction:
# a literal without [.eE] parses to Int64, otherwise Float64, so the
# integer-versus-decimal distinction (1 versus 1.0) survives to the
# canonicalizer just as Python's json module preserves it.

"An order-preserving JSON object: a vector of key => value pairs."
mutable struct JObj
    pairs::Vector{Pair{String,Any}}
end

JObj() = JObj(Vector{Pair{String,Any}}())

"Build a JObj from key => value pairs, in the given order."
function jobj(kvs::Pair...)
    o = JObj()
    for (k, v) in kvs
        jset!(o, String(k), v)
    end
    return o
end

"The keys of o, in insertion order."
jkeys(o::JObj) = String[k for (k, _) in o.pairs]

"True iff o has key k."
jhas(o::JObj, k::AbstractString) = any(p -> first(p) == k, o.pairs)

"The value at key k, or default when absent (Python dict.get)."
function jget(o::JObj, k::AbstractString, default=nothing)
    for (key, v) in o.pairs
        key == k && return v
    end
    return default
end

"Set key k to v, replacing in place or appending at the end (dict semantics)."
function jset!(o::JObj, k::AbstractString, v)
    for (i, p) in enumerate(o.pairs)
        if first(p) == k
            o.pairs[i] = String(k) => v
            return o
        end
    end
    push!(o.pairs, String(k) => v)
    return o
end

"Set key k to v only if absent (Python dict.setdefault)."
jsetdefault!(o::JObj, k::AbstractString, v) = jhas(o, k) ? o : jset!(o, k, v)

"Delete key k if present (Python dict.pop with default)."
function jdel!(o::JObj, k::AbstractString)
    i = findfirst(p -> first(p) == k, o.pairs)
    i === nothing || deleteat!(o.pairs, i)
    return o
end

"A shallow copy, like Python's dict(obj)."
jcopy(o::JObj) = JObj(copy(o.pairs))

Base.getindex(o::JObj, k::AbstractString) = begin
    for (key, v) in o.pairs
        key == k && return v
    end
    throw(KeyError(k))
end
Base.setindex!(o::JObj, v, k::AbstractString) = jset!(o, k, v)
Base.length(o::JObj) = length(o.pairs)

# Order-insensitive equality, mirroring Python dict equality.
function Base.:(==)(a::JObj, b::JObj)
    length(a.pairs) == length(b.pairs) || return false
    for (k, v) in a.pairs
        jhas(b, k) || return false
        jget(b, k) == v || return false
    end
    return true
end

# ---------------------------------------------------------------------------
# recursive-descent JSON parser over codeunits (bytes)
# ---------------------------------------------------------------------------

mutable struct _JsonParser
    bytes::Vector{UInt8}
    pos::Int
end

"Parse a JSON document; objects become JObj, arrays Vector{Any}."
json_parse(s::AbstractString) = json_parse(Vector{UInt8}(codeunits(s)))

function json_parse(bytes::Vector{UInt8})
    p = _JsonParser(bytes, 1)
    _skip_ws!(p)
    v = _parse_value!(p)
    _skip_ws!(p)
    p.pos <= length(p.bytes) && error("trailing JSON content at byte $(p.pos)")
    return v
end

function _skip_ws!(p::_JsonParser)
    while p.pos <= length(p.bytes) &&
            (p.bytes[p.pos] == 0x20 || p.bytes[p.pos] == 0x09 ||
             p.bytes[p.pos] == 0x0a || p.bytes[p.pos] == 0x0d)
        p.pos += 1
    end
end

function _expect!(p::_JsonParser, b::UInt8)
    (p.pos <= length(p.bytes) && p.bytes[p.pos] == b) ||
        error("expected '$(Char(b))' at byte $(p.pos)")
    p.pos += 1
end

function _parse_value!(p::_JsonParser)
    p.pos <= length(p.bytes) || error("unexpected end of JSON input")
    b = p.bytes[p.pos]
    b == UInt8('{') && return _parse_object!(p)
    b == UInt8('[') && return _parse_array!(p)
    b == UInt8('"') && return _parse_string!(p)
    if b == UInt8('t')
        _parse_literal!(p, "true"); return true
    elseif b == UInt8('f')
        _parse_literal!(p, "false"); return false
    elseif b == UInt8('n')
        _parse_literal!(p, "null"); return nothing
    end
    return _parse_number!(p)
end

function _parse_literal!(p::_JsonParser, lit::String)
    for c in codeunits(lit)
        (p.pos <= length(p.bytes) && p.bytes[p.pos] == c) ||
            error("bad literal at byte $(p.pos)")
        p.pos += 1
    end
end

function _parse_object!(p::_JsonParser)
    _expect!(p, UInt8('{'))
    o = JObj()
    _skip_ws!(p)
    if p.pos <= length(p.bytes) && p.bytes[p.pos] == UInt8('}')
        p.pos += 1
        return o
    end
    while true
        _skip_ws!(p)
        k = _parse_string!(p)
        _skip_ws!(p)
        _expect!(p, UInt8(':'))
        _skip_ws!(p)
        v = _parse_value!(p)
        jset!(o, k, v)
        _skip_ws!(p)
        p.pos <= length(p.bytes) || error("unterminated object")
        if p.bytes[p.pos] == UInt8(',')
            p.pos += 1
        elseif p.bytes[p.pos] == UInt8('}')
            p.pos += 1
            return o
        else
            error("expected ',' or '}' at byte $(p.pos)")
        end
    end
end

function _parse_array!(p::_JsonParser)
    _expect!(p, UInt8('['))
    a = Any[]
    _skip_ws!(p)
    if p.pos <= length(p.bytes) && p.bytes[p.pos] == UInt8(']')
        p.pos += 1
        return a
    end
    while true
        _skip_ws!(p)
        push!(a, _parse_value!(p))
        _skip_ws!(p)
        p.pos <= length(p.bytes) || error("unterminated array")
        if p.bytes[p.pos] == UInt8(',')
            p.pos += 1
        elseif p.bytes[p.pos] == UInt8(']')
            p.pos += 1
            return a
        else
            error("expected ',' or ']' at byte $(p.pos)")
        end
    end
end

function _hex4!(p::_JsonParser)
    p.pos + 3 <= length(p.bytes) || error("truncated \\u escape")
    v = UInt32(0)
    for _ in 1:4
        c = p.bytes[p.pos]
        d = UInt8('0') <= c <= UInt8('9') ? c - UInt8('0') :
            UInt8('a') <= c <= UInt8('f') ? c - UInt8('a') + 0x0a :
            UInt8('A') <= c <= UInt8('F') ? c - UInt8('A') + 0x0a :
            error("bad hex digit in \\u escape")
        v = v * 16 + d
        p.pos += 1
    end
    return v
end

function _parse_string!(p::_JsonParser)
    _expect!(p, UInt8('"'))
    io = IOBuffer()
    while true
        p.pos <= length(p.bytes) || error("unterminated string")
        b = p.bytes[p.pos]
        if b == UInt8('"')
            p.pos += 1
            return String(take!(io))
        elseif b == UInt8('\\')
            p.pos += 1
            p.pos <= length(p.bytes) || error("unterminated escape")
            e = p.bytes[p.pos]
            p.pos += 1
            if e == UInt8('"');      write(io, '"')
            elseif e == UInt8('\\'); write(io, '\\')
            elseif e == UInt8('/');  write(io, '/')
            elseif e == UInt8('b');  write(io, '\b')
            elseif e == UInt8('f');  write(io, '\f')
            elseif e == UInt8('n');  write(io, '\n')
            elseif e == UInt8('r');  write(io, '\r')
            elseif e == UInt8('t');  write(io, '\t')
            elseif e == UInt8('u')
                cp = _hex4!(p)
                if 0xD800 <= cp <= 0xDBFF && p.pos + 1 <= length(p.bytes) &&
                        p.bytes[p.pos] == UInt8('\\') &&
                        p.bytes[p.pos + 1] == UInt8('u')
                    p.pos += 2
                    lo = _hex4!(p)
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                end
                write(io, Char(cp))
            else
                error("bad escape at byte $(p.pos)")
            end
        else
            # a raw byte of the UTF-8 stream is copied through unchanged
            write(io, b)
            p.pos += 1
        end
    end
end

function _parse_number!(p::_JsonParser)
    start = p.pos
    while p.pos <= length(p.bytes) &&
            (p.bytes[p.pos] in UInt8[UInt8('-'), UInt8('+'), UInt8('.'),
                                     UInt8('e'), UInt8('E')] ||
             UInt8('0') <= p.bytes[p.pos] <= UInt8('9'))
        p.pos += 1
    end
    start < p.pos || error("bad JSON value at byte $(p.pos)")
    lit = String(p.bytes[start:p.pos - 1])
    # numbers are tagged by literal: no [.eE] means an integer (Int64)
    if occursin('.', lit) || occursin('e', lit) || occursin('E', lit)
        return parse(Float64, lit)
    end
    return parse(Int64, lit)
end

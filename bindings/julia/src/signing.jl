# signing.jl - record-level signing and verification (spec/provenance.md).
#
# The signature is computed over the record's canonical identity-bearing
# bytes (the RFC 8785 form with id and signature removed - exactly the bytes
# that are hashed for the record's identifier), so verification needs
# nothing but the record itself.  Ed25519 is deterministic (RFC 8032):
# re-signing the same record with the same key yields the same signature,
# so re-submission is idempotent.  A succession verifies against its
# predecessor key.

"(secret, \"ed25519:<hex>\") from a 32-byte seed."
function keypair_from_seed(seed32::Vector{UInt8})
    public = Ed25519.secret_to_public(seed32)
    return seed32, "ed25519:" * bytes2hex(public)
end

"Return the record completed with its id and Ed25519 signature."
function sign_record(record::JObj, secret::Vector{UInt8}, kind=nothing)
    k = kind === nothing ? infer_kind(record) : kind
    body = jcopy(record)
    jdel!(body, "signature")
    message = canonicalize(body, k)
    signature = bytes2hex(Ed25519.sign(secret, message))
    out = jcopy(body)
    jset!(out, "id", identify(body, k))
    jset!(out, "signature", signature)
    return out
end

function _signer_key_hex(record::JObj, kind)
    # a succession is signed by the predecessor key
    field = kind == "succession" ? "predecessor" : "source"
    value = jget(record, field, "")
    (value isa AbstractString && startswith(value, "ed25519:")) ||
        return nothing
    return String(split(value, ':'; limit=2)[2])
end

"True iff the record's signature verifies against its own key field."
function verify_record(record::JObj, kind=nothing)
    k = kind === nothing ? infer_kind(record) : kind
    sig_hex = jget(record, "signature")
    key_hex = _signer_key_hex(record, k)
    (sig_hex === nothing || sig_hex == "" || key_hex === nothing) &&
        return false
    public = try
        hex2bytes(String(key_hex))
    catch
        return false
    end
    signature = try
        hex2bytes(String(sig_hex))
    catch
        return false
    end
    body = jcopy(record)
    jdel!(body, "signature")
    return Ed25519.verify(public, canonicalize(body, k), signature)
end

-- signing.lua - record-level signing and verification (spec/provenance.md).
--
-- The signature is computed over the record's canonical identity-bearing
-- bytes (the RFC 8785 form with id and signature removed - exactly the bytes
-- that are hashed for the record's identifier), so verification needs
-- nothing but the record itself.  Ed25519 is deterministic (RFC 8032):
-- re-signing the same record with the same key yields the same signature,
-- so re-submission is idempotent.

local json = require("causalontology.json")
local ed25519 = require("causalontology.ed25519")
local canonical = require("causalontology.canonical")
local sha2 = require("causalontology.sha2")

local signing = {}

-- (secret, "ed25519:<hex>") from a 32-byte seed.
function signing.keypair_from_seed(seed32)
  local public = ed25519.secret_to_public(seed32)
  return seed32, "ed25519:" .. sha2.to_hex(public)
end

-- Return the record completed with its id and Ed25519 signature.
function signing.sign_record(record, secret, kind)
  kind = kind or canonical.infer_kind(record)
  local body = json.copy_object(record)
  json.set(body, "signature", nil)
  local message = canonical.canonicalize(body, kind)
  local signature = sha2.to_hex(ed25519.sign(secret, message))
  local out = json.copy_object(body)
  json.set(out, "id", canonical.identify(body, kind))
  json.set(out, "signature", signature)
  return out
end

-- A succession is signed by the predecessor key; all else by the source.
local function signer_key_hex(record, kind)
  local field = (kind == "succession") and "predecessor" or "source"
  local value = record[field] or ""
  if value:sub(1, 8) ~= "ed25519:" then return nil end
  return value:sub(9)
end

-- True iff the record's signature verifies against its own key field.
function signing.verify_record(record, kind)
  kind = kind or canonical.infer_kind(record)
  local sig_hex = record["signature"]
  local key_hex = signer_key_hex(record, kind)
  if not sig_hex or sig_hex == "" or not key_hex then return false end
  local public = sha2.from_hex(key_hex)
  local signature = sha2.from_hex(sig_hex)
  if not public or not signature then return false end
  local body = json.copy_object(record)
  json.set(body, "signature", nil)
  local message = canonical.canonicalize(body, kind)
  return ed25519.verify(public, message, signature)
end

return signing

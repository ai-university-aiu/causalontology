-- canonical.lua - canonicalization and content-addressed identity.
--
-- Implements the identity procedure of spec/identity.md:
--   1. take the object as JSON,
--   2. keep only the identity-bearing fields for its kind (with "type"
--      injected),
--   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
--   4. hash with SHA-256,
--   5. identifier = scheme + ":" + lowercase hex digest.
--
-- A faithful port of bindings/python/causalontology/canonical.py, with the
-- RFC 8785 serialization living in jcs.lua.

local json = require("causalontology.json")
local jcs = require("causalontology.jcs")
local sha2 = require("causalontology.sha2")

local canonical = {}

canonical.IDENTITY_FIELDS = {
  occurrent  = { "label", "category" },
  cro        = { "causes", "effects", "mechanism", "temporal", "modality",
                 "context", "refines" },
  continuant = { "label", "category" },
  realizable = { "kind", "bearer" },
  assertion  = { "about", "source", "evidence_type", "evidence", "strength",
                 "confidence", "timestamp" },
  enrichment = { "about", "field", "entry", "source", "timestamp" },
  retraction = { "retracts", "source", "timestamp" },
  succession = { "predecessor", "successor", "timestamp" },
}

canonical.PREFIX = {
  occurrent = "occurrent", cro = "causal_relation_object", continuant = "continuant", realizable = "realizable",
  assertion = "assertion", enrichment = "enrichment", retraction = "retraction",
  succession = "succession",
}

canonical.KIND_OF_PREFIX = {}
for kind, prefix in pairs(canonical.PREFIX) do
  canonical.KIND_OF_PREFIX[prefix] = kind
end

-- Infer an object's kind from its type field, id prefix, or shape.
function canonical.infer_kind(obj)
  if obj["type"] ~= nil then return obj["type"] end
  local id = obj["id"]
  if type(id) == "string" and id:find(":", 1, true) then
    local pre = id:match("^([^:]*):")
    if canonical.KIND_OF_PREFIX[pre] then
      return canonical.KIND_OF_PREFIX[pre]
    end
  end
  if obj["causes"] ~= nil and obj["effects"] ~= nil then return "causal_relation_object" end
  if obj["retracts"] ~= nil then return "retraction" end
  if obj["predecessor"] ~= nil and obj["successor"] ~= nil then
    return "succession"
  end
  if obj["field"] ~= nil and obj["entry"] ~= nil then return "enrichment" end
  if obj["evidence_type"] ~= nil
      or (obj["about"] ~= nil and obj["confidence"] ~= nil) then
    return "assertion"
  end
  if obj["kind"] ~= nil and obj["bearer"] ~= nil then return "realizable" end
  error("cannot infer kind (occurrents and continuants share a shape); " ..
        "pass kind explicitly", 0)
end

-- The identity-bearing subset of an object, with type always present.
-- Returns kind, subset.
function canonical.identity_bearing(obj, kind)
  kind = kind or canonical.infer_kind(obj)
  local fields = canonical.IDENTITY_FIELDS[kind]
  if not fields then
    error("unknown kind: " .. tostring(kind), 0)
  end
  local out = json.obj("type", kind)
  for _, field in ipairs(fields) do
    if obj[field] ~= nil then
      json.set(out, field, obj[field])
    end
  end
  return kind, out
end

-- The RFC 8785 identity-bearing bytes of an object.
function canonical.canonicalize(obj, kind)
  local _, ib = canonical.identity_bearing(obj, kind)
  return jcs.serialize(ib)
end

-- The content-addressed identifier: scheme + ":" + SHA-256 hex.
function canonical.identify(obj, kind)
  local k, ib = canonical.identity_bearing(obj, kind)
  local digest = sha2.sha256_hex(jcs.serialize(ib))
  return canonical.PREFIX[k] .. ":" .. digest
end

return canonical

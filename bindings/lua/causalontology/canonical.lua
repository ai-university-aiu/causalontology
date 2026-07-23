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

-- The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds the
-- cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the attitude,
-- the predicted_occurrence, and the prediction_error - all additive and
-- identity-preserving, so a record that omits a new field keeps its earlier
-- identifier byte-for-byte, and the new kinds open new identity schemes that
-- disturb no existing record). "type" is always injected, so it is not listed
-- here. Order does not matter (JCS sorts keys).
-- 2.0.0 whole-word re-mint (Principle P7): the kind key, the type value, and
-- the id scheme are one and the same string.
canonical.IDENTITY_FIELDS = {
  -- ---- type tier ----
  occurrent  = { "label", "category", "stratum" },
  causal_relation_object = { "causes", "effects", "mechanism", "temporal",
                             "modality", "context", "refines", "skips" },
  continuant = { "label", "category" },
  realizable = { "kind", "bearer", "label" },
  stratum    = { "label", "scheme", "ordinal", "unit", "governs" },
  bridge     = { "coarse", "fine", "relation" },
  cross_stratal_seam = { "source", "target", "mechanism_status", "chain" },
  port       = { "bearer", "label", "direction", "accepts", "realizable" },
  conduit    = { "label", "from", "to", "carries", "transform", "realized_by" },
  quality    = { "label", "datatype", "unit", "stratum" },
  -- ---- token tier ----
  token_individual   = { "instantiates", "designator", "part_of" },
  token_occurrence   = { "instantiates", "interval", "participants",
                         "locus", "observer" },
  state_assertion    = { "subject", "quality", "value", "interval" },
  token_causal_claim = { "causes", "effects", "covering_law",
                         "actual_delay", "counterfactual" },
  attitude             = { "holder", "attitude_type", "content" },
  predicted_occurrence = { "instantiates", "interval", "predictor",
                           "strength" },
  prediction_error     = { "predicted", "observed", "discrepancy" },
  -- ---- provenance tier ----
  assertion  = { "about", "source", "evidence_type", "evidence", "strength",
                 "confidence", "timestamp", "evidenced_by" },
  enrichment = { "about", "field", "entry", "source", "timestamp" },
  retraction = { "retracts", "source", "timestamp" },
  succession = { "predecessor", "successor", "timestamp" },
}

-- Whole-word re-mint (P7): the scheme IS the type value for every kind.
canonical.PREFIX = {}
for kind in pairs(canonical.IDENTITY_FIELDS) do
  canonical.PREFIX[kind] = kind
end

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
  if obj["coarse"] ~= nil and obj["fine"] ~= nil then return "bridge" end
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

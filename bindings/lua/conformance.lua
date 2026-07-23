#!/usr/bin/env lua
-- conformance.lua - the Causalontology conformance runner for
-- causalontology-lua (specification 4.0.0).
--
-- Runs every vector in conformance/vectors/ against the Lua binding.  An
-- implementation is conformant if and only if it passes every vector; this
-- runner exits nonzero on any failure.  It mirrors
-- bindings/python/tests/run_conformance.py exactly: V01-V38 re-frozen unaltered
-- in meaning (whole-word re-mint, Principle P7), V39-V107 new in 2.0.0,
-- V108-V119 the 3.0.0 additions (the ordinal ticks unit, the cross_stratal_seam
-- with Algorithm F, the conduit realized_by), and V120-V137 the 4.0.0 additions
-- (the attitude, the predicted_occurrence, the prediction_error).
--
-- Usage, from anywhere:  lua bindings/lua/conformance.lua
-- The repository root is CAUSALONTOLOGY_ROOT when set, else two directories
-- above this script.

-- ------------------------------------------------------------------ paths

local script = arg and arg[0] or "conformance.lua"
local script_dir = script:match("^(.*)[/\\][^/\\]*$") or "."
package.path = script_dir .. "/?.lua;" .. script_dir .. "/?/init.lua;"
               .. package.path

local ROOT = os.getenv("CAUSALONTOLOGY_ROOT") or (script_dir .. "/../..")
local VECDIR = ROOT .. "/conformance/vectors"

local json = require("causalontology.json")
local jcs = require("causalontology.jcs")
local sha2 = require("causalontology.sha2")
local ed25519 = require("causalontology.ed25519")
local canonical = require("causalontology.canonical")
local schema = require("causalontology.schema")
local semantics = require("causalontology.semantics")
local signing = require("causalontology.signing")
local store = require("causalontology.store")

-- point schema validation at the repository's spec/ directory
schema.spec_dir = schema.spec_dir or (ROOT .. "/spec")

local identify = canonical.identify
local validate_schema = schema.validate_schema
local validate_semantics = semantics.validate_semantics

-- ------------------------------------------------- vector file discovery

local vector_files = {}
do
  local ls = assert(io.popen("ls -1 '" .. VECDIR .. "' 2>/dev/null"),
                    "cannot list " .. VECDIR)
  for name in ls:lines() do
    local n = tonumber(name:match("^v(%d+)_.*%.json$"))
    if n then vector_files[n] = name end
  end
  ls:close()
  assert(vector_files[1], "no vectors found in " .. VECDIR)
end

local function vec(n)
  local fname = assert(vector_files[n], "vector " .. n .. " not found")
  local f = assert(io.open(VECDIR .. "/" .. fname, "rb"))
  local data = json.decode(f:read("a"))
  f:close()
  return data
end

local function vec_name(n)
  return (vector_files[n]:gsub("%.json$", ""))
end

-- ---------------------------------------------------------------- shorthand

local function O(...) return json.obj(...) end
local function A(list) return json.new_array(list) end

-- A content object completed with its real content-addressed id.
local function mk(obj)
  json.set(obj, "id", identify(obj))
  return obj
end

-- ---------------------------------------------------------- symbolic ids

-- Every whole-word scheme (Principle P7), plus the external ed25519 name.
local SCHEMES = {
  occurrent = true, causal_relation_object = true, continuant = true,
  realizable = true, assertion = true, enrichment = true, retraction = true,
  succession = true, stratum = true, bridge = true, cross_stratal_seam = true,
  port = true, conduit = true, quality = true, token_individual = true,
  token_occurrence = true, state_assertion = true, token_causal_claim = true,
  attitude = true, predicted_occurrence = true, prediction_error = true,
}
local WHOLE_WORD = {}
for k in pairs(SCHEMES) do WHOLE_WORD[k] = true end
WHOLE_WORD["ed25519"] = true

local KEYS = {}

-- A real, deterministic Ed25519 keypair for a symbolic key name.
local function key(name)
  if not KEYS[name] then
    local seed = sha2.sha256("key:" .. name)
    local secret, public = signing.keypair_from_seed(seed)
    KEYS[name] = { secret = secret, public = public }
  end
  return KEYS[name].secret, KEYS[name].public
end

local function is_64_hex(s)
  return #s == 64 and s:match("^[0-9a-f]+$") ~= nil
end

-- Normalize one symbolic identifier to a well-formed one.
local function sym(s)
  local scheme, name = s:match("^([^:]+):(.*)$")
  if scheme == "ed25519" then
    if is_64_hex(name) then return s end
    local _, public = key(name)
    return public
  end
  if is_64_hex(name) then return s end
  return scheme .. ":" .. sha2.sha256_hex(name)
end

-- Recursively normalize symbolic identifiers and placeholders.
local function normalize(x)
  if type(x) == "string" then
    if x == "<128 hex>" then return string.rep("ab", 64) end
    local pre = x:match("^([%w_]+):")
    if pre and (SCHEMES[pre] or pre == "ed25519") then return sym(x) end
    return x
  elseif json.is_array(x) then
    local out = json.new_array()
    for i, v in ipairs(x) do out[i] = normalize(v) end
    return out
  elseif json.is_object(x) then
    local out = json.new_object()
    for _, k in ipairs(json.keys(x)) do
      json.set(out, k, normalize(x[k]))
    end
    return out
  end
  return x
end

local TS = "2026-07-13T0%d:00:00Z"

-- Build, timestamp, and sign a provenance record.
local function signed(kind, body, who, ts_i)
  local secret, public = key(who)
  local rec = json.copy_object(body)
  json.set(rec, "type", kind)
  json.setdefault(rec, "timestamp", string.format(TS, ts_i or 0))
  if kind == "succession" then
    json.setdefault(rec, "predecessor", public)
  else
    json.set(rec, "source", public)
  end
  return signing.sign_record(rec, secret, kind)
end

-- ---------------------------------------------------------------- builders

local function stratum(label, scheme, ordinal, unit, governs)
  local o = O("type", "stratum", "label", label, "scheme", scheme,
              "ordinal", ordinal)
  if unit then json.set(o, "unit", unit) end
  if governs then json.set(o, "governs", governs) end
  return mk(o)
end

local function occ(label, stratum_id, category)
  local o = O("type", "occurrent", "label", label,
              "category", category or "event")
  if stratum_id then json.set(o, "stratum", stratum_id) end
  return mk(o)
end

local function cnt(label, category)
  return mk(O("type", "continuant", "label", label,
              "category", category or "object"))
end

local CRO_KW = { "mechanism", "temporal", "modality", "context", "refines", "skips" }

local function cro(causes, effects, opts)
  opts = opts or {}
  local o = O("type", "causal_relation_object",
              "causes", causes, "effects", effects)
  for _, f in ipairs(CRO_KW) do
    if opts[f] ~= nil then json.set(o, f, opts[f]) end
  end
  return mk(o)
end

local function bridge(coarse, fine, relation)
  return mk(O("type", "bridge", "coarse", coarse, "fine", fine,
              "relation", relation))
end

local function port(bearer, label, direction, accepts, realizable)
  local o = O("type", "port", "bearer", bearer, "label", label,
              "direction", direction, "accepts", accepts)
  if realizable then json.set(o, "realizable", realizable) end
  return mk(o)
end

local function conduit(frm, to, carries, label, transform)
  local o = O("type", "conduit", "label", label or "conn",
              "from", frm, "to", to, "carries", carries)
  if transform then json.set(o, "transform", transform) end
  return mk(o)
end

local function quality(label, datatype, unit, stratum_id)
  local o = O("type", "quality", "label", label, "datatype", datatype)
  if unit then json.set(o, "unit", unit) end
  if stratum_id then json.set(o, "stratum", stratum_id) end
  return mk(o)
end

local function individual(instantiates, designator, part_of)
  local o = O("type", "token_individual", "instantiates", instantiates)
  if designator then json.set(o, "designator", designator) end
  if part_of then json.set(o, "part_of", part_of) end
  return mk(o)
end

local function token(instantiates, interval, participants, locus)
  local o = O("type", "token_occurrence", "instantiates", instantiates,
              "interval", interval)
  if participants then json.set(o, "participants", participants) end
  if locus then json.set(o, "locus", locus) end
  return mk(o)
end

local function state(subject, qual, value, interval)
  return mk(O("type", "state_assertion", "subject", subject, "quality", qual,
              "value", value, "interval", interval))
end

local function tcc(causes, effects, opts)
  opts = opts or {}
  local o = O("type", "token_causal_claim", "causes", causes, "effects", effects)
  if opts.covering_law ~= nil then json.set(o, "covering_law", opts.covering_law) end
  if opts.actual_delay ~= nil then json.set(o, "actual_delay", opts.actual_delay) end
  if opts.counterfactual ~= nil then json.set(o, "counterfactual", opts.counterfactual) end
  return mk(o)
end

local function rlz(bearer, kind, label)
  local o = O("type", "realizable", "kind", kind, "bearer", bearer)
  if label then json.set(o, "label", label) end
  return mk(o)
end

-- ---------------------------------------------------------------- assert

local function check(cond, why)
  if not cond then error(tostring(why), 0) end
end

local function expect_rejected(fn, why)
  local ok, err = pcall(fn)
  check(not ok, why or "expected a RejectedWrite")
  check(store.is_rejected(err),
        "expected a RejectedWrite, got: " .. tostring(err))
  return err.message
end

local function any_mention(reasons, fragment)
  for _, r in ipairs(reasons) do
    if r:find(fragment, 1, true) then return true end
  end
  return false
end

local function reasons_str(why)
  return table.concat(why or {}, "; ")
end

-- Count the keys of a set table.
local function count(set)
  local n = 0
  for _ in pairs(set) do n = n + 1 end
  return n
end

-- ---------------------------------------------------------------------
-- internal sanity checks (not conformance vectors)
-- ---------------------------------------------------------------------

local function internal_checks()
  local sk = sha2.from_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  local pk = ed25519.secret_to_public(sk)
  check(sha2.to_hex(pk) ==
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    sha2.to_hex(pk))
  local sig = ed25519.sign(sk, "")
  check(ed25519.verify(pk, "", sig), "TEST 1 signature must verify")
  check(not ed25519.verify(pk, "x", sig), "wrong message must not verify")
  check(jcs.serialize(json.obj("b", 2, "a", 1)) == '{"a":1,"b":2}', "JCS keys")
  check(jcs.serialize(1.0) == "1", "JCS 1.0")
  check(jcs.serialize(6.000) == "6", "JCS 6.000")
  check(jcs.serialize(0.7) == "0.7", "JCS 0.7")
  check(semantics.to_seconds(1, "months") == 2629746, "months")
  check(semantics.to_seconds(1, "years") == 31556952, "years")
end

-- ---------------------------------------------------------------------
-- V01 - V38: the whole-word re-freeze of the 1.0.0 suite
-- ---------------------------------------------------------------------

local V = {}

V[1] = function()
  local inp = normalize(vec(1)["input"])
  local ok, why = validate_schema(inp); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(inp); check(ok2, reasons_str(why2))
end

V[2] = function()
  local inp = normalize(vec(2)["input"])
  check((validate_schema(inp)), "schema")
  check((validate_semantics(inp)), "semantics")
  local partial, missing = semantics.is_partial(inp)
  local expected = vec(2)["expect"]["missing"]
  check(partial, "must be partial")
  check(#missing == #expected, "missing count")
  for i = 1, #expected do
    check(missing[i] == expected[i], "missing order: " .. missing[i])
  end
end

local function schema_fails(n, must_mention)
  local inp = normalize(vec(n)["input"])
  local ok, why = validate_schema(inp)
  check(not ok, "expected schema-invalid")
  check(any_mention(why, must_mention), reasons_str(why))
end

V[3] = function() schema_fails(3, "effects") end
V[4] = function() schema_fails(4, "causes") end
V[5] = function() schema_fails(5, "modality") end
V[6] = function() schema_fails(6, "colour") end
V[7] = function() schema_fails(7, "causes") end

V[8] = function()
  local ok, why = validate_schema(normalize(vec(8)["input"]))
  check(ok, reasons_str(why))
end

V[9] = function() schema_fails(9, "label") end
V[10] = function() schema_fails(10, "category") end

V[11] = function()
  local ok, why = validate_schema(normalize(vec(11)["input"]))
  check(ok, reasons_str(why))
end

V[12] = function() schema_fails(12, "confidence") end

V[13] = function()
  local inp = normalize(vec(13)["input"])
  local ok, why = validate_schema(inp); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(inp); check(ok2, reasons_str(why2))
end

local function semantics_fails(n, must_mention)
  local inp = normalize(vec(n)["input"])
  local ok, why = validate_semantics(inp)
  check(not ok, "expected semantically-invalid")
  check(any_mention(why, must_mention), reasons_str(why))
end

V[14] = function()
  local inp = normalize(vec(14)["input"])
  check((validate_schema(inp)), "schema must pass")
  semantics_fails(14, "minimum_delay")
end

V[15] = function() semantics_fails(15, "acyclic") end
V[16] = function() semantics_fails(16, "acyclic") end

V[17] = function()
  local v = vec(17)
  local parent = normalize(v["given"]["parent"])
  local child = normalize(v["input"])
  local ok, reason = semantics.refinement_valid(child, parent)
  check(not ok and reason:find("rival", 1, true), reason)
end

V[18] = function() semantics_fails(18, "not a legal field") end
V[19] = function() semantics_fails(19, "language-tagged") end

V[20] = function()
  local dog, mam, ani = sym("continuant:dog"), sym("continuant:mammal"), sym("continuant:animal")
  local function enrich(about, entry, i)
    return signed("enrichment",
      O("about", about, "field", "subsumes", "entry", entry), "taxo", i)
  end
  local s = store.new(true)
  s:put_record(enrich(dog, mam, 1))
  s:put_record(enrich(mam, ani, 2))
  local message = expect_rejected(function()
    s:put_record(enrich(ani, dog, 3))
  end, "enforcing store accepted a cycle")
  check(message:find("cycle", 1, true), message)
  local s2 = store.new(true)
  s2:put_record(enrich(dog, mam, 1))
  s2:put_record(enrich(mam, ani, 2))
  local bad = enrich(ani, dog, 3)
  s2:force_merge_record(bad)
  local _, excluded = s2:_active_taxonomy_edges("subsumes")
  check(#excluded == 1 and excluded[1]["id"] == bad["id"], "excluded edge")
  local found = false
  for _, g in ipairs(s2:gaps("inconsistent_hierarchy")) do
    if g.id == bad["id"] then found = true end
  end
  check(found, "repair gap missing")
end

local function adm(n)
  local g = vec(n)["given"]
  local c = O("causes", A({ sym("occurrent:c") }),
              "effects", A({ sym("occurrent:e") }),
              "temporal", g["temporal"])
  return semantics.admissible(c, g["elapsed_seconds"])
end

V[21] = function() check(adm(21) == true, "must be admissible") end
V[22] = function() check(adm(22) == false, "must not be admissible") end
V[23] = function() check(adm(23) == true, "must be admissible") end

V[24] = function()
  local v = vec(24)
  check(identify(normalize(v["inputA"])) == identify(normalize(v["inputB"])),
        "identifiers differ")
end

V[25] = function()
  local v = vec(25)
  check(identify(normalize(v["inputA"])) == identify(normalize(v["inputB"])),
        "identifiers differ")
end

V[26] = function()
  local s = store.new()
  local obj = O("type", "occurrent", "label", "press_button", "category", "action")
  local a = s:put(json.copy_object(obj))
  local b = s:put(json.copy_object(obj))
  check(a == b and #s.object_order == 1, "put is not idempotent")
end

V[27] = function()
  local s = store.new()
  local o = s:put(O("type", "occurrent", "label", "press_button", "category", "action"))
  local entry = O("lang", "en", "text", "press the button")
  local r1 = signed("enrichment", O("about", o, "field", "aliases", "entry", entry), "alice", 1)
  local r2 = signed("enrichment", O("about", o, "field", "aliases", "entry", entry), "bob", 2)
  check(s:put_record(r1) ~= s:put_record(r2), "two records expected")
  local view = s:get(o).enrichments["aliases"]
  check(#view == 1 and #view[1].contributors == 2, "corroboration view")
end

V[28] = function()
  local s = store.new()
  local claim = O("type", "causal_relation_object",
    "causes", A({ sym("occurrent:A") }), "effects", A({ sym("occurrent:B") }),
    "modality", "sufficient")
  local i1 = s:put(json.copy_object(claim))
  local i2 = s:put(json.copy_object(claim))
  check(i1 == i2 and #s.object_order == 1, "one object expected")
  s:put_record(signed("assertion",
    O("about", i1, "evidence_type", "observation", "strength", 0.8, "confidence", 0.8), "lab1", 1))
  s:put_record(signed("assertion",
    O("about", i1, "evidence_type", "observation", "strength", 0.8, "confidence", 0.8), "lab2", 2))
  check(#s:assertions_about(i1) == 2, "two assertions expected")
end

V[29] = function()
  local rec = signed("assertion",
    O("about", sym("causal_relation_object:demo"), "evidence_type", "intervention",
      "strength", 0.7, "confidence", 0.9), "signer")
  check(signing.verify_record(rec) == true, "signature must verify")
end

V[30] = function()
  local rec = signed("assertion",
    O("about", sym("causal_relation_object:demo"), "evidence_type", "intervention",
      "strength", 0.7, "confidence", 0.9), "signer")
  local tampered = json.copy_object(rec)
  json.set(tampered, "confidence", 0.1)
  check(signing.verify_record(tampered) == false, "tampering must fail")
end

V[31] = function()
  local s = store.new()
  local x = s:put(O("type", "causal_relation_object",
    "causes", A({ sym("occurrent:A") }), "effects", A({ sym("occurrent:B") })))
  local a = signed("assertion",
    O("about", x, "evidence_type", "observation", "confidence", 0.8), "lab1", 1)
  s:put_record(a)
  s:put_record(signed("retraction", O("retracts", a["id"]), "lab1", 2))
  check(#s:assertions_about(x) == 0, "retracted assertion still visible")
  local hist = s:assertions_about(x, true)
  check(#hist == 1 and hist[1]["retracted"] == true, "history flag missing")
  local foreign = signed("retraction", O("retracts", a["id"]), "mallory", 3)
  expect_rejected(function() s:put_record(foreign) end, "foreign retraction accepted")
end

V[32] = function()
  local s = store.new()
  local o = s:put(O("type", "occurrent", "label", "press_button", "category", "action"))
  local e = signed("enrichment",
    O("about", o, "field", "aliases", "entry", O("lang", "ja", "text", "botan")), "bob", 1)
  s:put_record(e)
  check(#(s:get(o).enrichments["aliases"] or {}) == 1, "alias missing")
  s:put_record(signed("retraction", O("retracts", e["id"]), "bob", 2))
  check(#(s:get(o).enrichments["aliases"] or {}) == 0, "retracted alias still visible")
  local hist = s:get(o, "history").enrichments["aliases"] or {}
  check(#hist == 1, "history view lost the alias")
end

V[33] = function()
  local s = store.new()
  local _, k1 = key("K1")
  local _, k2 = key("K2")
  local a = signed("assertion",
    O("about", sym("causal_relation_object:claim"), "evidence_type", "observation",
      "confidence", 0.9), "K1", 1)
  s:put_record(a)
  s:put_record(signed("succession", O("successor", k2), "K1", 2))
  check(s:lineage(k2)[k1] == true and s:lineage(k1)[k2] == true, "lineage")
  s:put_record(signed("retraction", O("retracts", a["id"]), "K2", 3))
  check(#s:assertions_about(sym("causal_relation_object:claim")) == 0, "succession retraction")
end

V[34] = function()
  local g = normalize(vec(34)["given"])
  check(semantics.conflicts(g["A"], g["B"]) == true, "must conflict")
end

V[35] = function()
  local g = normalize(vec(35)["given"])
  check(semantics.conflicts(g["A"], g["B"]) == false, "must not conflict")
end

V[36] = function()
  local A_, B_, C_, D_ = sym("occurrent:A"), sym("occurrent:B"), sym("occurrent:C"), sym("occurrent:D")
  local m1 = O("id", sym("causal_relation_object:m1"), "causes", A({ A_ }), "effects", A({ B_ }))
  local m2 = O("id", sym("causal_relation_object:m2"), "causes", A({ B_ }), "effects", A({ C_ }))
  local m3 = O("id", sym("causal_relation_object:m3"), "causes", A({ D_ }), "effects", A({ C_ }))
  local P = O("causes", A({ A_ }), "effects", A({ C_ }),
              "mechanism", A({ m1["id"], m2["id"] }))
  check(semantics.hierarchy_consistent(P, { [m1["id"]] = m1, [m2["id"]] = m2 }) == "consistent", "consistent")
  local P2 = json.copy_object(P)
  json.set(P2, "mechanism", A({ m1["id"], m3["id"] }))
  check(semantics.hierarchy_consistent(P2, { [m1["id"]] = m1, [m3["id"]] = m3 }) == "inconsistent", "inconsistent")
  check(semantics.hierarchy_consistent(P, { [m1["id"]] = m1 }) == "indeterminate", "indeterminate")
end

V[37] = function()
  local s = store.new()
  local o = s:put(O("type", "occurrent", "label", "press_button", "category", "action"))
  s:put_record(signed("enrichment",
    O("about", o, "field", "aliases", "entry", O("lang", "en", "text", "Press the Button")), "alice", 1))
  local hits = s:resolve("Press  The   Button", "en")
  check(#hits == 1 and hits[1] == o, "alias match")
  check(s:resolve("press_button", "en")[1] == o, "label, first")
end

V[38] = function()
  local s = store.new()
  local P = s:put(O("type", "causal_relation_object",
    "causes", A({ sym("occurrent:A") }), "effects", A({ sym("occurrent:B") })))
  local function gap_ids()
    local ids = {}
    for _, g in ipairs(s:gaps("missing_field")) do ids[g.id] = true end
    return ids
  end
  check(gap_ids()[P] == true, "the parent must be a gap")
  local R = s:put(O("type", "causal_relation_object",
    "causes", A({ sym("occurrent:A") }), "effects", A({ sym("occurrent:B") }),
    "temporal", O("minimum_delay", 0, "maximum_delay", 1, "unit", "seconds"),
    "modality", "sufficient", "refines", P))
  local ids = gap_ids()
  check(ids[P] == nil, "the gap did not close")
  check(ids[R] == nil, "the refinement itself must be complete")
end

-- ---------------------------------------------------------------------
-- V39 - V107: the 2.0.0 additions
-- ---------------------------------------------------------------------

local function neuro()
  local labels = { [4] = "macromolecular", [5] = "subcellular", [6] = "cellular",
                   [7] = "synaptic", [9] = "region", [14] = "community_and_society" }
  local s = {}
  for o, label in pairs(labels) do s[o] = stratum(label, "neuroendocrine", o) end
  return s
end

V[39] = function()
  local st = stratum("cellular", "neuroendocrine", 6, "cell", A({ "cell_biology" }))
  local ok, why = validate_schema(st); check(ok, reasons_str(why))
end

V[40] = function()
  local bad = mk(O("type", "stratum", "label", "cellular", "ordinal", 6))
  local ok, why = validate_schema(bad, "stratum")
  check(not ok and any_mention(why, "scheme"), reasons_str(why))
end

V[41] = function()
  local a = stratum("cellular", "neuroendocrine", 6)
  local b = stratum("neuronal", "neuroendocrine", 6)
  for _, x in ipairs({ a, b }) do
    local ok, why = validate_schema(x); check(ok, reasons_str(why))
  end
  check(a["id"] ~= b["id"], "distinct labels distinct ids")
end

V[42] = function()
  local s = neuro()
  local s4p = stratum("molecular", "physics", 4)
  local c = occ("chronic_social_subordination", s[14]["id"])
  local e = occ("gene_expression", s4p["id"])
  local smap = { [s[14]["id"]] = s[14], [s4p["id"]] = s4p }
  local omap = { [c["id"]] = c, [e["id"]] = e }
  local P = cro(A({ c["id"] }), A({ e["id"] }))
  check(semantics.classify_cro(P, omap, smap) == "scheme_mismatch", "scheme_mismatch")
end

V[43] = function()
  for _, x in ipairs({ stratum("macromolecular", "neuroendocrine", 4),
                       stratum("region", "neuroendocrine", 9) }) do
    local ok, why = validate_schema(x); check(ok, reasons_str(why))
  end
end

V[44] = function()
  local st = stratum("cellular", "neuroendocrine", 6)
  local o = occ("neuron_fires", st["id"])
  local ok, why = validate_schema(o); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(o); check(ok2, reasons_str(why2))
end

V[45] = function()
  local o = occ("press_button")
  local ok, why = validate_schema(o); check(ok, reasons_str(why))
  local e = occ("light_on")
  local P = cro(A({ o["id"] }), A({ e["id"] }))
  check(semantics.classify_cro(P, { [o["id"]] = o, [e["id"]] = e }, {}) == "unclassifiable", "unclassifiable")
end

V[46] = function()
  local s = neuro()
  local a = occ("depolarization", s[5]["id"])
  local b = occ("depolarization", s[6]["id"])
  check(a["id"] ~= b["id"], "stratum is identity-bearing")
end

local function bridge_fixture(relation)
  local s = neuro()
  local coarse = occ("action_potential_fires", s[6]["id"])
  local fine = { occ("sodium_channels_open", s[4]["id"]), occ("sodium_influx", s[4]["id"]) }
  local fine_ids = A({})
  for _, f in ipairs(fine) do fine_ids[#fine_ids + 1] = f["id"] end
  local b = bridge(coarse["id"], fine_ids, relation)
  local omap = { [coarse["id"]] = coarse }
  for _, f in ipairs(fine) do omap[f["id"]] = f end
  local smap = { [s[4]["id"]] = s[4], [s[6]["id"]] = s[6] }
  return b, omap, smap
end

local function valid_bridge(relation)
  local b, omap, smap = bridge_fixture(relation)
  local ok, why = validate_schema(b); check(ok, reasons_str(why))
  local ok2, why2 = semantics.bridge_wellformed(b, omap, smap); check(ok2, why2)
end

V[47] = function() valid_bridge("constitutes") end
V[48] = function() valid_bridge("aggregates") end
V[49] = function() valid_bridge("realizes") end
V[50] = function() valid_bridge("supervenes_on") end

V[51] = function()
  local s = neuro()
  local coarse = occ("x_coarse", s[4]["id"])
  local fine = occ("x_fine", s[6]["id"])
  local b = bridge(coarse["id"], A({ fine["id"] }), "constitutes")
  local omap = { [coarse["id"]] = coarse, [fine["id"]] = fine }
  local smap = { [s[4]["id"]] = s[4], [s[6]["id"]] = s[6] }
  local ok = semantics.bridge_wellformed(b, omap, smap); check(not ok, "coarse must be coarser")
end

V[52] = function()
  local s = neuro()
  local coarse = occ("c", s[6]["id"])
  local f1 = occ("f1", s[4]["id"]); local f2 = occ("f2", s[5]["id"])
  local b = bridge(coarse["id"], A({ f1["id"], f2["id"] }), "constitutes")
  local omap = { [coarse["id"]] = coarse, [f1["id"]] = f1, [f2["id"]] = f2 }
  local smap = { [s[4]["id"]] = s[4], [s[5]["id"]] = s[5], [s[6]["id"]] = s[6] }
  local ok = semantics.bridge_wellformed(b, omap, smap); check(not ok, "fine span one stratum")
end

V[53] = function()
  local x, y = sym("occurrent:x"), sym("occurrent:y")
  local b1 = bridge(x, A({ y }), "constitutes")
  local b2 = bridge(y, A({ x }), "constitutes")
  local edges = {}
  for _, b in ipairs({ b1, b2 }) do
    for _, f in ipairs(b["fine"]) do
      edges[f] = edges[f] or {}
      edges[f][#edges[f] + 1] = b["coarse"]
    end
  end
  check(semantics.has_cycle(edges) == true, "bridge cycle")
end

V[54] = function()
  local a = stratum("cellular", "neuroendocrine", 6)
  local b = stratum("molecular", "physics", 4)
  local coarse = occ("c", a["id"]); local fine = occ("f", b["id"])
  local br = bridge(coarse["id"], A({ fine["id"] }), "constitutes")
  local omap = { [coarse["id"]] = coarse, [fine["id"]] = fine }
  local smap = { [a["id"]] = a, [b["id"]] = b }
  local ok = semantics.bridge_wellformed(br, omap, smap); check(not ok, "scheme must match")
end

V[55] = function()
  local s = neuro()
  local coarse = occ("decision_made", s[6]["id"])
  local f1 = occ("cascade_a", s[4]["id"]); local f2 = occ("cascade_b", s[4]["id"])
  local b1 = bridge(coarse["id"], A({ f1["id"] }), "realizes")
  local b2 = bridge(coarse["id"], A({ f2["id"] }), "realizes")
  check(b1["id"] ~= b2["id"], "distinct bridges")
  for _, b in ipairs({ b1, b2 }) do
    local ok, why = validate_schema(b); check(ok, reasons_str(why))
  end
end

local function reach_fixture()
  local s = neuro()
  local ap = occ("action_potential_fires", s[6]["id"])
  local nt = occ("neurotransmitter_released", s[6]["id"])
  local fa = occ("calcium_enters", s[4]["id"])
  local fb = occ("vesicle_fuses", s[4]["id"])
  local m1 = cro(A({ fa["id"] }), A({ fb["id"] }))
  local P = cro(A({ ap["id"] }), A({ nt["id"] }), { mechanism = A({ m1["id"] }) })
  local bridges = { bridge(ap["id"], A({ fa["id"] }), "constitutes"),
                    bridge(nt["id"], A({ fb["id"] }), "constitutes") }
  return P, { [m1["id"]] = m1 }, bridges
end

V[56] = function()
  local P, members, bridges = reach_fixture()
  check(semantics.hierarchy_consistent(P, members, bridges) == "consistent", "bridged consistent")
end

V[57] = function()
  local P, members = reach_fixture()
  check(semantics.hierarchy_consistent(P, members, {}) == "inconsistent", "literal inconsistent")
end

V[58] = function()
  local P, members, bridges = reach_fixture()
  local literal = semantics.hierarchy_consistent(P, members, {})
  local bridged = semantics.hierarchy_consistent(P, members, bridges)
  check(literal ~= "consistent" and bridged == "consistent", "bridged reachability")
end

local function classify(cause_ord, effect_ord)
  local s = neuro()
  local c = occ("c", s[cause_ord]["id"]); local e = occ("e", s[effect_ord]["id"])
  local smap = { [s[cause_ord]["id"]] = s[cause_ord], [s[effect_ord]["id"]] = s[effect_ord] }
  local omap = { [c["id"]] = c, [e["id"]] = e }
  return semantics.classify_cro(cro(A({ c["id"] }), A({ e["id"] })), omap, smap)
end

V[59] = function() check(classify(6, 6) == "intra_stratal", "intra") end
V[60] = function() check(classify(6, 5) == "adjacent_stratal", "adjacent") end
V[61] = function() check(classify(14, 4) == "skipping", "skipping") end

local function skip_fixture(cause_ord, effect_ord, opts)
  local s = neuro()
  local c = occ("c", s[cause_ord]["id"]); local e = occ("e", s[effect_ord]["id"])
  local smap = { [s[cause_ord]["id"]] = s[cause_ord], [s[effect_ord]["id"]] = s[effect_ord] }
  local omap = { [c["id"]] = c, [e["id"]] = e }
  local P = cro(A({ c["id"] }), A({ e["id"] }), opts)
  return P, semantics.classify_cro(P, omap, smap)
end

local function eq_list(a, b)
  if #a ~= #b then return false end
  for i = 1, #a do if a[i] ~= b[i] then return false end end
  return true
end

V[62] = function()
  local P, cls = skip_fixture(14, 4)
  check(eq_list(semantics.skip_gaps(P, cls), { "incomplete_mechanism" }), "gaps")
end

V[63] = function()
  local P, cls = skip_fixture(14, 4, { skips = true })
  check(eq_list(semantics.skip_gaps(P, cls), {}), "no gaps")
end

V[64] = function()
  local P, cls = skip_fixture(14, 4, { skips = true, mechanism = A({ sym("causal_relation_object:m") }) })
  check(eq_list(semantics.skip_gaps(P, cls), { "contradictory_skip" }), "gaps")
  local ok, why = validate_semantics(P)
  check(not ok and any_mention(why, "contradictory_skip"), reasons_str(why))
end

V[65] = function()
  local P, cls = skip_fixture(6, 6, { skips = true })
  check(eq_list(semantics.skip_gaps(P, cls), { "vacuous_skip" }), "gaps")
end

V[66] = function()
  local s = neuro()
  local c = occ("c", s[14]["id"]); local e = occ("e", s[4]["id"])
  local absent = cro(A({ c["id"] }), A({ e["id"] }))
  local false_ = cro(A({ c["id"] }), A({ e["id"] }), { skips = false })
  check(absent["id"] ~= false_["id"], "skips:false differs from absent")
end

V[67] = function()
  local s = neuro()
  local c1 = occ("c1", s[4]["id"]); local c2 = occ("c2", s[6]["id"])
  local e = occ("e", s[6]["id"])
  local P = cro(A({ c1["id"], c2["id"] }), A({ e["id"] }))
  check(semantics.endpoints_mixed(P, { [c1["id"]] = c1, [c2["id"]] = c2, [e["id"]] = e }) == true, "mixed")
end

V[68] = function()
  local P = cro(A({ sym("occurrent:a") }), A({ sym("occurrent:b") }), { modality = "enabling" })
  local ok, why = validate_schema(P); check(ok, reasons_str(why))
end

V[69] = function()
  local a = O("causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }), "modality", "enabling")
  local b = O("causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }), "modality", "sufficient")
  check(semantics.conflicts(a, b) == false, "enabling compatible with sufficient")
end

V[70] = function()
  local a = O("causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }), "modality", "enabling")
  local b = O("causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }), "modality", "preventive")
  check(semantics.conflicts(a, b) == true, "enabling conflicts preventive")
end

V[71] = function()
  local b = cnt("hippocampus")
  local p = port(b["id"], "perforant_path", "in", A({ sym("occurrent:signal") }))
  local ok, why = validate_schema(p); check(ok, reasons_str(why))
end

V[72] = function()
  local b = cnt("hippocampus")["id"]
  local x = sym("occurrent:signal")
  check(port(b, "perforant_path", "in", A({ x }))["id"]
        ~= port(b, "fornix", "in", A({ x }))["id"], "label is identity-bearing")
end

local function conduit_fixture(opts)
  opts = opts or {}
  local x = sym("occurrent:motor_command"); local y = sym("occurrent:error_signal")
  local z = sym("occurrent:unrelated")
  local m1 = cnt("motor_cortex")["id"]; local m2 = cnt("spinal_neuron")["id"]
  local frm = port(m1, "out_port", opts.in_from and "in" or "out", A({ x }))
  local to = port(m2, "in_port", "in", opts.transform and A({ y }) or A({ x }))
  local carries = opts.bad_carry and A({ z }) or A({ x })
  local xform, cro_map = nil, {}
  if opts.transform then
    local law = cro(A({ x }), A({ y })); cro_map[law["id"]] = law
    xform = law["id"]
  end
  local c = conduit(frm["id"], to["id"], carries, "conn", xform)
  return c, { [frm["id"]] = frm, [to["id"]] = to }, cro_map
end

V[73] = function()
  local c, pmap = conduit_fixture()
  local ok, why = validate_schema(c); check(ok, reasons_str(why))
  local ok2, why2 = semantics.conduit_wellformed(c, pmap); check(ok2, why2)
end

V[74] = function()
  local c, pmap, cmap = conduit_fixture({ transform = true })
  local ok, why = validate_schema(c); check(ok, reasons_str(why))
  local ok2, why2 = semantics.conduit_wellformed(c, pmap, cmap); check(ok2, why2)
end

V[75] = function()
  local c, pmap = conduit_fixture({ bad_carry = true })
  local ok = semantics.conduit_wellformed(c, pmap); check(not ok, "carries not accepted")
end

V[76] = function()
  local c, pmap = conduit_fixture({ in_from = true })
  local ok = semantics.conduit_wellformed(c, pmap); check(not ok, "from must be out")
end

V[77] = function()
  local c, pmap, cmap = conduit_fixture({ transform = true })
  local ok, why = semantics.conduit_wellformed(c, pmap, cmap); check(ok, why)
  local law
  for _, v in pairs(cmap) do law = v end
  local carried = false
  for _, o in ipairs(c["carries"]) do if o == law["effects"][1] then carried = true end end
  check(not carried, "transform effect not carried directly")
end

V[78] = function()
  local b = cnt("hippocampus")["id"]
  check(rlz(b, "disposition", "long_term_potentiation")["id"]
        ~= rlz(b, "disposition", "pattern_separation")["id"], "label distinguishes")
end

V[79] = function()
  local b = cnt("hippocampus")["id"]
  local u1 = rlz(b, "disposition"); local u2 = rlz(b, "disposition")
  local ok, why = validate_schema(u1); check(ok, reasons_str(why))
  check(u1["id"] == u2["id"], "unlabelled realizables coincide")
  check(rlz(b, "disposition", "some_function")["id"] ~= u1["id"], "label breaks the tie")
end

V[80] = function()
  local parent = occ("fires"); local child = occ("fires_action_potential")
  local e = O("type", "enrichment", "about", child["id"],
              "field", "occurrent_subsumes", "entry", parent["id"])
  local ok, why = validate_semantics(e); check(ok, reasons_str(why))
end

V[81] = function()
  local a, b = sym("occurrent:a"), sym("occurrent:b")
  check(semantics.has_cycle({ [a] = { b }, [b] = { a } }) == true, "cycle")
end

V[82] = function()
  local whole = occ("eat"); local part = occ("chew")
  local e = O("type", "enrichment", "about", part["id"],
              "field", "occurrent_part_of", "entry", whole["id"])
  local ok, why = validate_semantics(e); check(ok, reasons_str(why))
end

V[83] = function()
  local spec = semantics.ENRICHMENT_FIELDS["occurrent_part_of"]
  check(spec.shape == "occurrent" and spec.kinds.occurrent == true and count(spec.kinds) == 1,
        "occurrent_part_of shape")
  local s = store.new()
  s:put(occ("eat")); s:put(occ("chew"))
  for _, oid in ipairs(s.object_order) do
    check(s.objects[oid]["type"] ~= "causal_relation_object", "no cro created")
  end
end

V[84] = function()
  local s = neuro()
  local a = occ("run", s[9]["id"]); local b = occ("sprint", s[6]["id"])
  check(a["stratum"] ~= b["stratum"], "distinct strata")
end

V[85] = function()
  local c = cnt("human_patient")
  local ti = individual(c["id"], "salted_hash_abc123")
  local ok, why = validate_schema(ti); check(ok, reasons_str(why))
end

V[86] = function()
  local bad = mk(O("type", "token_individual", "designator", "x"))
  local ok, why = validate_schema(bad, "token_individual")
  check(not ok and any_mention(why, "instantiates"), reasons_str(why))
end

V[87] = function()
  local c = cnt("human_patient")["id"]
  check(individual(c, "hash_a")["id"] ~= individual(c, "hash_b")["id"], "designator distinguishes")
end

V[88] = function()
  local o = occ("bilateral_hippocampal_resection")
  local t = token(o["id"], O("start", "1953-08-25T00:00:00Z", "end", "1953-08-25T00:00:00Z"))
  local ok, why = validate_schema(t); check(ok, reasons_str(why))
end

V[89] = function()
  local o = occ("amnesia_onset")["id"]
  local bounded = token(o, O("start", "1953-08-25T00:00:00Z", "end", "1953-08-26T00:00:00Z"))
  local instantaneous = token(o, O("start", "1953-08-25T00:00:00Z"))
  local ongoing = token(o, O("start", "1953-08-25T00:00:00Z", "open", true))
  local ids = { [bounded["id"]] = true, [instantaneous["id"]] = true, [ongoing["id"]] = true }
  check(count(ids) == 3, "three distinct intervals")
end

V[90] = function()
  local o = occ("resection")["id"]; local c = cnt("human_patient")["id"]
  local patient = individual(c, "p")["id"]
  local surgeon = individual(c, "s")["id"]
  local t = token(o, O("start", "1953-08-25T00:00:00Z"),
    A({ O("role", "patient", "filler", patient), O("role", "agent", "filler", surgeon) }))
  local ok, why = validate_schema(t); check(ok, reasons_str(why))
end

V[91] = function()
  local q = quality("cortisol_concentration", "quantity", "ug/dL")
  local ok, why = validate_schema(q); check(ok, reasons_str(why))
end

local function state_fixture(datatype, value, unit)
  local q = quality("cortisol_concentration", datatype, unit)
  local c = cnt("human_patient")["id"]
  local subj = individual(c, "p")["id"]
  local st = state(subj, q["id"], value,
    O("start", "2026-01-01T00:00:00Z", "end", "2026-01-01T01:00:00Z"))
  return st, q
end

V[92] = function()
  local st, q = state_fixture("quantity", O("quantity", 15.0, "unit", "ug/dL"), "ug/dL")
  local ok, why = validate_schema(st); check(ok, reasons_str(why))
  check(eq_list(semantics.state_gaps(st, q), {}), "no gaps")
end

V[93] = function()
  local st, q = state_fixture("categorical", O("categorical", "elevated"))
  local ok, why = validate_schema(st); check(ok, reasons_str(why))
  check(eq_list(semantics.state_gaps(st, q), {}), "no gaps")
end

V[94] = function()
  local st, q = state_fixture("boolean", O("boolean", true))
  local ok, why = validate_schema(st); check(ok, reasons_str(why))
  check(eq_list(semantics.state_gaps(st, q), {}), "no gaps")
end

V[95] = function()
  local st, q = state_fixture("quantity", O("categorical", "elevated"), "ug/dL")
  check(eq_list(semantics.state_gaps(st, q), { "value_type_mismatch" }), "gaps")
end

V[96] = function()
  local st, q = state_fixture("quantity", O("quantity", 15.0, "unit", "mg/dL"), "ug/dL")
  check(eq_list(semantics.state_gaps(st, q), { "unit_mismatch" }), "gaps")
end

local function law_and_tokens()
  local o_cause = occ("resection"); local o_effect = occ("amnesia_onset")
  local law = cro(A({ o_cause["id"] }), A({ o_effect["id"] }),
    { temporal = O("minimum_delay", 0, "maximum_delay", 1, "unit", "days"),
      modality = "sufficient" })
  local t_cause = token(o_cause["id"], O("start", "1953-08-25T00:00:00Z"))
  local t_effect = token(o_effect["id"], O("start", "1953-08-25T00:00:00Z", "open", true))
  return law, o_cause, o_effect, t_cause, t_effect
end

V[97] = function()
  local law, _, _, tc, te = law_and_tokens()
  local claim = tcc(A({ tc["id"] }), A({ te["id"] }),
    { covering_law = law["id"], actual_delay = O("duration", 0, "unit", "instant"),
      counterfactual = true })
  local ok, why = validate_schema(claim); check(ok, reasons_str(why))
end

V[98] = function()
  local _, _, _, tc, te = law_and_tokens()
  local claim = tcc(A({ tc["id"] }), A({ te["id"] }))
  local ok, why = validate_schema(claim); check(ok, reasons_str(why))
  check(claim["covering_law"] == nil, "covering_law optional")
end

V[99] = function()
  local law = law_and_tokens()
  check(semantics.delay_within_window(O("duration", 0, "unit", "instant"), law["temporal"]) == true, "within")
end

V[100] = function()
  local temporal = O("minimum_delay", 0, "maximum_delay", 1, "unit", "hours")
  check(semantics.delay_within_window(O("duration", 5, "unit", "days"), temporal) == false, "outside")
end

V[101] = function()
  local o = occ("x")["id"]
  local cause = token(o, O("start", "2026-01-02T00:00:00Z"))
  local effect = token(o, O("start", "2026-01-01T00:00:00Z"))
  local claim = tcc(A({ cause["id"] }), A({ effect["id"] }))
  check(semantics.retrocausal(claim, { [cause["id"]] = cause, [effect["id"]] = effect }) == true, "retrocausal")
end

V[102] = function()
  local other = cro(A({ sym("occurrent:foo") }), A({ sym("occurrent:bar") }))
  local _, _, _, tc, te = law_and_tokens()
  local claim = tcc(A({ tc["id"] }), A({ te["id"] }), { covering_law = other["id"] })
  check(semantics.covering_law_mismatch(claim, { [tc["id"]] = tc, [te["id"]] = te }, other) == true, "mismatch")
end

V[103] = function()
  local a = signed("assertion",
    O("about", sym("token_occurrence:t"), "evidence_type", "observation", "confidence", 0.9), "signer")
  local ok, why = validate_schema(a); check(ok, reasons_str(why))
end

V[104] = function()
  local ev = A({ sym("token_occurrence:t1"), sym("token_causal_claim:c1") })
  local base = O("type", "assertion", "about", sym("causal_relation_object:law"),
    "source", select(2, key("signer")), "evidence_type", "intervention",
    "strength", 0.95, "confidence", 0.99, "timestamp", "2026-07-14T00:00:00Z")
  local a = json.copy_object(base)
  json.set(a, "evidenced_by", ev)
  local a_id = json.copy_object(a)
  json.set(a_id, "id", identify(a))
  local ok, why = validate_schema(a_id); check(ok, reasons_str(why))
  check(identify(a) ~= identify(base), "evidenced_by is identity-bearing")
end

V[105] = function()
  local a = signed("assertion",
    O("about", sym("causal_relation_object:law"), "evidence_type", "simulation", "confidence", 0.5), "signer")
  local ok, why = validate_schema(a); check(ok, reasons_str(why))
  local rank = { intervention = 0, observation = 1, simulation = 2 }
  check(rank.intervention < rank.observation and rank.observation < rank.simulation, "ordering")
end

V[106] = function()
  local function scan(node, ids)
    if type(node) == "string" then
      local scheme, hex = node:match("^([a-z0-9_]+):([0-9a-f]+)$")
      if scheme and #hex == 64 then ids[#ids + 1] = scheme end
    elseif json.is_array(node) then
      for _, x in ipairs(node) do scan(x, ids) end
    elseif json.is_object(node) then
      for _, k in ipairs(json.keys(node)) do scan(node[k], ids) end
    end
  end
  for n = 1, 38 do
    local ids = {}
    scan(vec(n), ids)
    for _, scheme in ipairs(ids) do
      check(WHOLE_WORD[scheme], "V106: abbreviated scheme " .. scheme .. " in vector " .. n)
    end
  end
  local rec = O("type", "occurrent", "label", "press_button", "category", "action")
  check(identify(rec) == identify(rec), "deterministic")
  check(identify(rec):match("^([^:]+):") == "occurrent", "whole-word scheme")
end

V[107] = function()
  local hexid = string.rep("0", 64)
  -- the abbreviated prefix here is intentional (the negative test) and must
  -- NOT be re-minted; assemble it letter by letter to survive re-mint tools.
  local cro_abbr = "c" .. "r" .. "o"
  local abbreviated = O("type", "causal_relation_object", "id", cro_abbr .. ":" .. hexid,
    "causes", A({ "occurrent:" .. hexid }), "effects", A({ "occurrent:" .. hexid }))
  local ok = validate_schema(abbreviated, "causal_relation_object")
  check(not ok, "abbreviated scheme must be rejected")
  local abbr_str = O("type", "stratum", "id", "str:" .. hexid, "label", "cellular",
    "scheme", "neuroendocrine", "ordinal", 6)
  local ok2 = validate_schema(abbr_str, "stratum"); check(not ok2, "str: must be rejected")
  local whole = O("type", "causal_relation_object", "id", "causal_relation_object:" .. hexid,
    "causes", A({ "occurrent:" .. hexid }), "effects", A({ "occurrent:" .. hexid }))
  local ok3, why3 = validate_schema(whole, "causal_relation_object"); check(ok3, reasons_str(why3))
end

-- ---------------------------------------------------------------------
-- V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam, realized_by)
-- ---------------------------------------------------------------------

-- a cross_stratal_seam content object, completed with its content-addressed id
local function seam(source, target, mechanism_status, chain)
  local o = O("type", "cross_stratal_seam", "source", source, "target", target,
              "mechanism_status", mechanism_status)
  if chain ~= nil and #chain > 0 then json.set(o, "chain", A(chain)) end
  return mk(o)
end

-- build a seam over the neuro fixture: (seam, occ_map, stratum_map).
local function seam_fixture(src_ord, tgt_ord, mechanism_status, chain_ords)
  local s = neuro()
  local src = occ("source_event", s[src_ord]["id"])
  local tgt = occ("target_event", s[tgt_ord]["id"])
  local omap = { [src["id"]] = src, [tgt["id"]] = tgt }
  local smap = { [s[src_ord]["id"]] = s[src_ord], [s[tgt_ord]["id"]] = s[tgt_ord] }
  local chain = nil
  if chain_ords ~= nil then
    chain = {}
    for i, ord in ipairs(chain_ords) do
      local c = occ("chain_" .. (i - 1), s[ord]["id"])
      omap[c["id"]] = c
      smap[s[ord]["id"]] = s[ord]
      chain[#chain + 1] = c["id"]
    end
  end
  return seam(src["id"], tgt["id"], mechanism_status, chain), omap, smap
end

-- a conduit with an optional realized_by reference, completed with its id
local function conduit_realized(realized_by)
  local o = O("type", "conduit", "label", "conn",
              "from", "port:" .. string.rep("1", 64),
              "to", "port:" .. string.rep("2", 64),
              "carries", A({ "occurrent:" .. string.rep("3", 64) }))
  if realized_by ~= nil then json.set(o, "realized_by", realized_by) end
  return mk(o)
end

-- -- Change One: the ordinal (tick) temporal unit --
V[108] = function()
  local P = cro(A({ sym("occurrent:a") }), A({ sym("occurrent:b") }),
    { temporal = O("minimum_delay", 0, "maximum_delay", 5, "unit", "ticks"),
      modality = "sufficient" })
  local ok, why = validate_schema(P); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(P); check(ok2, reasons_str(why2))
end

V[109] = function()
  local P = cro(A({ sym("occurrent:a") }), A({ sym("occurrent:b") }),
    { temporal = O("minimum_delay", 2, "maximum_delay", 5, "unit", "ticks") })
  check(semantics.admissible(P, 3) == true, "3 ticks inside [2, 5]")
  check(semantics.admissible(P, 2) == true and semantics.admissible(P, 5) == true,
        "endpoints are admissible")
  check(semantics.admissible(P, 6) == false and semantics.admissible(P, 1) == false,
        "outside the tick window is not admissible")
end

V[110] = function()
  local tick_window = O("minimum_delay", 0, "maximum_delay", 5, "unit", "ticks")
  local wall_window = O("minimum_delay", 0, "maximum_delay", 5, "unit", "seconds")
  check(semantics.delay_within_window(O("duration", 3, "unit", "ticks"), tick_window) == true,
        "3 ticks within the tick window")
  check(semantics.delay_within_window(O("duration", 1, "unit", "ticks"), wall_window) == false,
        "a tick delay is not within a wall-clock window")
  check(semantics.delay_within_window(O("duration", 1, "unit", "seconds"), tick_window) == false,
        "a seconds delay is not within a tick window")
  local a = O("causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }),
              "temporal", tick_window, "modality", "sufficient")
  local b = O("causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }),
              "temporal", wall_window, "modality", "preventive")
  check(semantics.conflicts(a, b) == false, "disjoint dimensions do not overlap")
  local accepted = pcall(function() semantics.to_seconds(1, "ticks") end)
  check(not accepted, "to_seconds must refuse an ordinal unit")
end

V[111] = function()
  local function base_cro(temporal)
    local o = O("type", "causal_relation_object",
                "causes", A({ sym("occurrent:a") }),
                "effects", A({ sym("occurrent:b") }),
                "modality", "sufficient")
    json.set(o, "temporal", temporal)
    return o
  end
  local tick = base_cro(O("minimum_delay", 0, "maximum_delay", 1, "unit", "ticks"))
  local secs = base_cro(O("minimum_delay", 0, "maximum_delay", 1, "unit", "seconds"))
  check(identify(tick) ~= identify(secs), "the unit is identity-bearing")
  -- a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
  check(identify(secs) == "causal_relation_object:"
    .. "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
    "the wall-clock CRO identity is pinned")
end

-- -- Change Two: the managed cross-stratal seam (eighteenth kind) --
V[112] = function()
  local sm, omap, smap = seam_fixture(14, 4, "unmodeled")
  local ok, why = validate_schema(sm); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(sm); check(ok2, reasons_str(why2))
  local ok3, why3 = semantics.seam_wellformed(sm, omap, smap); check(ok3, why3)
end

V[113] = function()
  local a = seam_fixture(14, 4, "unmodeled")
  local b, omap, smap = seam_fixture(14, 4, "absent")
  local ok, why = validate_schema(b); check(ok, reasons_str(why))
  local ok2, why2 = semantics.seam_wellformed(b, omap, smap); check(ok2, why2)
  check(a["id"] ~= b["id"], "mechanism_status is identity-bearing")
end

V[114] = function()
  local drawn, omap, smap = seam_fixture(14, 4, "unmodeled", { 9, 7, 6, 5 })
  local ok, why = validate_schema(drawn); check(ok, reasons_str(why))
  local ok2, why2 = semantics.seam_wellformed(drawn, omap, smap); check(ok2, why2)
  local bad, omap2, smap2 = seam_fixture(14, 4, "absent", { 9, 7, 6, 5 })
  local ok3, why3 = validate_semantics(bad)
  check(not ok3 and any_mention(why3, "contradictory_seam"),
        "contradictory_seam: " .. reasons_str(why3))
  local ok4 = semantics.seam_wellformed(bad, omap2, smap2)
  check(not ok4, "a drawn chain with absent status is malformed")
end

V[115] = function()
  local sm, omap, smap = seam_fixture(14, 4, "unmodeled")
  local s = neuro()
  check(semantics.seam_home(sm, omap, smap) == s[14]["id"],
        "the home is the coarsest (max ordinal) stratum")
end

V[116] = function()
  local adj, o1, s1 = seam_fixture(6, 5, "unmodeled")   -- adjacent (gap 1)
  local ok1 = semantics.seam_wellformed(adj, o1, s1)
  check(not ok1, "an adjacent seam is malformed")
  local co, o2, s2 = seam_fixture(6, 6, "unmodeled")    -- co-stratal (gap 0)
  local ok2 = semantics.seam_wellformed(co, o2, s2)
  check(not ok2, "a co-stratal seam is malformed")
  local sm = seam_fixture(14, 4, "unmodeled")
  check(sm["id"]:sub(1, #"cross_stratal_seam:") == "cross_stratal_seam:",
        "a new identity scheme")
end

-- -- Change Three: the realized_by reference --
V[117] = function()
  local c = conduit_realized("causal_relation_object:" .. string.rep("a", 64))
  local ok, why = validate_schema(c); check(ok, reasons_str(why))
  local c2 = conduit_realized("native:region_stratum_predict")
  local ok2, why2 = validate_schema(c2); check(ok2, reasons_str(why2))  -- native scheme is legal
end

V[118] = function()
  local bound = conduit_realized("native:region_stratum_predict")
  local unbound = conduit_realized()
  check(bound["id"] ~= unbound["id"], "realized_by is identity-bearing")
  -- an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
  check(unbound["id"] == "conduit:"
    .. "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
    "the unbound conduit identity is pinned")
end

V[119] = function()
  local unbound = conduit_realized()
  local ok, why = validate_schema(unbound); check(ok, reasons_str(why))  -- unbound is legal
  local bad = json.copy_object(unbound)
  json.set(bad, "realized_by", "not-a-scheme-qualified-reference")
  local ok2 = validate_schema(bad, "conduit")
  check(not ok2, "a malformed realized_by reference is rejected")
end

-- ---------------------------------------------------------------------
-- V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
-- prediction_error)
-- ---------------------------------------------------------------------
local function attitude(holder, attitude_type, content)
  return mk(O("type", "attitude", "holder", holder,
              "attitude_type", attitude_type, "content", content))
end

local function predicted(instantiates, interval, predictor, strength)
  local o = O("type", "predicted_occurrence", "instantiates", instantiates,
              "interval", interval, "predictor", predictor)
  if strength ~= nil then json.set(o, "strength", strength) end
  return mk(o)
end

local function prediction_error(predicted_id, discrepancy, observed)
  local o = O("type", "prediction_error", "predicted", predicted_id,
              "discrepancy", discrepancy)
  if observed ~= nil then json.set(o, "observed", observed) end
  return mk(o)
end

-- an interval carrying the ordinal (tick) dimension
local function tick_interval(start_tick, end_tick)
  local o = O("start_tick", start_tick)
  if end_tick ~= nil then json.set(o, "end_tick", end_tick) end
  return o
end

-- a modeled predicting agent (a token individual), by identity
local function predictor_id()
  return individual(cnt("forecasting_mind")["id"], "predictor_p")["id"]
end

-- a modeled believing agent (a token individual), by identity
local function believer_id(designator)
  return individual(cnt("believing_mind")["id"], designator or "holder_h")["id"]
end

-- -- Group X: prediction and prediction error (Section A) --
V[120] = function()
  local o = occ("rainfall_begins")
  local p = predicted(o["id"], tick_interval(3, 8), predictor_id())
  local ok, why = validate_schema(p); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(p); check(ok2, reasons_str(why2))
  check(p["id"]:sub(1, #"predicted_occurrence:") == "predicted_occurrence:",
        "a new identity scheme")
  local report = identify(O("type", "token_occurrence", "instantiates", o["id"],
    "interval", tick_interval(3, 8)), "token_occurrence")
  check(p["id"] ~= report, "a forecast is not a report")
  check(report:sub(1, #"token_occurrence:") == "token_occurrence:",
        "the report is a token_occurrence")
end

V[121] = function()
  local o = occ("rainfall_begins")
  local wall = O("start", "2026-07-23T00:00:00Z", "end", "2026-07-24T00:00:00Z")
  local who = predictor_id()
  local with_strength = predicted(o["id"], wall, who, 0.8)
  local without = predicted(o["id"], wall, who)
  for _, p in ipairs({ with_strength, without }) do
    local ok, why = validate_schema(p); check(ok, reasons_str(why))
    local ok2, why2 = validate_semantics(p); check(ok2, reasons_str(why2))
  end
  check(with_strength["id"] ~= without["id"], "strength is identity-bearing")
end

V[122] = function()
  local o = occ("rainfall_begins")
  local bad = mk(O("type", "predicted_occurrence", "instantiates", o["id"],
    "interval", tick_interval(3)))
  local ok, why = validate_schema(bad, "predicted_occurrence")
  check(not ok and any_mention(why, "predictor"),
        "predictor is required: " .. reasons_str(why))
end

V[123] = function()
  local o = occ("rainfall_begins")
  local both = predicted(o["id"],
    O("start", "2026-07-23T00:00:00Z", "start_tick", 3), predictor_id())
  local ok, why = validate_schema(both); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(both)
  check(not ok2 and any_mention(why2, "dimension_conflict"),
        "dimension_conflict: " .. reasons_str(why2))
end

V[124] = function()
  local o = occ("rainfall_begins")
  local p = predicted(o["id"], O("start", "2026-07-23T00:00:00Z"), predictor_id())
  local t = token(o["id"], O("start", "2026-07-23T06:00:00Z"))
  local err = prediction_error(p["id"], 0.0, t["id"])
  local ok, why = validate_schema(err); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(err); check(ok2, reasons_str(why2))
  check(semantics.prediction_pairing_mismatch(err, p, t) == false, "no pairing mismatch")
end

V[125] = function()
  local o = occ("rainfall_begins")
  local p = predicted(o["id"], O("start", "2026-07-23T00:00:00Z"), predictor_id())
  local err = prediction_error(p["id"], -1.0)
  local ok, why = validate_schema(err); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(err); check(ok2, reasons_str(why2))
  check(err["observed"] == nil, "observed is absent")
  check(semantics.prediction_pairing_mismatch(err, p, nil) == false,
        "an absent observed is never a mismatch")
end

V[126] = function()
  local o = occ("rainfall_begins")
  local p = predicted(o["id"], tick_interval(0), predictor_id())
  local bad = mk(O("type", "prediction_error", "predicted", p["id"]))
  local ok, why = validate_schema(bad, "prediction_error")
  check(not ok and any_mention(why, "discrepancy"),
        "discrepancy is required: " .. reasons_str(why))
end

V[127] = function()
  local o = occ("rainfall_begins")
  local other = occ("snowfall_begins")
  local p = predicted(o["id"], O("start", "2026-07-23T00:00:00Z"), predictor_id())
  local t = token(other["id"], O("start", "2026-07-23T06:00:00Z"))
  local err = prediction_error(p["id"], 1.0, t["id"])
  local ok, why = validate_schema(err); check(ok, reasons_str(why))
  check(semantics.prediction_pairing_mismatch(err, p, t) == true, "pairing mismatch")
end

-- -- Group Y: attitude and theory of mind (Section B) --
V[128] = function()
  local st = state_fixture("quantity", O("quantity", 15.0, "unit", "ug/dL"), "ug/dL")
  local att = attitude(believer_id(), "believes", st["id"])
  local ok, why = validate_schema(att); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(att); check(ok2, reasons_str(why2))
end

V[129] = function()
  local a = occ("switch_pressed")
  local b = occ("light_on")
  local actual = cro(A({ a["id"] }), A({ b["id"] }), { modality = "sufficient" })
  local believed = cro(A({ a["id"] }), A({ b["id"] }), { modality = "preventive" })
  check(semantics.conflicts(believed, actual) == true, "the claims contradict")
  local att = attitude(believer_id(), "believes", believed["id"])
  local ok, why = validate_schema(att); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(att); check(ok2, reasons_str(why2))  -- validity unaffected
  local s = store.new()
  s:put(a); s:put(b); s:put(actual); s:put(att)
  local conflicts_gaps = s:gaps("conflict")
  check(#conflicts_gaps == 0, "Rule 25: no conflict raised for a quarantined belief")
end

V[130] = function()
  local o = occ("rainfall_begins")
  local att = attitude(believer_id(), "desires", o["id"])
  local ok, why = validate_schema(att); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(att); check(ok2, reasons_str(why2))
end

V[131] = function()
  local o = occ("press_button")
  local att = attitude(believer_id(), "intends", o["id"])
  local ok, why = validate_schema(att); check(ok, reasons_str(why))
  local ok2, why2 = validate_semantics(att); check(ok2, reasons_str(why2))
end

V[132] = function()
  local st = state_fixture("boolean", O("boolean", true))
  local inner = attitude(believer_id("holder_b"), "believes", st["id"])
  local outer = attitude(believer_id("holder_a"), "believes", inner["id"])
  for _, att in ipairs({ inner, outer }) do
    local ok, why = validate_schema(att); check(ok, reasons_str(why))
    local ok2, why2 = validate_semantics(att); check(ok2, reasons_str(why2))
  end
  check(outer["id"] ~= inner["id"], "distinct ids")
  check(outer["content"] == inner["id"], "nested content")
end

V[133] = function()
  local o = occ("rainfall_begins")
  local bad = mk(O("type", "attitude", "holder", believer_id(),
    "attitude_type", "suspects", "content", o["id"]))
  local ok, why = validate_schema(bad, "attitude")
  check(not ok and any_mention(why, "attitude_type"),
        "attitude_type is a closed enumeration: " .. reasons_str(why))
end

V[134] = function()
  local o = occ("rainfall_begins")
  local bad = mk(O("type", "attitude", "holder", believer_id(),
    "attitude_type", "believes", "content", o["id"], "strength", 0.9))
  local ok, why = validate_schema(bad, "attitude")
  check(not ok and any_mention(why, "strength"),
        "an attitude carries no strength: " .. reasons_str(why))
end

V[135] = function()
  local o = occ("rainfall_begins")
  local att = attitude(believer_id(), "expects", o["id"])
  local a = signed("assertion", O("about", att["id"],
    "evidence_type", "observation", "confidence", 0.9), "signer")
  local ok, why = validate_schema(a); check(ok, reasons_str(why))
  check(signing.verify_record(a) == true, "the assertion verifies")
  -- the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
  check(att["holder"]:match("^([^:]+):") == "token_individual",
        "the holder is a modeled agent")
  check(a["source"]:match("^([^:]+):") == "ed25519",
        "the source is a signing key")
  check(att["holder"] ~= a["source"], "the holder and the source differ")
end

V[136] = function()
  -- the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
  local secs = O("type", "causal_relation_object",
    "causes", A({ sym("occurrent:a") }), "effects", A({ sym("occurrent:b") }),
    "modality", "sufficient",
    "temporal", O("minimum_delay", 0, "maximum_delay", 1, "unit", "seconds"))
  check(identify(secs) == "causal_relation_object:"
    .. "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
    "the wall-clock CRO identity holds under 4.0.0")
  -- the V118 unbound conduit, re-pinned under 4.0.0
  local unbound = conduit_realized()
  check(unbound["id"] == "conduit:"
    .. "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
    "the unbound conduit identity holds under 4.0.0")
end

V[137] = function()
  local hexid = string.rep("0", 64)
  -- NOTE: the abbreviated prefixes are intentional (the negative test); they
  -- must NOT be re-minted. Each is assembled to survive re-mint tools.
  local att_abbr = "a" .. "t" .. "t"
  local prd_abbr = "p" .. "r" .. "d"
  local err_abbr = "e" .. "r" .. "r"
  local bad_att = O("type", "attitude", "id", att_abbr .. ":" .. hexid,
    "holder", "token_individual:" .. hexid, "attitude_type", "believes",
    "content", "state_assertion:" .. hexid)
  local ok = validate_schema(bad_att, "attitude")
  check(not ok, "the abbreviated attitude scheme must be rejected")
  local bad_prd = O("type", "predicted_occurrence", "id", prd_abbr .. ":" .. hexid,
    "instantiates", "occurrent:" .. hexid, "interval", tick_interval(0),
    "predictor", "token_individual:" .. hexid)
  local ok2 = validate_schema(bad_prd, "predicted_occurrence")
  check(not ok2, "the abbreviated predicted_occurrence scheme must be rejected")
  local bad_err = O("type", "prediction_error", "id", err_abbr .. ":" .. hexid,
    "predicted", "predicted_occurrence:" .. hexid, "discrepancy", 0.0)
  local ok3 = validate_schema(bad_err, "prediction_error")
  check(not ok3, "the abbreviated prediction_error scheme must be rejected")
  local whole_att = json.copy_object(bad_att)
  json.set(whole_att, "id", "attitude:" .. hexid)
  local ok4, why4 = validate_schema(whole_att, "attitude")
  check(ok4, "the whole-word attitude validates: " .. reasons_str(why4))
  local whole_prd = json.copy_object(bad_prd)
  json.set(whole_prd, "id", "predicted_occurrence:" .. hexid)
  local ok5, why5 = validate_schema(whole_prd, "predicted_occurrence")
  check(ok5, "the whole-word predicted_occurrence validates: " .. reasons_str(why5))
  local whole_err = json.copy_object(bad_err)
  json.set(whole_err, "id", "prediction_error:" .. hexid)
  local ok6, why6 = validate_schema(whole_err, "prediction_error")
  check(ok6, "the whole-word prediction_error validates: " .. reasons_str(why6))
end

-- ---------------------------------------------------------------------

local function describe(err)
  if store.is_rejected(err) then return "RejectedWrite: " .. err.message end
  return tostring(err)
end

local function main()
  print("causalontology-lua conformance run (specification 4.0.0)")
  io.write("internal checks (RFC 8032, RFC 8785, fixed constants) ... ")
  internal_checks()
  print("ok")
  local failures = 0
  local total = 137
  for n = 1, total do
    local ok, err = pcall(V[n])
    if ok then
      print("PASS  " .. vec_name(n))
    else
      failures = failures + 1
      print("FAIL  " .. vec_name(n) .. " :: " .. describe(err))
    end
  end
  print(string.rep("-", 60))
  print(string.format("%d/%d vectors passed", total - failures, total))
  if failures > 0 then
    os.exit(1)
  end
  print("causalontology-lua is CONFORMANT to the suite " ..
        "(vectors frozen at specification 4.0.0).")
end

main()

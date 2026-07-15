#!/usr/bin/env lua
-- conformance.lua - the Causalontology conformance runner for
-- causalontology-lua.
--
-- Runs every vector in conformance/vectors/ against the Lua binding.  An
-- implementation is conformant if and only if it passes every vector; this
-- runner exits nonzero on any failure.  It mirrors
-- bindings/python/tests/run_conformance.py exactly.
--
-- The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
-- identifiers, real keys, and a real verifying signature, so the historic
-- symbolic-identifier normalization below now simply passes frozen values
-- through.  The harness still derives behavioral keypairs deterministically
-- from seed sha256("key:" + name).
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

-- ------------------------------------------------- vector file discovery

-- List the vector directory once (the Lua stdlib has no glob).
local vector_files = {}
do
  local ls = assert(io.popen("ls -1 '" .. VECDIR .. "' 2>/dev/null"),
                    "cannot list " .. VECDIR)
  for name in ls:lines() do
    local n = tonumber(name:match("^v(%d%d)_.*%.json$"))
    if n then vector_files[n] = name end
  end
  ls:close()
  assert(vector_files[1], "no vectors found in " .. VECDIR)
end

-- Load vector n's JSON file (for its structured inputs).
local function vec(n)
  local fname = assert(vector_files[n], "vector " .. n .. " not found")
  local f = assert(io.open(VECDIR .. "/" .. fname, "rb"))
  local data = json.decode(f:read("a"))
  f:close()
  return data
end

-- The vector's file stem, for the PASS/FAIL report lines.
local function vec_name(n)
  return (vector_files[n]:gsub("%.json$", ""))
end

-- ---------------------------------------------------------------- helpers

local SCHEMES = {
  occ = true, cro = true, cnt = true, rlz = true,
  ast = true, enr = true, ret = true, suc = true,
}

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
    if is_64_hex(name) then return s end  -- frozen: a real key passes through
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
    local pre = x:match("^(%w+):")
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

-- assert with a value payload in the message.
local function check(cond, why)
  if not cond then error(tostring(why), 0) end
end

-- Run fn, expecting a RejectedWrite; returns its message.
local function expect_rejected(fn, why)
  local ok, err = pcall(fn)
  check(not ok, why or "expected a RejectedWrite")
  check(store.is_rejected(err),
        "expected a RejectedWrite, got: " .. tostring(err))
  return err.message
end

-- True iff some reason string contains the fragment (plain find).
local function any_mention(reasons, fragment)
  for _, r in ipairs(reasons) do
    if r:find(fragment, 1, true) then return true end
  end
  return false
end

-- ---------------------------------------------------------------------
-- internal sanity checks (not conformance vectors)
-- ---------------------------------------------------------------------

local function internal_checks()
  -- RFC 8032, TEST 1 known-answer
  local sk = sha2.from_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  local pk = ed25519.secret_to_public(sk)
  check(sha2.to_hex(pk) ==
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    sha2.to_hex(pk))
  local sig = ed25519.sign(sk, "")
  check(ed25519.verify(pk, "", sig), "TEST 1 signature must verify")
  check(not ed25519.verify(pk, "x", sig), "wrong message must not verify")
  -- JCS basics
  check(jcs.serialize(json.obj("b", 2, "a", 1)) == '{"a":1,"b":2}', "JCS keys")
  check(jcs.serialize(1.0) == "1", "JCS 1.0")
  check(jcs.serialize(6.000) == "6", "JCS 6.000")
  check(jcs.serialize(0.7) == "0.7", "JCS 0.7")
end

-- ---------------------------------------------------------------------
-- the 38 vectors
-- ---------------------------------------------------------------------

local V = {}

V[1] = function()
  local inp = normalize(vec(1)["input"])
  local ok, why = schema.validate_schema(inp)
  check(ok, table.concat(why or {}, "; "))
  local ok2, why2 = semantics.validate_semantics(inp)
  check(ok2, table.concat(why2 or {}, "; "))
end

V[2] = function()
  local inp = normalize(vec(2)["input"])
  check((schema.validate_schema(inp)), "schema")
  check((semantics.validate_semantics(inp)), "semantics")
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
  local ok, why = schema.validate_schema(inp)
  check(not ok, "expected schema-invalid")
  check(any_mention(why, must_mention), table.concat(why, "; "))
end

V[3] = function() schema_fails(3, "effects") end
V[4] = function() schema_fails(4, "causes") end
V[5] = function() schema_fails(5, "modality") end
V[6] = function() schema_fails(6, "colour") end
V[7] = function() schema_fails(7, "causes") end

V[8] = function()
  local ok, why = schema.validate_schema(normalize(vec(8)["input"]))
  check(ok, table.concat(why or {}, "; "))
end

V[9] = function() schema_fails(9, "label") end
V[10] = function() schema_fails(10, "category") end

V[11] = function()
  local ok, why = schema.validate_schema(normalize(vec(11)["input"]))
  check(ok, table.concat(why or {}, "; "))
end

V[12] = function() schema_fails(12, "confidence") end

V[13] = function()
  local inp = normalize(vec(13)["input"])
  local ok, why = schema.validate_schema(inp)
  check(ok, table.concat(why or {}, "; "))
  local ok2, why2 = semantics.validate_semantics(inp)
  check(ok2, table.concat(why2 or {}, "; "))
end

local function semantics_fails(n, must_mention)
  local inp = normalize(vec(n)["input"])
  local ok, why = semantics.validate_semantics(inp)
  check(not ok, "expected semantically-invalid")
  check(any_mention(why, must_mention), table.concat(why, "; "))
end

V[14] = function()
  local inp = normalize(vec(14)["input"])
  check((schema.validate_schema(inp)), "schema must pass")
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
      json.obj("about", about, "field", "subsumes", "entry", entry),
      "taxo", i)
  end
  -- enforcing tier rejects the cycle-completing write
  local s = store.new(true)
  s:put_record(enrich(dog, mam, 1))
  s:put_record(enrich(mam, ani, 2))
  local message = expect_rejected(function()
    s:put_record(enrich(ani, dog, 3))
  end, "enforcing store accepted a cycle")
  check(message:find("cycle", 1, true), message)
  -- decentralized merge: the view breaks the cycle deterministically
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
  local cro = json.obj(
    "causes", json.new_array({ sym("occurrent:c") }),
    "effects", json.new_array({ sym("occurrent:e") }),
    "temporal", g["temporal"])
  return semantics.admissible(cro, g["elapsed_seconds"])
end

V[21] = function() check(adm(21) == true, "must be admissible") end
V[22] = function() check(adm(22) == false, "must not be admissible") end
V[23] = function() check(adm(23) == true, "must be admissible") end

V[24] = function()
  local v = vec(24)
  check(canonical.identify(normalize(v["inputA"]))
        == canonical.identify(normalize(v["inputB"])), "identifiers differ")
end

V[25] = function()
  local v = vec(25)
  check(canonical.identify(normalize(v["inputA"]))
        == canonical.identify(normalize(v["inputB"])), "identifiers differ")
end

V[26] = function()
  local s = store.new()
  local obj = json.obj("type", "occurrent", "label", "press_button",
                       "category", "action")
  local a = s:put(json.copy_object(obj))
  local b = s:put(json.copy_object(obj))
  check(a == b and #s.object_order == 1, "put is not idempotent")
end

V[27] = function()
  local s = store.new()
  local occ = s:put(json.obj("type", "occurrent", "label", "press_button",
                             "category", "action"))
  local entry = json.obj("lang", "en", "text", "press the button")
  local r1 = signed("enrichment",
    json.obj("about", occ, "field", "aliases", "entry", entry), "alice", 1)
  local r2 = signed("enrichment",
    json.obj("about", occ, "field", "aliases", "entry", entry), "bob", 2)
  check(s:put_record(r1) ~= s:put_record(r2), "two records expected")
  local view = s:get(occ).enrichments["aliases"]
  check(#view == 1 and #view[1].contributors == 2, "corroboration view")
end

V[28] = function()
  local s = store.new()
  local claim = json.obj("type", "causal_relation_object",
    "causes", json.new_array({ sym("occurrent:A") }),
    "effects", json.new_array({ sym("occurrent:B") }),
    "modality", "sufficient")
  local i1 = s:put(json.copy_object(claim))
  local i2 = s:put(json.copy_object(claim))
  check(i1 == i2 and #s.object_order == 1, "one object expected")
  s:put_record(signed("assertion",
    json.obj("about", i1, "evidence_type", "observation",
             "strength", 0.8, "confidence", 0.8), "lab1", 1))
  s:put_record(signed("assertion",
    json.obj("about", i1, "evidence_type", "observation",
             "strength", 0.8, "confidence", 0.8), "lab2", 2))
  check(#s:assertions_about(i1) == 2, "two assertions expected")
end

V[29] = function()
  local rec = signed("assertion",
    json.obj("about", sym("causal_relation_object:demo"), "evidence_type", "intervention",
             "strength", 0.7, "confidence", 0.9), "signer")
  check(signing.verify_record(rec) == true, "signature must verify")
end

V[30] = function()
  local rec = signed("assertion",
    json.obj("about", sym("causal_relation_object:demo"), "evidence_type", "intervention",
             "strength", 0.7, "confidence", 0.9), "signer")
  local tampered = json.copy_object(rec)
  json.set(tampered, "confidence", 0.1)
  check(signing.verify_record(tampered) == false, "tampering must fail")
end

V[31] = function()
  local s = store.new()
  local x = s:put(json.obj("type", "causal_relation_object",
    "causes", json.new_array({ sym("occurrent:A") }),
    "effects", json.new_array({ sym("occurrent:B") })))
  local a = signed("assertion",
    json.obj("about", x, "evidence_type", "observation",
             "confidence", 0.8), "lab1", 1)
  s:put_record(a)
  s:put_record(signed("retraction", json.obj("retracts", a["id"]), "lab1", 2))
  check(#s:assertions_about(x) == 0, "retracted assertion still visible")
  local hist = s:assertions_about(x, true)
  check(#hist == 1 and hist[1]["retracted"] == true, "history flag missing")
  local foreign = signed("retraction", json.obj("retracts", a["id"]),
                         "mallory", 3)
  expect_rejected(function() s:put_record(foreign) end,
                  "foreign retraction accepted")
  check(#s:assertions_about(x) == 0, "still excluded by lab1's own")
  check(#s:assertions_about(x, true) == 1, "history count changed")
end

V[32] = function()
  local s = store.new()
  local occ = s:put(json.obj("type", "occurrent", "label", "press_button",
                             "category", "action"))
  local e = signed("enrichment",
    json.obj("about", occ, "field", "aliases",
             "entry", json.obj("lang", "ja", "text", "botan")), "bob", 1)
  s:put_record(e)
  check(#(s:get(occ).enrichments["aliases"] or {}) == 1, "alias missing")
  s:put_record(signed("retraction", json.obj("retracts", e["id"]), "bob", 2))
  check(#(s:get(occ).enrichments["aliases"] or {}) == 0,
        "retracted alias still visible")
  local hist = s:get(occ, "history").enrichments["aliases"] or {}
  check(#hist == 1, "history view lost the alias")
end

V[33] = function()
  local s = store.new()
  local _, k1 = key("K1")
  local _, k2 = key("K2")
  local a = signed("assertion",
    json.obj("about", sym("causal_relation_object:claim"), "evidence_type", "observation",
             "confidence", 0.9), "K1", 1)
  s:put_record(a)
  local succ = signed("succession", json.obj("successor", k2), "K1", 2)
  s:put_record(succ)
  check(s:lineage(k2)[k1] == true and s:lineage(k1)[k2] == true, "lineage")
  local r = signed("retraction", json.obj("retracts", a["id"]), "K2", 3)
  s:put_record(r)  -- successor may retract the predecessor's record
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
  local A, B, C, D = sym("occurrent:A"), sym("occurrent:B"), sym("occurrent:C"), sym("occurrent:D")
  local m1 = json.obj("id", sym("causal_relation_object:m1"),
    "causes", json.new_array({ A }), "effects", json.new_array({ B }))
  local m2 = json.obj("id", sym("causal_relation_object:m2"),
    "causes", json.new_array({ B }), "effects", json.new_array({ C }))
  local m3 = json.obj("id", sym("causal_relation_object:m3"),
    "causes", json.new_array({ D }), "effects", json.new_array({ C }))
  local P = json.obj("causes", json.new_array({ A }),
    "effects", json.new_array({ C }),
    "mechanism", json.new_array({ m1["id"], m2["id"] }))
  check(semantics.hierarchy_consistent(
    P, { [m1["id"]] = m1, [m2["id"]] = m2 }) == "consistent", "consistent")
  local P2 = json.copy_object(P)
  json.set(P2, "mechanism", json.new_array({ m1["id"], m3["id"] }))
  check(semantics.hierarchy_consistent(
    P2, { [m1["id"]] = m1, [m3["id"]] = m3 }) == "inconsistent",
    "inconsistent")
  check(semantics.hierarchy_consistent(
    P, { [m1["id"]] = m1 }) == "indeterminate", "indeterminate")
end

V[37] = function()
  local s = store.new()
  local occ = s:put(json.obj("type", "occurrent", "label", "press_button",
                             "category", "action"))
  s:put_record(signed("enrichment",
    json.obj("about", occ, "field", "aliases",
             "entry", json.obj("lang", "en", "text", "Press the Button")),
    "alice", 1))
  local hits = s:resolve("Press  The   Button", "en")
  check(#hits == 1 and hits[1] == occ, "alias match")
  check(s:resolve("press_button", "en")[1] == occ, "label, first")
end

V[38] = function()
  local s = store.new()
  local P = s:put(json.obj("type", "causal_relation_object",
    "causes", json.new_array({ sym("occurrent:A") }),
    "effects", json.new_array({ sym("occurrent:B") })))
  local function gap_ids()
    local ids = {}
    for _, g in ipairs(s:gaps("missing_field")) do ids[g.id] = true end
    return ids
  end
  check(gap_ids()[P] == true, "the parent must be a gap")
  local R = s:put(json.obj("type", "causal_relation_object",
    "causes", json.new_array({ sym("occurrent:A") }),
    "effects", json.new_array({ sym("occurrent:B") }),
    "temporal", json.obj("minimum_delay", 0, "maximum_delay", 1, "unit", "seconds"),
    "modality", "sufficient",
    "refines", P))
  local ids = gap_ids()
  check(ids[P] == nil, "the gap did not close")
  check(ids[R] == nil, "the refinement itself must be complete")
end

-- ---------------------------------------------------------------------

local function describe(err)
  if store.is_rejected(err) then return "RejectedWrite: " .. err.message end
  return tostring(err)
end

local function main()
  print("causalontology-lua conformance run")
  io.write("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
  internal_checks()
  print("ok")
  local failures = 0
  for n = 1, 38 do
    local ok, err = pcall(V[n])
    if ok then
      print("PASS  " .. vec_name(n))
    else
      failures = failures + 1
      print("FAIL  " .. vec_name(n) .. " :: " .. describe(err))
    end
  end
  local total = 38
  print(string.rep("-", 60))
  print(string.format("%d/%d vectors passed", total - failures, total))
  if failures > 0 then
    os.exit(1)
  end
  print("causalontology-lua is CONFORMANT to the suite " ..
        "(vectors frozen at specification 1.0.0).")
end

main()

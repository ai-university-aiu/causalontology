#!/usr/bin/env ruby
# frozen_string_literal: false

# The Causalontology conformance runner for causalontology-ruby (spec 4.0.0).
#
# Runs every vector in conformance/vectors/ against the Ruby binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure. It mirrors
# bindings/python/tests/run_conformance.py exactly: same fixtures, same
# expected results. Vectors V01-V107 are the whole-word 2.0.0 baseline
# (Principle P7): V01-V38 re-frozen unaltered in meaning, V39-V107 new.
# V108-V119 are the 3.0.0 additions (the ticks unit, the cross_stratal_seam,
# the conduit realized_by); V120-V137 are the 4.0.0 additions (the attitude,
# the predicted_occurrence, the prediction_error).
#
# Symbolic names still used inside this harness's own behavioral constructions
# ("occurrent:A", key "alice") are normalized deterministically - symbolic
# object ids become scheme:sha256(name), and symbolic key names become real
# Ed25519 keypairs seeded from sha256("key:" + name).

require "json"
require "digest"
require "set"
require_relative "lib/causalontology"

C = Causalontology
ROOT = ENV["CAUSALONTOLOGY_ROOT"] || File.expand_path("../..", __dir__)
VECDIR = File.join(ROOT, "conformance", "vectors")

# ---------------------------------------------------------------------------
# assertion helper
# ---------------------------------------------------------------------------
class VectorFailure < StandardError; end

def assert(cond, msg = "assertion failed")
  raise VectorFailure, msg.to_s unless cond
end

# ---------------------------------------------------------------------------
# whole-word scheme normalization (Principle P7)
# ---------------------------------------------------------------------------
SCHEMES = ["occurrent", "causal_relation_object", "continuant", "realizable",
           "assertion", "enrichment", "retraction", "succession",
           "stratum", "bridge", "cross_stratal_seam", "port", "conduit",
           "quality", "token_individual", "token_occurrence", "state_assertion",
           "token_causal_claim",
           "attitude", "predicted_occurrence", "prediction_error"].freeze
WHOLE_WORD = Set.new(SCHEMES) | Set.new(["ed25519"])
SCHEME_PREFIX = /\A(#{(SCHEMES + ["ed25519"]).join("|")}):/
HEX64 = /\A[0-9a-f]{64}\z/
KEYS = {}

# A real, deterministic Ed25519 keypair for a symbolic key name.
def key(name)
  KEYS[name] ||= begin
    seed = Digest::SHA256.digest("key:" + name)
    C.keypair_from_seed(seed)
  end
end

# Normalize one symbolic identifier to a well-formed one.
def sym(s)
  scheme, name = s.split(":", 2)
  if scheme == "ed25519"
    return s if name.match?(HEX64) # a real key passes through
    return key(name)[1]
  end
  return s if name.match?(HEX64)
  scheme + ":" + Digest::SHA256.hexdigest(name)
end

# Recursively normalize symbolic identifiers and placeholders.
def normalize(x)
  case x
  when String
    return "ab" * 64 if x == "<128 hex>"
    return sym(x) if x.match?(SCHEME_PREFIX)
    x
  when Array
    x.map { |v| normalize(v) }
  when Hash
    x.transform_values { |v| normalize(v) } # preserves key order
  else
    x
  end
end

# Load vector n's JSON file (for its structured inputs).
def vec(n)
  hits = Dir.glob(File.join(VECDIR, format("v%02d_*.json", n)))
  assert hits.length == 1, "vector #{n} not found"
  JSON.parse(File.read(hits[0]))
end

def vec_name(n)
  File.basename(Dir.glob(File.join(VECDIR, format("v%02d_*.json", n)))[0], ".json")
end

TS = "2026-07-13T0%d:00:00Z"

# Build, timestamp, and sign a provenance record.
def signed(kind, body, who, ts_i = 0)
  secret, pub = key(who)
  rec = body.dup
  rec["type"] = kind
  rec["timestamp"] = format(TS, ts_i) unless rec.key?("timestamp")
  if kind == "succession"
    rec["predecessor"] = pub unless rec.key?("predecessor")
  else
    rec["source"] = pub
  end
  C.sign_record(rec, secret, kind)
end

# A content object completed with its real content-addressed id.
def mk(obj)
  o = obj.dup
  o["id"] = C.identify(o)
  o
end

# builders -------------------------------------------------------------------
def stratum(label, scheme, ordinal, unit = nil, governs = nil)
  o = { "type" => "stratum", "label" => label, "scheme" => scheme,
        "ordinal" => ordinal }
  o["unit"] = unit if unit
  o["governs"] = governs if governs
  mk(o)
end

def occ(label, stratum_id = nil, category = "event")
  o = { "type" => "occurrent", "label" => label, "category" => category }
  o["stratum"] = stratum_id if stratum_id
  mk(o)
end

def cnt(label, category = "object")
  mk({ "type" => "continuant", "label" => label, "category" => category })
end

def cro(causes, effects, **kw)
  o = { "type" => "causal_relation_object", "causes" => causes,
        "effects" => effects }
  kw.each { |k, v| o[k.to_s] = v }
  mk(o)
end

def bridge(coarse, fine, relation)
  mk({ "type" => "bridge", "coarse" => coarse, "fine" => fine,
       "relation" => relation })
end

def port(bearer, label, direction, accepts, realizable = nil)
  o = { "type" => "port", "bearer" => bearer, "label" => label,
        "direction" => direction, "accepts" => accepts }
  o["realizable"] = realizable if realizable
  mk(o)
end

def conduit(frm, to, carries, label: "conn", transform: nil)
  o = { "type" => "conduit", "label" => label, "from" => frm, "to" => to,
        "carries" => carries }
  o["transform"] = transform if transform
  mk(o)
end

def quality(label, datatype, unit = nil, stratum_id = nil)
  o = { "type" => "quality", "label" => label, "datatype" => datatype }
  o["unit"] = unit if unit
  o["stratum"] = stratum_id if stratum_id
  mk(o)
end

def individual(instantiates, designator: nil, part_of: nil)
  o = { "type" => "token_individual", "instantiates" => instantiates }
  o["designator"] = designator if designator
  o["part_of"] = part_of if part_of
  mk(o)
end

def token(instantiates, interval, participants: nil, locus: nil)
  o = { "type" => "token_occurrence", "instantiates" => instantiates,
        "interval" => interval }
  o["participants"] = participants if participants
  o["locus"] = locus if locus
  mk(o)
end

def state(subject, qual, value, interval)
  mk({ "type" => "state_assertion", "subject" => subject, "quality" => qual,
       "value" => value, "interval" => interval })
end

def tcc(causes, effects, covering_law: nil, actual_delay: nil,
        counterfactual: nil)
  o = { "type" => "token_causal_claim", "causes" => causes,
        "effects" => effects }
  o["covering_law"] = covering_law if covering_law
  o["actual_delay"] = actual_delay if actual_delay
  o["counterfactual"] = counterfactual unless counterfactual.nil?
  mk(o)
end

# ---------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# ---------------------------------------------------------------------------
def internal_checks
  # RFC 8032, TEST 1 known-answer
  sk = ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"].pack("H*")
  pk = C::Ed25519.secret_to_public(sk)
  assert pk.unpack1("H*") ==
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         pk.unpack1("H*")
  sig = C::Ed25519.sign(sk, "")
  assert C::Ed25519.verify(pk, "", sig)
  assert !C::Ed25519.verify(pk, "x", sig)
  # JCS basics
  assert C::Jcs.encode({ "b" => 2, "a" => 1 }) == '{"a":1,"b":2}'
  assert C::Jcs.encode(1.0) == "1"
  assert C::Jcs.encode(6.000) == "6"
  assert C::Jcs.encode(0.7) == "0.7"
  # fixed unit constants
  assert C.to_seconds(1, "months") == 2629746
  assert C.to_seconds(1, "years") == 31556952
end

# ---------------------------------------------------------------------------
# V01 - V38: the whole-word re-freeze of the 1.0.0 suite (unaltered in meaning)
# ---------------------------------------------------------------------------
def v01
  inp = normalize(vec(1)["input"])
  ok, why = C.validate_schema(inp)
  assert ok, why
  ok, why = C.validate_semantics(inp)
  assert ok, why
end

def v02
  inp = normalize(vec(2)["input"])
  ok, _why = C.validate_schema(inp)
  assert ok
  ok, _why = C.validate_semantics(inp)
  assert ok
  partial, missing = C.is_partial(inp)
  assert partial && missing == vec(2)["expect"]["missing"], missing
end

def schema_fails(n, must_mention)
  inp = normalize(vec(n)["input"])
  ok, why = C.validate_schema(inp)
  assert !ok, "expected schema-invalid"
  assert why.any? { |w| w.include?(must_mention) }, why
end

def v03; schema_fails(3, "effects"); end
def v04; schema_fails(4, "causes"); end
def v05; schema_fails(5, "modality"); end
def v06; schema_fails(6, "colour"); end
def v07; schema_fails(7, "causes"); end

def v08
  ok, why = C.validate_schema(normalize(vec(8)["input"]))
  assert ok, why
end

def v09; schema_fails(9, "label"); end
def v10; schema_fails(10, "category"); end

def v11
  ok, why = C.validate_schema(normalize(vec(11)["input"]))
  assert ok, why
end

def v12; schema_fails(12, "confidence"); end

def v13
  inp = normalize(vec(13)["input"])
  ok, why = C.validate_schema(inp)
  assert ok, why
  ok, why = C.validate_semantics(inp)
  assert ok, why
end

def semantics_fails(n, must_mention)
  inp = normalize(vec(n)["input"])
  ok, why = C.validate_semantics(inp)
  assert !ok, "expected semantically-invalid"
  assert why.any? { |w| w.include?(must_mention) }, why
end

def v14
  inp = normalize(vec(14)["input"])
  ok, _why = C.validate_schema(inp)
  assert ok
  semantics_fails(14, "minimum_delay")
end

def v15; semantics_fails(15, "acyclic"); end
def v16; semantics_fails(16, "acyclic"); end

def v17
  v = vec(17)
  parent = normalize(v["given"]["parent"])
  child = normalize(v["input"])
  ok, reason = C.refinement_valid(child, parent)
  assert !ok && reason.include?("rival"), reason
end

def v18; semantics_fails(18, "not a legal field"); end
def v19; semantics_fails(19, "language-tagged"); end

def v20
  dog = sym("continuant:dog")
  mam = sym("continuant:mammal")
  ani = sym("continuant:animal")
  enrich = lambda do |about, entry, i|
    signed("enrichment",
           { "about" => about, "field" => "subsumes", "entry" => entry },
           "taxo", i)
  end
  s = C::InMemoryStore.new(enforcing: true)
  s.put_record(enrich.call(dog, mam, 1))
  s.put_record(enrich.call(mam, ani, 2))
  begin
    s.put_record(enrich.call(ani, dog, 3))
    raise VectorFailure, "enforcing store accepted a cycle"
  rescue C::RejectedWrite => e
    assert e.message.include?("cycle"), e.message
  end
  s2 = C::InMemoryStore.new(enforcing: true)
  s2.put_record(enrich.call(dog, mam, 1))
  s2.put_record(enrich.call(mam, ani, 2))
  bad = enrich.call(ani, dog, 3)
  s2.force_merge_record(bad)
  _active, excluded = s2.active_taxonomy_edges("subsumes")
  assert excluded.length == 1 && excluded[0]["id"] == bad["id"]
  repair = s2.gaps("inconsistent_hierarchy")
  assert repair.any? { |g| g["id"] == bad["id"] }
end

def adm(n)
  g = vec(n)["given"]
  c = { "causes" => [sym("occurrent:c")], "effects" => [sym("occurrent:e")],
        "temporal" => g["temporal"] }
  C.admissible(c, g["elapsed_seconds"])
end

def v21; assert adm(21) == true; end
def v22; assert adm(22) == false; end
def v23; assert adm(23) == true; end

def v24
  v = vec(24)
  assert C.identify(normalize(v["inputA"])) == C.identify(normalize(v["inputB"]))
end

def v25
  v = vec(25)
  assert C.identify(normalize(v["inputA"])) == C.identify(normalize(v["inputB"]))
end

def v26
  s = C::InMemoryStore.new
  obj = { "type" => "occurrent", "label" => "press_button",
          "category" => "action" }
  a = s.put(obj.dup)
  b = s.put(obj.dup)
  assert a == b && s.objects.length == 1
end

def v27
  s = C::InMemoryStore.new
  occid = s.put({ "type" => "occurrent", "label" => "press_button",
                  "category" => "action" })
  entry = { "lang" => "en", "text" => "press the button" }
  r1 = signed("enrichment", { "about" => occid, "field" => "aliases",
                              "entry" => entry }, "alice", 1)
  r2 = signed("enrichment", { "about" => occid, "field" => "aliases",
                              "entry" => entry }, "bob", 2)
  assert s.put_record(r1) != s.put_record(r2)
  view = s.get(occid)["enrichments"]["aliases"]
  assert view.length == 1 && view[0]["contributors"].length == 2
end

def v28
  s = C::InMemoryStore.new
  claim = { "type" => "causal_relation_object", "causes" => [sym("occurrent:A")],
            "effects" => [sym("occurrent:B")], "modality" => "sufficient" }
  i1 = s.put(claim.dup)
  i2 = s.put(claim.dup)
  assert i1 == i2 && s.objects.length == 1
  [["lab1", 1], ["lab2", 2]].each do |who, ts|
    s.put_record(signed("assertion",
                        { "about" => i1, "evidence_type" => "observation",
                          "strength" => 0.8, "confidence" => 0.8 }, who, ts))
  end
  assert s.assertions_about(i1).length == 2
end

def v29
  rec = signed("assertion", { "about" => sym("causal_relation_object:demo"),
                              "evidence_type" => "intervention",
                              "strength" => 0.7, "confidence" => 0.9 }, "signer")
  assert C.verify_record(rec) == true
end

def v30
  rec = signed("assertion", { "about" => sym("causal_relation_object:demo"),
                              "evidence_type" => "intervention",
                              "strength" => 0.7, "confidence" => 0.9 }, "signer")
  tampered = rec.merge("confidence" => 0.1)
  assert C.verify_record(tampered) == false
end

def v31
  s = C::InMemoryStore.new
  x = s.put({ "type" => "causal_relation_object", "causes" => [sym("occurrent:A")],
              "effects" => [sym("occurrent:B")] })
  a = signed("assertion", { "about" => x, "evidence_type" => "observation",
                            "confidence" => 0.8 }, "lab1", 1)
  s.put_record(a)
  s.put_record(signed("retraction", { "retracts" => a["id"] }, "lab1", 2))
  assert s.assertions_about(x) == []
  hist = s.assertions_about(x, include_retracted: true)
  assert hist.length == 1 && hist[0]["retracted"] == true
  foreign = signed("retraction", { "retracts" => a["id"] }, "mallory", 3)
  begin
    s.put_record(foreign)
    raise VectorFailure, "foreign retraction accepted"
  rescue C::RejectedWrite
    # expected: only the source or its lineage may retract
  end
end

def v32
  s = C::InMemoryStore.new
  occid = s.put({ "type" => "occurrent", "label" => "press_button",
                  "category" => "action" })
  e = signed("enrichment", { "about" => occid, "field" => "aliases",
                             "entry" => { "lang" => "ja", "text" => "botan" } },
             "bob", 1)
  s.put_record(e)
  before = s.get(occid)["enrichments"]["aliases"] || []
  assert before.length == 1
  s.put_record(signed("retraction", { "retracts" => e["id"] }, "bob", 2))
  after = s.get(occid)["enrichments"]["aliases"] || []
  assert after == []
  hist = s.get(occid, view: "history")["enrichments"]["aliases"] || []
  assert hist.length == 1
end

def v33
  s = C::InMemoryStore.new
  k1 = key("K1")[1]
  k2 = key("K2")[1]
  a = signed("assertion", { "about" => sym("causal_relation_object:claim"),
                            "evidence_type" => "observation",
                            "confidence" => 0.9 }, "K1", 1)
  s.put_record(a)
  s.put_record(signed("succession", { "successor" => k2 }, "K1", 2))
  assert s.lineage(k2).include?(k1) && s.lineage(k1).include?(k2)
  s.put_record(signed("retraction", { "retracts" => a["id"] }, "K2", 3))
  assert s.assertions_about(sym("causal_relation_object:claim")) == []
end

def v34
  g = normalize(vec(34)["given"])
  assert C.conflicts(g["A"], g["B"]) == true
end

def v35
  g = normalize(vec(35)["given"])
  assert C.conflicts(g["A"], g["B"]) == false
end

def v36
  a = sym("occurrent:A"); b = sym("occurrent:B")
  c = sym("occurrent:C"); d = sym("occurrent:D")
  m1 = { "id" => sym("causal_relation_object:m1"), "causes" => [a], "effects" => [b] }
  m2 = { "id" => sym("causal_relation_object:m2"), "causes" => [b], "effects" => [c] }
  m3 = { "id" => sym("causal_relation_object:m3"), "causes" => [d], "effects" => [c] }
  parent = { "causes" => [a], "effects" => [c],
             "mechanism" => [m1["id"], m2["id"]] }
  assert C.hierarchy_consistent(parent, { m1["id"] => m1, m2["id"] => m2 }) == "consistent"
  parent2 = parent.merge("mechanism" => [m1["id"], m3["id"]])
  assert C.hierarchy_consistent(parent2, { m1["id"] => m1, m3["id"] => m3 }) == "inconsistent"
  assert C.hierarchy_consistent(parent, { m1["id"] => m1 }) == "indeterminate"
end

def v37
  s = C::InMemoryStore.new
  occid = s.put({ "type" => "occurrent", "label" => "press_button",
                  "category" => "action" })
  s.put_record(signed("enrichment",
                      { "about" => occid, "field" => "aliases",
                        "entry" => { "lang" => "en",
                                     "text" => "Press the Button" } },
                      "alice", 1))
  assert s.resolve("Press  The   Button", "en") == [occid]
  assert s.resolve("press_button", "en")[0] == occid
end

def v38
  s = C::InMemoryStore.new
  parent = s.put({ "type" => "causal_relation_object", "causes" => [sym("occurrent:A")],
                   "effects" => [sym("occurrent:B")] })
  gaps = s.gaps("missing_field").map { |g| g["id"] }
  assert gaps.include?(parent)
  refinement = s.put({ "type" => "causal_relation_object", "causes" => [sym("occurrent:A")],
                       "effects" => [sym("occurrent:B")],
                       "temporal" => { "minimum_delay" => 0, "maximum_delay" => 1,
                                       "unit" => "seconds" },
                       "modality" => "sufficient", "refines" => parent })
  gaps = s.gaps("missing_field").map { |g| g["id"] }
  assert !gaps.include?(parent), "the gap did not close"
  assert !gaps.include?(refinement), "the refinement itself must be complete"
end

# ---------------------------------------------------------------------------
# V39 - V107: the 2.0.0 additions
# ---------------------------------------------------------------------------
def neuro
  labels = { 4 => "macromolecular", 5 => "subcellular", 6 => "cellular",
             7 => "synaptic", 9 => "region", 14 => "community_and_society" }
  labels.each_with_object({}) { |(o, l), h| h[o] = stratum(l, "neuroendocrine", o) }
end

def v39
  st = stratum("cellular", "neuroendocrine", 6, "cell", ["cell_biology"])
  ok, why = C.validate_schema(st)
  assert ok, why
end

def v40
  bad = mk({ "type" => "stratum", "label" => "cellular", "ordinal" => 6 })
  ok, why = C.validate_schema(bad, "stratum")
  assert !ok && why.any? { |w| w.include?("scheme") }, why
end

def v41
  a = stratum("cellular", "neuroendocrine", 6)
  b = stratum("neuronal", "neuroendocrine", 6)
  [a, b].each do |x|
    ok, why = C.validate_schema(x)
    assert ok, why
  end
  assert a["id"] != b["id"]
end

def v42
  s = neuro
  s4p = stratum("molecular", "physics", 4)
  c = occ("chronic_social_subordination", s[14]["id"])
  e = occ("gene_expression", s4p["id"])
  smap = { s[14]["id"] => s[14], s4p["id"] => s4p }
  omap = { c["id"] => c, e["id"] => e }
  parent = cro([c["id"]], [e["id"]])
  assert C.classify_cro(parent, omap, smap) == "scheme_mismatch"
end

def v43
  [stratum("macromolecular", "neuroendocrine", 4),
   stratum("region", "neuroendocrine", 9)].each do |x|
    ok, why = C.validate_schema(x)
    assert ok, why
  end
end

def v44
  st = stratum("cellular", "neuroendocrine", 6)
  o = occ("neuron_fires", st["id"])
  ok, why = C.validate_schema(o)
  assert ok, why
  ok, why = C.validate_semantics(o)
  assert ok, why
end

def v45
  o = occ("press_button")
  ok, why = C.validate_schema(o)
  assert ok, why
  e = occ("light_on")
  parent = cro([o["id"]], [e["id"]])
  assert C.classify_cro(parent, { o["id"] => o, e["id"] => e }, {}) == "unclassifiable"
end

def v46
  s = neuro
  a = occ("depolarization", s[5]["id"])
  b = occ("depolarization", s[6]["id"])
  assert a["id"] != b["id"]
end

def bridge_fixture(relation)
  s = neuro
  coarse = occ("action_potential_fires", s[6]["id"])
  fine = [occ("sodium_channels_open", s[4]["id"]),
          occ("sodium_influx", s[4]["id"])]
  b = bridge(coarse["id"], fine.map { |f| f["id"] }, relation)
  omap = { coarse["id"] => coarse }
  fine.each { |f| omap[f["id"]] = f }
  smap = { s[4]["id"] => s[4], s[6]["id"] => s[6] }
  [b, omap, smap]
end

def valid_bridge(relation)
  b, omap, smap = bridge_fixture(relation)
  ok, why = C.validate_schema(b)
  assert ok, why
  ok, why = C.bridge_wellformed(b, omap, smap)
  assert ok, why
end

def v47; valid_bridge("constitutes"); end
def v48; valid_bridge("aggregates"); end
def v49; valid_bridge("realizes"); end
def v50; valid_bridge("supervenes_on"); end

def v51
  s = neuro
  coarse = occ("x_coarse", s[4]["id"])
  fine = occ("x_fine", s[6]["id"])
  b = bridge(coarse["id"], [fine["id"]], "constitutes")
  omap = { coarse["id"] => coarse, fine["id"] => fine }
  smap = { s[4]["id"] => s[4], s[6]["id"] => s[6] }
  ok, _ = C.bridge_wellformed(b, omap, smap)
  assert !ok
end

def v52
  s = neuro
  coarse = occ("c", s[6]["id"])
  f1 = occ("f1", s[4]["id"])
  f2 = occ("f2", s[5]["id"])
  b = bridge(coarse["id"], [f1["id"], f2["id"]], "constitutes")
  omap = { coarse["id"] => coarse, f1["id"] => f1, f2["id"] => f2 }
  smap = { s[4]["id"] => s[4], s[5]["id"] => s[5], s[6]["id"] => s[6] }
  ok, _ = C.bridge_wellformed(b, omap, smap)
  assert !ok
end

def v53
  x = sym("occurrent:x")
  y = sym("occurrent:y")
  b1 = bridge(x, [y], "constitutes")
  b2 = bridge(y, [x], "constitutes")
  edges = {}
  [b1, b2].each do |b|
    b["fine"].each { |f| (edges[f] ||= []) << b["coarse"] }
  end
  assert C.has_cycle(edges) == true
end

def v54
  a = stratum("cellular", "neuroendocrine", 6)
  b = stratum("molecular", "physics", 4)
  coarse = occ("c", a["id"])
  fine = occ("f", b["id"])
  br = bridge(coarse["id"], [fine["id"]], "constitutes")
  omap = { coarse["id"] => coarse, fine["id"] => fine }
  smap = { a["id"] => a, b["id"] => b }
  ok, _ = C.bridge_wellformed(br, omap, smap)
  assert !ok
end

def v55
  s = neuro
  coarse = occ("decision_made", s[6]["id"])
  f1 = occ("cascade_a", s[4]["id"])
  f2 = occ("cascade_b", s[4]["id"])
  b1 = bridge(coarse["id"], [f1["id"]], "realizes")
  b2 = bridge(coarse["id"], [f2["id"]], "realizes")
  assert b1["id"] != b2["id"]
  [b1, b2].each do |b|
    ok, why = C.validate_schema(b)
    assert ok, why
  end
end

def reach_fixture
  s = neuro
  ap = occ("action_potential_fires", s[6]["id"])
  nt = occ("neurotransmitter_released", s[6]["id"])
  fa = occ("calcium_enters", s[4]["id"])
  fb = occ("vesicle_fuses", s[4]["id"])
  m1 = cro([fa["id"]], [fb["id"]])
  parent = cro([ap["id"]], [nt["id"]], mechanism: [m1["id"]])
  bridges = [bridge(ap["id"], [fa["id"]], "constitutes"),
             bridge(nt["id"], [fb["id"]], "constitutes")]
  [parent, { m1["id"] => m1 }, bridges]
end

def v56
  parent, members, bridges = reach_fixture
  assert C.hierarchy_consistent(parent, members, bridges) == "consistent"
end

def v57
  parent, members, _ = reach_fixture
  assert C.hierarchy_consistent(parent, members, []) == "inconsistent"
end

def v58
  parent, members, bridges = reach_fixture
  literal = C.hierarchy_consistent(parent, members, [])
  bridged = C.hierarchy_consistent(parent, members, bridges)
  assert literal != "consistent" && bridged == "consistent"
end

def classify(cause_ord, effect_ord)
  s = neuro
  c = occ("c", s[cause_ord]["id"])
  e = occ("e", s[effect_ord]["id"])
  smap = { s[cause_ord]["id"] => s[cause_ord], s[effect_ord]["id"] => s[effect_ord] }
  omap = { c["id"] => c, e["id"] => e }
  C.classify_cro(cro([c["id"]], [e["id"]]), omap, smap)
end

def v59; assert classify(6, 6) == "intra_stratal"; end
def v60; assert classify(6, 5) == "adjacent_stratal"; end
def v61; assert classify(14, 4) == "skipping"; end

def skip_fixture(cause_ord, effect_ord, **kw)
  s = neuro
  c = occ("c", s[cause_ord]["id"])
  e = occ("e", s[effect_ord]["id"])
  smap = { s[cause_ord]["id"] => s[cause_ord], s[effect_ord]["id"] => s[effect_ord] }
  omap = { c["id"] => c, e["id"] => e }
  parent = cro([c["id"]], [e["id"]], **kw)
  [parent, C.classify_cro(parent, omap, smap)]
end

def v62
  parent, cls = skip_fixture(14, 4)
  assert C.skip_gaps(parent, cls) == ["incomplete_mechanism"]
end

def v63
  parent, cls = skip_fixture(14, 4, skips: true)
  assert C.skip_gaps(parent, cls) == []
end

def v64
  parent, cls = skip_fixture(14, 4, skips: true,
                             mechanism: [sym("causal_relation_object:m")])
  assert C.skip_gaps(parent, cls) == ["contradictory_skip"]
  ok, why = C.validate_semantics(parent)
  assert !ok && why.any? { |w| w.include?("contradictory_skip") }
end

def v65
  parent, cls = skip_fixture(6, 6, skips: true)
  assert C.skip_gaps(parent, cls) == ["vacuous_skip"]
end

def v66
  s = neuro
  c = occ("c", s[14]["id"])
  e = occ("e", s[4]["id"])
  absent = cro([c["id"]], [e["id"]])
  false_ = cro([c["id"]], [e["id"]], skips: false)
  assert absent["id"] != false_["id"]
end

def v67
  s = neuro
  c1 = occ("c1", s[4]["id"])
  c2 = occ("c2", s[6]["id"])
  e = occ("e", s[6]["id"])
  parent = cro([c1["id"], c2["id"]], [e["id"]])
  assert C.endpoints_mixed(parent, { c1["id"] => c1, c2["id"] => c2, e["id"] => e }) == true
end

def v68
  parent = cro([sym("occurrent:a")], [sym("occurrent:b")], modality: "enabling")
  ok, why = C.validate_schema(parent)
  assert ok, why
end

def v69
  a = { "causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")],
        "modality" => "enabling" }
  b = { "causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")],
        "modality" => "sufficient" }
  assert C.conflicts(a, b) == false
end

def v70
  a = { "causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")],
        "modality" => "enabling" }
  b = { "causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")],
        "modality" => "preventive" }
  assert C.conflicts(a, b) == true
end

def v71
  b = cnt("hippocampus")
  p = port(b["id"], "perforant_path", "in", [sym("occurrent:signal")])
  ok, why = C.validate_schema(p)
  assert ok, why
end

def v72
  b = cnt("hippocampus")["id"]
  x = sym("occurrent:signal")
  assert port(b, "perforant_path", "in", [x])["id"] !=
         port(b, "fornix", "in", [x])["id"]
end

def conduit_fixture(transform: false, bad_carry: false, in_from: false)
  x = sym("occurrent:motor_command")
  y = sym("occurrent:error_signal")
  z = sym("occurrent:unrelated")
  m1 = cnt("motor_cortex")["id"]
  m2 = cnt("spinal_neuron")["id"]
  frm = port(m1, "out_port", in_from ? "in" : "out", [x])
  to = port(m2, "in_port", "in", transform ? [y] : [x])
  carries = bad_carry ? [z] : [x]
  xform = nil
  cro_map = {}
  if transform
    law = cro([x], [y])
    cro_map[law["id"]] = law
    xform = law["id"]
  end
  c = conduit(frm["id"], to["id"], carries, transform: xform)
  [c, { frm["id"] => frm, to["id"] => to }, cro_map]
end

def v73
  c, pmap, _ = conduit_fixture
  ok, why = C.validate_schema(c)
  assert ok, why
  ok, why = C.conduit_wellformed(c, pmap)
  assert ok, why
end

def v74
  c, pmap, cmap = conduit_fixture(transform: true)
  ok, why = C.validate_schema(c)
  assert ok, why
  ok, why = C.conduit_wellformed(c, pmap, cmap)
  assert ok, why
end

def v75
  c, pmap, _ = conduit_fixture(bad_carry: true)
  ok, _ = C.conduit_wellformed(c, pmap)
  assert !ok
end

def v76
  c, pmap, _ = conduit_fixture(in_from: true)
  ok, _ = C.conduit_wellformed(c, pmap)
  assert !ok
end

def v77
  c, pmap, cmap = conduit_fixture(transform: true)
  ok, why = C.conduit_wellformed(c, pmap, cmap)
  assert ok, why
  law = cmap.values[0]
  assert !c["carries"].include?(law["effects"][0])
end

def rlz(bearer, kind, label = nil)
  o = { "type" => "realizable", "kind" => kind, "bearer" => bearer }
  o["label"] = label if label
  mk(o)
end

def v78
  b = cnt("hippocampus")["id"]
  assert rlz(b, "disposition", "long_term_potentiation")["id"] !=
         rlz(b, "disposition", "pattern_separation")["id"]
end

def v79
  b = cnt("hippocampus")["id"]
  u1 = rlz(b, "disposition")
  u2 = rlz(b, "disposition")
  ok, why = C.validate_schema(u1)
  assert ok, why
  assert u1["id"] == u2["id"]
  assert rlz(b, "disposition", "some_function")["id"] != u1["id"]
end

def v80
  parent = occ("fires")
  child = occ("fires_action_potential")
  e = { "type" => "enrichment", "about" => child["id"],
        "field" => "occurrent_subsumes", "entry" => parent["id"] }
  ok, why = C.validate_semantics(e)
  assert ok, why
end

def v81
  a = sym("occurrent:a")
  b = sym("occurrent:b")
  assert C.has_cycle({ a => [b], b => [a] }) == true
end

def v82
  whole = occ("eat")
  part = occ("chew")
  e = { "type" => "enrichment", "about" => part["id"],
        "field" => "occurrent_part_of", "entry" => whole["id"] }
  ok, why = C.validate_semantics(e)
  assert ok, why
end

def v83
  legal_kinds, shape = C::Semantics::ENRICHMENT_FIELDS["occurrent_part_of"]
  assert shape == "occurrent" && legal_kinds == ["occurrent"]
  s = C::InMemoryStore.new
  s.put(occ("eat"))
  s.put(occ("chew"))
  assert s.objects.values.none? { |o| o["type"] == "causal_relation_object" }
end

def v84
  s = neuro
  a = occ("run", s[9]["id"])
  b = occ("sprint", s[6]["id"])
  assert a["stratum"] != b["stratum"]
end

def v85
  c = cnt("human_patient")
  ti = individual(c["id"], designator: "salted_hash_abc123")
  ok, why = C.validate_schema(ti)
  assert ok, why
end

def v86
  bad = mk({ "type" => "token_individual", "designator" => "x" })
  ok, why = C.validate_schema(bad, "token_individual")
  assert !ok && why.any? { |w| w.include?("instantiates") }, why
end

def v87
  c = cnt("human_patient")["id"]
  assert individual(c, designator: "hash_a")["id"] !=
         individual(c, designator: "hash_b")["id"]
end

def v88
  o = occ("bilateral_hippocampal_resection")
  t = token(o["id"], { "start" => "1953-08-25T00:00:00Z",
                       "end" => "1953-08-25T00:00:00Z" })
  ok, why = C.validate_schema(t)
  assert ok, why
end

def v89
  o = occ("amnesia_onset")["id"]
  bounded = token(o, { "start" => "1953-08-25T00:00:00Z",
                       "end" => "1953-08-26T00:00:00Z" })
  instantaneous = token(o, { "start" => "1953-08-25T00:00:00Z" })
  ongoing = token(o, { "start" => "1953-08-25T00:00:00Z", "open" => true })
  assert Set.new([bounded["id"], instantaneous["id"], ongoing["id"]]).length == 3
end

def v90
  o = occ("resection")["id"]
  c = cnt("human_patient")["id"]
  patient = individual(c, designator: "p")["id"]
  surgeon = individual(c, designator: "s")["id"]
  t = token(o, { "start" => "1953-08-25T00:00:00Z" },
            participants: [{ "role" => "patient", "filler" => patient },
                           { "role" => "agent", "filler" => surgeon }])
  ok, why = C.validate_schema(t)
  assert ok, why
end

def v91
  q = quality("cortisol_concentration", "quantity", "ug/dL")
  ok, why = C.validate_schema(q)
  assert ok, why
end

def state_fixture(datatype, value, unit = nil)
  q = quality("cortisol_concentration", datatype, unit)
  c = cnt("human_patient")["id"]
  subj = individual(c, designator: "p")["id"]
  st = state(subj, q["id"], value,
             { "start" => "2026-01-01T00:00:00Z", "end" => "2026-01-01T01:00:00Z" })
  [st, q]
end

def v92
  st, q = state_fixture("quantity", { "quantity" => 15.0, "unit" => "ug/dL" },
                        "ug/dL")
  ok, why = C.validate_schema(st)
  assert ok, why
  assert C.state_gaps(st, q) == []
end

def v93
  st, q = state_fixture("categorical", { "categorical" => "elevated" })
  ok, why = C.validate_schema(st)
  assert ok, why
  assert C.state_gaps(st, q) == []
end

def v94
  st, q = state_fixture("boolean", { "boolean" => true })
  ok, why = C.validate_schema(st)
  assert ok, why
  assert C.state_gaps(st, q) == []
end

def v95
  st, q = state_fixture("quantity", { "categorical" => "elevated" }, "ug/dL")
  assert C.state_gaps(st, q) == ["value_type_mismatch"]
end

def v96
  st, q = state_fixture("quantity", { "quantity" => 15.0, "unit" => "mg/dL" },
                        "ug/dL")
  assert C.state_gaps(st, q) == ["unit_mismatch"]
end

def law_and_tokens
  o_cause = occ("resection")
  o_effect = occ("amnesia_onset")
  law = cro([o_cause["id"]], [o_effect["id"]],
            temporal: { "minimum_delay" => 0, "maximum_delay" => 1, "unit" => "days" },
            modality: "sufficient")
  t_cause = token(o_cause["id"], { "start" => "1953-08-25T00:00:00Z" })
  t_effect = token(o_effect["id"], { "start" => "1953-08-25T00:00:00Z",
                                     "open" => true })
  [law, o_cause, o_effect, t_cause, t_effect]
end

def v97
  law, _, _, tc, te = law_and_tokens
  claim = tcc([tc["id"]], [te["id"]], covering_law: law["id"],
              actual_delay: { "duration" => 0, "unit" => "instant" },
              counterfactual: true)
  ok, why = C.validate_schema(claim)
  assert ok, why
end

def v98
  _, _, _, tc, te = law_and_tokens
  claim = tcc([tc["id"]], [te["id"]])
  ok, why = C.validate_schema(claim)
  assert ok, why
  assert !claim.key?("covering_law")
end

def v99
  law, _, _, _, _ = law_and_tokens
  assert C.delay_within_window({ "duration" => 0, "unit" => "instant" },
                               law["temporal"]) == true
end

def v100
  temporal = { "minimum_delay" => 0, "maximum_delay" => 1, "unit" => "hours" }
  assert C.delay_within_window({ "duration" => 5, "unit" => "days" }, temporal) == false
end

def v101
  o = occ("x")["id"]
  cause = token(o, { "start" => "2026-01-02T00:00:00Z" })
  effect = token(o, { "start" => "2026-01-01T00:00:00Z" })
  claim = tcc([cause["id"]], [effect["id"]])
  assert C.retrocausal(claim, { cause["id"] => cause, effect["id"] => effect }) == true
end

def v102
  other = cro([sym("occurrent:foo")], [sym("occurrent:bar")])
  _, _, _, tc, te = law_and_tokens
  claim = tcc([tc["id"]], [te["id"]], covering_law: other["id"])
  assert C.covering_law_mismatch(claim, { tc["id"] => tc, te["id"] => te }, other) == true
end

def v103
  a = signed("assertion", { "about" => sym("token_occurrence:t"),
                            "evidence_type" => "observation",
                            "confidence" => 0.9 }, "signer")
  ok, why = C.validate_schema(a)
  assert ok, why
end

def v104
  ev = [sym("token_occurrence:t1"), sym("token_causal_claim:c1")]
  base = { "type" => "assertion", "about" => sym("causal_relation_object:law"),
           "source" => key("signer")[1], "evidence_type" => "intervention",
           "strength" => 0.95, "confidence" => 0.99,
           "timestamp" => "2026-07-14T00:00:00Z" }
  a = base.merge("evidenced_by" => ev)
  ok, why = C.validate_schema(a.merge("id" => C.identify(a)))
  assert ok, why
  assert C.identify(a) != C.identify(base) # evidenced_by is identity-bearing
end

def v105
  a = signed("assertion", { "about" => sym("causal_relation_object:law"),
                            "evidence_type" => "simulation",
                            "confidence" => 0.5 }, "signer")
  ok, why = C.validate_schema(a)
  assert ok, why
  rank = { "intervention" => 0, "observation" => 1, "simulation" => 2 }
  assert rank["intervention"] < rank["observation"] &&
         rank["observation"] < rank["simulation"]
end

def v106
  scan = nil
  scan = lambda do |node, ids|
    case node
    when String
      m = node.match(/\A([a-z0-9_]+):[0-9a-f]{64}\z/)
      ids << m[1] if m
    when Array
      node.each { |x| scan.call(x, ids) }
    when Hash
      node.each_value { |x| scan.call(x, ids) }
    end
  end
  (1..38).each do |n|
    ids = []
    scan.call(vec(n), ids)
    ids.each do |scheme|
      assert WHOLE_WORD.include?(scheme),
             "V106: abbreviated scheme #{scheme.inspect} in vector #{n}"
    end
  end
  rec = { "type" => "occurrent", "label" => "press_button", "category" => "action" }
  assert C.identify(rec) == C.identify(rec)
  assert C.identify(rec).split(":", 2)[0] == "occurrent"
end

def v107
  hexid = "0" * 64
  # NOTE: the abbreviated prefix below is intentional (the negative test);
  # it must NOT be re-minted. "c" "r" "o" is assembled to survive re-mint tools.
  cro_abbr = "c" + "r" + "o"
  abbreviated = { "type" => "causal_relation_object", "id" => cro_abbr + ":" + hexid,
                  "causes" => ["occurrent:" + hexid],
                  "effects" => ["occurrent:" + hexid] }
  ok, _ = C.validate_schema(abbreviated, "causal_relation_object")
  assert !ok, "abbreviated scheme must be rejected"
  abbr_str = { "type" => "stratum", "id" => "str:" + hexid, "label" => "cellular",
               "scheme" => "neuroendocrine", "ordinal" => 6 }
  ok, _ = C.validate_schema(abbr_str, "stratum")
  assert !ok
  whole = { "type" => "causal_relation_object",
            "id" => "causal_relation_object:" + hexid,
            "causes" => ["occurrent:" + hexid],
            "effects" => ["occurrent:" + hexid] }
  ok, why = C.validate_schema(whole, "causal_relation_object")
  assert ok, why
end

# ---------------------------------------------------------------------------
# V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam, realized_by)
# ---------------------------------------------------------------------------
def seam(source, target, mechanism_status, chain = nil)
  o = { "type" => "cross_stratal_seam", "source" => source,
        "target" => target, "mechanism_status" => mechanism_status }
  o["chain"] = chain unless chain.nil? || chain.empty?
  mk(o)
end

# Build a seam over the neuro fixture: [seam, occ_map, stratum_map].
def seam_fixture(src_ord, tgt_ord, mechanism_status, chain_ords = nil)
  s = neuro
  src = occ("source_event", s[src_ord]["id"])
  tgt = occ("target_event", s[tgt_ord]["id"])
  omap = { src["id"] => src, tgt["id"] => tgt }
  smap = { s[src_ord]["id"] => s[src_ord], s[tgt_ord]["id"] => s[tgt_ord] }
  chain = nil
  unless chain_ords.nil?
    chain = []
    chain_ords.each_with_index do |o, i|
      c = occ("chain_#{i}", s[o]["id"])
      omap[c["id"]] = c
      smap[s[o]["id"]] = s[o]
      chain << c["id"]
    end
  end
  [seam(src["id"], tgt["id"], mechanism_status, chain), omap, smap]
end

# A conduit with an optional realized_by reference, completed with its id.
def conduit_realized(realized_by = nil)
  frm = "port:" + "1" * 64
  to = "port:" + "2" * 64
  x = "occurrent:" + "3" * 64
  o = { "type" => "conduit", "label" => "conn", "from" => frm, "to" => to,
        "carries" => [x] }
  o["realized_by"] = realized_by if realized_by
  mk(o)
end

# -- Change One: the ordinal (tick) temporal unit --
def v108
  p = cro([sym("occurrent:a")], [sym("occurrent:b")],
          temporal: { "minimum_delay" => 0, "maximum_delay" => 5,
                      "unit" => "ticks" },
          modality: "sufficient")
  ok, why = C.validate_schema(p)
  assert ok, why
  ok, why = C.validate_semantics(p)
  assert ok, why
end

def v109
  p = cro([sym("occurrent:a")], [sym("occurrent:b")],
          temporal: { "minimum_delay" => 2, "maximum_delay" => 5,
                      "unit" => "ticks" })
  assert C.admissible(p, 3) == true                 # 3 ticks inside [2, 5]
  assert C.admissible(p, 2) == true && C.admissible(p, 5) == true
  assert C.admissible(p, 6) == false && C.admissible(p, 1) == false
end

def v110
  tick_window = { "minimum_delay" => 0, "maximum_delay" => 5, "unit" => "ticks" }
  wall_window = { "minimum_delay" => 0, "maximum_delay" => 5, "unit" => "seconds" }
  assert C.delay_within_window({ "duration" => 3, "unit" => "ticks" },
                               tick_window) == true
  assert C.delay_within_window({ "duration" => 1, "unit" => "ticks" },
                               wall_window) == false
  assert C.delay_within_window({ "duration" => 1, "unit" => "seconds" },
                               tick_window) == false
  a = { "causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")],
        "temporal" => tick_window, "modality" => "sufficient" }
  b = { "causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")],
        "temporal" => wall_window, "modality" => "preventive" }
  assert C.conflicts(a, b) == false                 # disjoint dimensions
  begin
    C.to_seconds(1, "ticks")
    raise VectorFailure, "to_seconds accepted ticks"
  rescue ArgumentError
    # expected: an ordinal unit has no wall-clock seconds mapping
  end
end

def v111
  base = { "type" => "causal_relation_object", "causes" => [sym("occurrent:a")],
           "effects" => [sym("occurrent:b")], "modality" => "sufficient" }
  tick = base.merge("temporal" => { "minimum_delay" => 0, "maximum_delay" => 1,
                                    "unit" => "ticks" })
  secs = base.merge("temporal" => { "minimum_delay" => 0, "maximum_delay" => 1,
                                    "unit" => "seconds" })
  assert C.identify(tick) != C.identify(secs)       # the unit is identity-bearing
  # a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0 value)
  assert C.identify(secs) == "causal_relation_object:" \
         "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c"
end

# -- Change Two: the managed cross-stratal seam (eighteenth kind) --
def v112
  sm, omap, smap = seam_fixture(14, 4, "unmodeled")
  ok, why = C.validate_schema(sm)
  assert ok, why
  ok, why = C.validate_semantics(sm)
  assert ok, why
  ok, why = C.seam_wellformed(sm, omap, smap)
  assert ok, why
end

def v113
  a, = seam_fixture(14, 4, "unmodeled")
  b, omap, smap = seam_fixture(14, 4, "absent")
  ok, why = C.validate_schema(b)
  assert ok, why
  ok, why = C.seam_wellformed(b, omap, smap)
  assert ok, why
  assert a["id"] != b["id"]                          # mechanism_status is identity-bearing
end

def v114
  drawn, omap, smap = seam_fixture(14, 4, "unmodeled", [9, 7, 6, 5])
  ok, why = C.validate_schema(drawn)
  assert ok, why
  ok, why = C.seam_wellformed(drawn, omap, smap)
  assert ok, why
  bad, omap2, smap2 = seam_fixture(14, 4, "absent", [9, 7, 6, 5])
  ok, why = C.validate_semantics(bad)
  assert !ok && why.any? { |w| w.include?("contradictory_seam") }, why
  ok2, _ = C.seam_wellformed(bad, omap2, smap2)
  assert !ok2
end

def v115
  sm, omap, smap = seam_fixture(14, 4, "unmodeled")
  s = neuro
  assert C.seam_home(sm, omap, smap) == s[14]["id"]  # coarsest (max ordinal) stratum
end

def v116
  adj, o1, s1 = seam_fixture(6, 5, "unmodeled")       # adjacent (gap 1)
  ok, _ = C.seam_wellformed(adj, o1, s1)
  assert !ok
  co, o2, s2 = seam_fixture(6, 6, "unmodeled")        # co-stratal (gap 0)
  ok, _ = C.seam_wellformed(co, o2, s2)
  assert !ok
  sm, = seam_fixture(14, 4, "unmodeled")
  assert sm["id"].start_with?("cross_stratal_seam:") # a new identity scheme
end

# -- Change Three: the realized_by reference --
def v117
  c = conduit_realized("causal_relation_object:" + "a" * 64)
  ok, why = C.validate_schema(c)
  assert ok, why
  c2 = conduit_realized("native:region_stratum_predict")
  ok, why = C.validate_schema(c2)
  assert ok, why                                     # a native scheme reference is legal
end

def v118
  bound = conduit_realized("native:region_stratum_predict")
  unbound = conduit_realized
  assert bound["id"] != unbound["id"]                # realized_by is identity-bearing
  # an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0 value)
  assert unbound["id"] == "conduit:" \
         "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6"
end

def v119
  unbound = conduit_realized
  ok, why = C.validate_schema(unbound)
  assert ok, why                                     # unbound is legal
  bad = unbound.dup
  bad["realized_by"] = "not-a-scheme-qualified-reference"
  ok, _ = C.validate_schema(bad, "conduit")
  assert !ok
end

# ---------------------------------------------------------------------------
# V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
# prediction_error)
# ---------------------------------------------------------------------------
def attitude(holder, attitude_type, content)
  mk({ "type" => "attitude", "holder" => holder,
       "attitude_type" => attitude_type, "content" => content })
end

def predicted(instantiates, interval, predictor, strength: nil)
  o = { "type" => "predicted_occurrence", "instantiates" => instantiates,
        "interval" => interval, "predictor" => predictor }
  o["strength"] = strength unless strength.nil?
  mk(o)
end

def prediction_error(predicted_id, discrepancy, observed: nil)
  o = { "type" => "prediction_error", "predicted" => predicted_id,
        "discrepancy" => discrepancy }
  o["observed"] = observed if observed
  mk(o)
end

# A modeled predicting agent (a token individual), by identity.
def predictor_id
  c = cnt("forecasting_mind")
  individual(c["id"], designator: "predictor_p")["id"]
end

# A modeled believing agent (a token individual), by identity.
def believer(designator = "holder_h")
  c = cnt("believing_mind")
  individual(c["id"], designator: designator)["id"]
end

# -- Group X: prediction and prediction error (Section A) --
def v120
  o = occ("rainfall_begins")
  p = predicted(o["id"], { "start_tick" => 3, "end_tick" => 8 }, predictor_id)
  ok, why = C.validate_schema(p)
  assert ok, why
  ok, why = C.validate_semantics(p)
  assert ok, why
  assert p["id"].start_with?("predicted_occurrence:")
  report = C.identify({ "type" => "token_occurrence", "instantiates" => o["id"],
                        "interval" => { "start_tick" => 3, "end_tick" => 8 } },
                      "token_occurrence")
  assert p["id"] != report                           # a forecast is not a report
  assert report.start_with?("token_occurrence:")
end

def v121
  o = occ("rainfall_begins")
  wall = { "start" => "2026-07-23T00:00:00Z", "end" => "2026-07-24T00:00:00Z" }
  who = predictor_id
  with_strength = predicted(o["id"], wall, who, strength: 0.8)
  without = predicted(o["id"], wall, who)
  [with_strength, without].each do |p|
    ok, why = C.validate_schema(p)
    assert ok, why
    ok, why = C.validate_semantics(p)
    assert ok, why
  end
  assert with_strength["id"] != without["id"]        # strength is identity-bearing
end

def v122
  o = occ("rainfall_begins")
  bad = mk({ "type" => "predicted_occurrence", "instantiates" => o["id"],
             "interval" => { "start_tick" => 3 } })
  ok, why = C.validate_schema(bad, "predicted_occurrence")
  assert !ok && why.any? { |w| w.include?("predictor") }, why
end

def v123
  o = occ("rainfall_begins")
  both = predicted(o["id"],
                   { "start" => "2026-07-23T00:00:00Z", "start_tick" => 3 },
                   predictor_id)
  ok, why = C.validate_schema(both)
  assert ok, why
  ok, why = C.validate_semantics(both)
  assert !ok && why.any? { |w| w.include?("dimension_conflict") }, why
end

def v124
  o = occ("rainfall_begins")
  p = predicted(o["id"], { "start" => "2026-07-23T00:00:00Z" }, predictor_id)
  t = token(o["id"], { "start" => "2026-07-23T06:00:00Z" })
  err = prediction_error(p["id"], 0.0, observed: t["id"])
  ok, why = C.validate_schema(err)
  assert ok, why
  ok, why = C.validate_semantics(err)
  assert ok, why
  assert C.prediction_pairing_mismatch(err, p, t) == false
end

def v125
  o = occ("rainfall_begins")
  p = predicted(o["id"], { "start" => "2026-07-23T00:00:00Z" }, predictor_id)
  err = prediction_error(p["id"], -1.0)
  ok, why = C.validate_schema(err)
  assert ok, why
  ok, why = C.validate_semantics(err)
  assert ok, why
  assert !err.key?("observed")
  assert C.prediction_pairing_mismatch(err, p, nil) == false
end

def v126
  o = occ("rainfall_begins")
  p = predicted(o["id"], { "start_tick" => 0 }, predictor_id)
  bad = mk({ "type" => "prediction_error", "predicted" => p["id"] })
  ok, why = C.validate_schema(bad, "prediction_error")
  assert !ok && why.any? { |w| w.include?("discrepancy") }, why
end

def v127
  o = occ("rainfall_begins")
  other = occ("snowfall_begins")
  p = predicted(o["id"], { "start" => "2026-07-23T00:00:00Z" }, predictor_id)
  t = token(other["id"], { "start" => "2026-07-23T06:00:00Z" })
  err = prediction_error(p["id"], 1.0, observed: t["id"])
  ok, why = C.validate_schema(err)
  assert ok, why
  assert C.prediction_pairing_mismatch(err, p, t) == true
end

# -- Group Y: attitude and theory of mind (Section B) --
def v128
  st, = state_fixture("quantity", { "quantity" => 15.0, "unit" => "ug/dL" },
                      "ug/dL")
  att = attitude(believer, "believes", st["id"])
  ok, why = C.validate_schema(att)
  assert ok, why
  ok, why = C.validate_semantics(att)
  assert ok, why
end

def v129
  a = occ("switch_pressed")
  b = occ("light_on")
  actual = cro([a["id"]], [b["id"]], modality: "sufficient")
  believed = cro([a["id"]], [b["id"]], modality: "preventive")
  assert C.conflicts(believed, actual) == true       # the CLAIMS contradict
  att = attitude(believer, "believes", believed["id"])
  ok, why = C.validate_schema(att)
  assert ok, why
  ok, why = C.validate_semantics(att)
  assert ok, why                                     # validity unaffected
  s = C::InMemoryStore.new
  s.put(a)
  s.put(b)
  s.put(actual)
  s.put(att)
  assert s.gaps("conflict") == []                    # Rule 25: NO conflict raised
end

def v130
  o = occ("rainfall_begins")
  att = attitude(believer, "desires", o["id"])
  ok, why = C.validate_schema(att)
  assert ok, why
  ok, why = C.validate_semantics(att)
  assert ok, why
end

def v131
  o = occ("press_button")
  att = attitude(believer, "intends", o["id"])
  ok, why = C.validate_schema(att)
  assert ok, why
  ok, why = C.validate_semantics(att)
  assert ok, why
end

def v132
  st, = state_fixture("boolean", { "boolean" => true })
  inner = attitude(believer("holder_b"), "believes", st["id"])
  outer = attitude(believer("holder_a"), "believes", inner["id"])
  [inner, outer].each do |att|
    ok, why = C.validate_schema(att)
    assert ok, why
    ok, why = C.validate_semantics(att)
    assert ok, why
  end
  assert outer["id"] != inner["id"]
  assert outer["content"] == inner["id"]             # nested content
end

def v133
  o = occ("rainfall_begins")
  bad = mk({ "type" => "attitude", "holder" => believer,
             "attitude_type" => "suspects", "content" => o["id"] })
  ok, why = C.validate_schema(bad, "attitude")
  assert !ok && why.any? { |w| w.include?("attitude_type") }, why
end

def v134
  o = occ("rainfall_begins")
  bad = mk({ "type" => "attitude", "holder" => believer,
             "attitude_type" => "believes", "content" => o["id"],
             "strength" => 0.9 })
  ok, why = C.validate_schema(bad, "attitude")
  assert !ok && why.any? { |w| w.include?("strength") }, why
end

def v135
  o = occ("rainfall_begins")
  att = attitude(believer, "expects", o["id"])
  a = signed("assertion", { "about" => att["id"],
                            "evidence_type" => "observation",
                            "confidence" => 0.9 }, "signer")
  ok, why = C.validate_schema(a)
  assert ok, why
  assert C.verify_record(a) == true
  # the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
  assert att["holder"].split(":", 2)[0] == "token_individual"
  assert a["source"].split(":", 2)[0] == "ed25519"
  assert att["holder"] != a["source"]
end

def v136
  # the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
  secs = { "type" => "causal_relation_object", "causes" => [sym("occurrent:a")],
           "effects" => [sym("occurrent:b")], "modality" => "sufficient",
           "temporal" => { "minimum_delay" => 0, "maximum_delay" => 1,
                           "unit" => "seconds" } }
  assert C.identify(secs) == "causal_relation_object:" \
         "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c"
  # the V118 unbound conduit, re-pinned under 4.0.0
  unbound = conduit_realized
  assert unbound["id"] == "conduit:" \
         "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6"
end

def v137
  hexid = "0" * 64
  # NOTE: the abbreviated prefixes below are intentional (the negative test);
  # they must NOT be re-minted. Each is assembled to survive re-mint tools.
  att_abbr = "a" + "t" + "t"
  prd_abbr = "p" + "r" + "d"
  err_abbr = "e" + "r" + "r"
  bad_att = { "type" => "attitude", "id" => att_abbr + ":" + hexid,
              "holder" => "token_individual:" + hexid,
              "attitude_type" => "believes",
              "content" => "state_assertion:" + hexid }
  ok, _ = C.validate_schema(bad_att, "attitude")
  assert !ok
  bad_prd = { "type" => "predicted_occurrence", "id" => prd_abbr + ":" + hexid,
              "instantiates" => "occurrent:" + hexid,
              "interval" => { "start_tick" => 0 },
              "predictor" => "token_individual:" + hexid }
  ok, _ = C.validate_schema(bad_prd, "predicted_occurrence")
  assert !ok
  bad_err = { "type" => "prediction_error", "id" => err_abbr + ":" + hexid,
              "predicted" => "predicted_occurrence:" + hexid,
              "discrepancy" => 0.0 }
  ok, _ = C.validate_schema(bad_err, "prediction_error")
  assert !ok
  whole_att = bad_att.merge("id" => "attitude:" + hexid)
  ok, why = C.validate_schema(whole_att, "attitude")
  assert ok, why
  whole_prd = bad_prd.merge("id" => "predicted_occurrence:" + hexid)
  ok, why = C.validate_schema(whole_prd, "predicted_occurrence")
  assert ok, why
  whole_err = bad_err.merge("id" => "prediction_error:" + hexid)
  ok, why = C.validate_schema(whole_err, "prediction_error")
  assert ok, why
end

# ---------------------------------------------------------------------------
def main
  puts "causalontology-ruby conformance run (specification 4.0.0)"
  print "internal checks (RFC 8032, RFC 8785, fixed constants) ... "
  internal_checks
  puts "ok"
  failures = 0
  total = 137
  (1..total).each do |n|
    name = vec_name(n)
    begin
      send(format("v%02d", n))
      puts "PASS  #{name}"
    rescue StandardError => e
      failures += 1
      puts "FAIL  #{name} :: #{e.class}: #{e.message}"
    end
  end
  puts "-" * 60
  puts "#{total - failures}/#{total} vectors passed"
  exit 1 if failures > 0
  puts "causalontology-ruby is CONFORMANT to the suite " \
       "(vectors frozen at specification 4.0.0)."
end

main if __FILE__ == $PROGRAM_NAME

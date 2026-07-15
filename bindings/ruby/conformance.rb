#!/usr/bin/env ruby
# frozen_string_literal: false

# The Causalontology conformance runner for causalontology-ruby.
#
# Runs every vector in conformance/vectors/ against the Ruby binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure. It mirrors
# bindings/python/tests/run_conformance.py exactly.
#
# The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
# identifiers and real Ed25519 keys, which the normalization below simply
# passes through. Symbolic names still used inside this harness's own
# behavioral constructions ("occurrent:A", key "alice") are normalized
# deterministically - symbolic object ids become scheme:sha256(name), and
# symbolic key names become real Ed25519 keypairs seeded from
# sha256("key:" + name).

require "json"
require "digest"
require_relative "lib/causalontology"

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
# symbolic-identifier normalization
# ---------------------------------------------------------------------------
SYM_PREFIX = /\A(occ|cro|cnt|rlz|ast|enr|ret|suc|ed25519):/
HEX64 = /\A[0-9a-f]{64}\z/
KEYS = {}

# A real, deterministic Ed25519 keypair for a symbolic key name.
def key(name)
  KEYS[name] ||= begin
    seed = Digest::SHA256.digest("key:" + name)
    Causalontology.keypair_from_seed(seed)
  end
end

# Normalize one symbolic identifier to a well-formed one.
def sym(s)
  scheme, name = s.split(":", 2)
  if scheme == "ed25519"
    return s if name.match?(HEX64) # frozen: a real key passes through
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
    return sym(x) if x.match?(SYM_PREFIX)
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
  Causalontology.sign_record(rec, secret, kind)
end

# ---------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# ---------------------------------------------------------------------------
def internal_checks
  # RFC 8032, TEST 1 known-answer
  sk = ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"].pack("H*")
  pk = Causalontology::Ed25519.secret_to_public(sk)
  assert pk.unpack1("H*") ==
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         pk.unpack1("H*")
  sig = Causalontology::Ed25519.sign(sk, "")
  assert Causalontology::Ed25519.verify(pk, "", sig)
  assert !Causalontology::Ed25519.verify(pk, "x", sig)
  # JCS basics
  assert Causalontology::Jcs.encode({ "b" => 2, "a" => 1 }) == '{"a":1,"b":2}'
  assert Causalontology::Jcs.encode(1.0) == "1"
  assert Causalontology::Jcs.encode(6.000) == "6"
  assert Causalontology::Jcs.encode(0.7) == "0.7"
end

# ---------------------------------------------------------------------------
# the 38 vectors
# ---------------------------------------------------------------------------
def v01
  inp = normalize(vec(1)["input"])
  ok, why = Causalontology.validate_schema(inp)
  assert ok, why
  ok, why = Causalontology.validate_semantics(inp)
  assert ok, why
end

def v02
  inp = normalize(vec(2)["input"])
  ok, _why = Causalontology.validate_schema(inp)
  assert ok
  ok, _why = Causalontology.validate_semantics(inp)
  assert ok
  partial, missing = Causalontology.is_partial(inp)
  assert partial && missing == vec(2)["expect"]["missing"], missing
end

def schema_fails(n, must_mention)
  inp = normalize(vec(n)["input"])
  ok, why = Causalontology.validate_schema(inp)
  assert !ok, "expected schema-invalid"
  assert why.any? { |w| w.include?(must_mention) }, why
end

def v03; schema_fails(3, "effects"); end
def v04; schema_fails(4, "causes"); end
def v05; schema_fails(5, "modality"); end
def v06; schema_fails(6, "colour"); end
def v07; schema_fails(7, "causes"); end

def v08
  ok, why = Causalontology.validate_schema(normalize(vec(8)["input"]))
  assert ok, why
end

def v09; schema_fails(9, "label"); end
def v10; schema_fails(10, "category"); end

def v11
  ok, why = Causalontology.validate_schema(normalize(vec(11)["input"]))
  assert ok, why
end

def v12; schema_fails(12, "confidence"); end

def v13
  inp = normalize(vec(13)["input"])
  ok, why = Causalontology.validate_schema(inp)
  assert ok, why
  ok, why = Causalontology.validate_semantics(inp)
  assert ok, why
end

def semantics_fails(n, must_mention)
  inp = normalize(vec(n)["input"])
  ok, why = Causalontology.validate_semantics(inp)
  assert !ok, "expected semantically-invalid"
  assert why.any? { |w| w.include?(must_mention) }, why
end

def v14
  inp = normalize(vec(14)["input"])
  ok, _why = Causalontology.validate_schema(inp)
  assert ok
  semantics_fails(14, "minimum_delay")
end

def v15; semantics_fails(15, "acyclic"); end
def v16; semantics_fails(16, "acyclic"); end

def v17
  v = vec(17)
  parent = normalize(v["given"]["parent"])
  child = normalize(v["input"])
  ok, reason = Causalontology.refinement_valid(child, parent)
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
  # enforcing tier rejects the cycle-completing write
  s = Causalontology::InMemoryStore.new(enforcing: true)
  s.put_record(enrich.call(dog, mam, 1))
  s.put_record(enrich.call(mam, ani, 2))
  begin
    s.put_record(enrich.call(ani, dog, 3))
    raise VectorFailure, "enforcing store accepted a cycle"
  rescue Causalontology::RejectedWrite => e
    assert e.message.include?("cycle"), e.message
  end
  # decentralized merge: the view breaks the cycle deterministically
  s2 = Causalontology::InMemoryStore.new(enforcing: true)
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
  cro = { "causes" => [sym("occurrent:c")], "effects" => [sym("occurrent:e")],
          "temporal" => g["temporal"] }
  Causalontology.admissible(cro, g["elapsed_seconds"])
end

def v21; assert adm(21) == true; end
def v22; assert adm(22) == false; end
def v23; assert adm(23) == true; end

def v24
  v = vec(24)
  assert Causalontology.identify(normalize(v["inputA"])) ==
         Causalontology.identify(normalize(v["inputB"]))
end

def v25
  v = vec(25)
  assert Causalontology.identify(normalize(v["inputA"])) ==
         Causalontology.identify(normalize(v["inputB"]))
end

def v26
  s = Causalontology::InMemoryStore.new
  obj = { "type" => "occurrent", "label" => "press_button",
          "category" => "action" }
  a = s.put(obj.dup)
  b = s.put(obj.dup)
  assert a == b && s.objects.length == 1
end

def v27
  s = Causalontology::InMemoryStore.new
  occ = s.put({ "type" => "occurrent", "label" => "press_button",
                "category" => "action" })
  entry = { "lang" => "en", "text" => "press the button" }
  r1 = signed("enrichment", { "about" => occ, "field" => "aliases",
                              "entry" => entry }, "alice", 1)
  r2 = signed("enrichment", { "about" => occ, "field" => "aliases",
                              "entry" => entry }, "bob", 2)
  assert s.put_record(r1) != s.put_record(r2) # two records
  view = s.get(occ)["enrichments"]["aliases"]
  assert view.length == 1 && view[0]["contributors"].length == 2
end

def v28
  s = Causalontology::InMemoryStore.new
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
  assert Causalontology.verify_record(rec) == true
end

def v30
  rec = signed("assertion", { "about" => sym("causal_relation_object:demo"),
                              "evidence_type" => "intervention",
                              "strength" => 0.7, "confidence" => 0.9 }, "signer")
  tampered = rec.merge("confidence" => 0.1)
  assert Causalontology.verify_record(tampered) == false
end

def v31
  s = Causalontology::InMemoryStore.new
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
  rescue Causalontology::RejectedWrite
    # expected: only the source or its lineage may retract
  end
  assert s.assertions_about(x) == [] # still excluded by lab1's own
  assert s.assertions_about(x, include_retracted: true).length == 1
end

def v32
  s = Causalontology::InMemoryStore.new
  occ = s.put({ "type" => "occurrent", "label" => "press_button",
                "category" => "action" })
  e = signed("enrichment", { "about" => occ, "field" => "aliases",
                             "entry" => { "lang" => "ja", "text" => "botan" } },
             "bob", 1)
  s.put_record(e)
  before = s.get(occ)["enrichments"]["aliases"] || []
  assert before.length == 1
  s.put_record(signed("retraction", { "retracts" => e["id"] }, "bob", 2))
  after = s.get(occ)["enrichments"]["aliases"] || []
  assert after == []
  hist = s.get(occ, view: "history")["enrichments"]["aliases"] || []
  assert hist.length == 1
end

def v33
  s = Causalontology::InMemoryStore.new
  k1 = key("K1")[1]
  k2 = key("K2")[1]
  a = signed("assertion", { "about" => sym("causal_relation_object:claim"),
                            "evidence_type" => "observation",
                            "confidence" => 0.9 }, "K1", 1)
  s.put_record(a)
  succ = signed("succession", { "successor" => k2 }, "K1", 2)
  s.put_record(succ)
  assert s.lineage(k2).include?(k1) && s.lineage(k1).include?(k2)
  r = signed("retraction", { "retracts" => a["id"] }, "K2", 3)
  s.put_record(r) # successor may retract the predecessor's record
  assert s.assertions_about(sym("causal_relation_object:claim")) == []
end

def v34
  g = normalize(vec(34)["given"])
  assert Causalontology.conflicts(g["A"], g["B"]) == true
end

def v35
  g = normalize(vec(35)["given"])
  assert Causalontology.conflicts(g["A"], g["B"]) == false
end

def v36
  a = sym("occurrent:A")
  b = sym("occurrent:B")
  c = sym("occurrent:C")
  d = sym("occurrent:D")
  m1 = { "id" => sym("causal_relation_object:m1"), "causes" => [a], "effects" => [b] }
  m2 = { "id" => sym("causal_relation_object:m2"), "causes" => [b], "effects" => [c] }
  m3 = { "id" => sym("causal_relation_object:m3"), "causes" => [d], "effects" => [c] }
  parent = { "causes" => [a], "effects" => [c],
             "mechanism" => [m1["id"], m2["id"]] }
  assert Causalontology.hierarchy_consistent(
    parent, { m1["id"] => m1, m2["id"] => m2 }) == "consistent"
  parent2 = parent.merge("mechanism" => [m1["id"], m3["id"]])
  assert Causalontology.hierarchy_consistent(
    parent2, { m1["id"] => m1, m3["id"] => m3 }) == "inconsistent"
  assert Causalontology.hierarchy_consistent(
    parent, { m1["id"] => m1 }) == "indeterminate"
end

def v37
  s = Causalontology::InMemoryStore.new
  occ = s.put({ "type" => "occurrent", "label" => "press_button",
                "category" => "action" })
  s.put_record(signed("enrichment",
                      { "about" => occ, "field" => "aliases",
                        "entry" => { "lang" => "en",
                                     "text" => "Press the Button" } },
                      "alice", 1))
  assert s.resolve("Press  The   Button", "en") == [occ] # alias match
  assert s.resolve("press_button", "en")[0] == occ       # label, first
end

def v38
  s = Causalontology::InMemoryStore.new
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
def main
  puts "causalontology-ruby conformance run"
  print "internal checks (RFC 8032 known-answer, RFC 8785 basics) ... "
  internal_checks
  puts "ok"
  failures = 0
  (1..38).each do |n|
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
  puts "#{38 - failures}/38 vectors passed"
  exit 1 if failures > 0
  puts "causalontology-ruby is CONFORMANT to the suite " \
       "(vectors frozen at specification 1.0.0)."
end

main if __FILE__ == $PROGRAM_NAME

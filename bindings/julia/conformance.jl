#!/usr/bin/env julia
# The Causalontology conformance runner for causalontology-julia.
#
# Runs every vector in conformance/vectors/ against the Julia binding.  An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure.  Mirrors
# bindings/python/tests/run_conformance.py exactly.
#
# The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
# identifiers and real Ed25519 keys, which pass through unchanged.  The
# behavioral vectors derive deterministic keypairs from the seed
# sha256("key:" + name).

include(joinpath(@__DIR__, "src", "Causalontology.jl"))

using .Causalontology
using SHA

const CO = Causalontology
const ROOT = normpath(joinpath(@__DIR__, "..", ".."))
const VECDIR = joinpath(ROOT, "conformance", "vectors")

# ---------------------------------------------------------------------------
# symbolic-identifier normalization (frozen values pass through unchanged)
# ---------------------------------------------------------------------------
const _SCHEMES = ("occurrent", "causal_relation_object", "continuant", "realizable", "assertion", "enrichment", "retraction", "succession")
const _KEYS = Dict{String,Tuple{Vector{UInt8},String}}()
const _HEX64 = r"^[0-9a-f]{64}$"
const _SYM_RE = Regex("^(" * join(vcat(collect(_SCHEMES), ["ed25519"]), "|") *
                      "):")

"A real, deterministic Ed25519 keypair for a symbolic key name."
function key(name::String)
    get!(_KEYS, name) do
        seed = sha256(Vector{UInt8}(codeunits("key:" * name)))
        keypair_from_seed(seed)
    end
end

"Normalize one symbolic identifier to a well-formed one."
function sym(s::String)
    idx = findfirst(':', s)
    scheme, name = s[1:idx-1], s[idx+1:end]
    if scheme == "ed25519"
        occursin(_HEX64, name) && return s  # frozen: a real key passes through
        return key(name)[2]
    end
    occursin(_HEX64, name) && return s
    return scheme * ":" * bytes2hex(sha256(Vector{UInt8}(codeunits(name))))
end

"Recursively normalize symbolic identifiers and placeholders."
normalize(x) = x
normalize(x::String) =
    x == "<128 hex>" ? "ab"^64 : (occursin(_SYM_RE, x) ? sym(x) : x)
normalize(x::AbstractVector) = Any[normalize(v) for v in x]
function normalize(x::JObj)
    o = JObj()
    for (k, v) in x.pairs
        jset!(o, k, normalize(v))
    end
    return o
end

"The filenames of vector n (exactly one)."
function _vec_hits(n::Int)
    prefix = "v" * lpad(n, 2, '0') * "_"
    hits = [f for f in readdir(VECDIR)
            if startswith(f, prefix) && endswith(f, ".json")]
    length(hits) == 1 || error("vector $n not found")
    return hits
end

"Load vector n's JSON file (for its structured inputs)."
vec(n::Int) = json_parse(read(joinpath(VECDIR, _vec_hits(n)[1]), String))

vecstem(n::Int) = replace(_vec_hits(n)[1], ".json" => "")

ts(i::Int) = "2026-07-13T0$(i):00:00Z"

"Build, timestamp, and sign a provenance record."
function signed(kind::String, body::JObj, who::String, ts_i::Int=0)
    secret, pub = key(who)
    rec = jcopy(body)
    jset!(rec, "type", kind)
    jsetdefault!(rec, "timestamp", ts(ts_i))
    if kind == "succession"
        jsetdefault!(rec, "predecessor", pub)
    else
        jset!(rec, "source", pub)
    end
    return sign_record(rec, secret, kind)
end

check(cond::Bool, msg="check failed") = cond ? nothing : error(string(msg))

# ---------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# ---------------------------------------------------------------------------
function internal_checks()
    # RFC 8032, TEST 1 known-answer: the gate before any vector
    sk = hex2bytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = CO.Ed25519.secret_to_public(sk)
    check(bytes2hex(pk) == ("d75a980182b10ab7d54bfed3c964073a" *
                            "0ee172f3daa62325af021a68f707511a"),
          "RFC 8032 TEST 1 public key mismatch: " * bytes2hex(pk))
    sig = CO.Ed25519.sign(sk, UInt8[])
    check(bytes2hex(sig) == ("e5564300c360ac729086e2cc806e828a" *
                             "84877f1eb8e5d974d873e06522490155" *
                             "5fb8821590a33bacc61e39701cf9b46b" *
                             "d25bf5f0595bbe24655141438e7a100b"),
          "RFC 8032 TEST 1 signature mismatch: " * bytes2hex(sig))
    check(CO.Ed25519.verify(pk, UInt8[], sig),
          "RFC 8032 TEST 1 signature must verify")
    check(!CO.Ed25519.verify(pk, Vector{UInt8}(codeunits("x")), sig),
          "RFC 8032 TEST 1 wrong message must be rejected")
    # JCS basics
    check(CO._jcs(jobj("b" => 2, "a" => 1)) == "{\"a\":1,\"b\":2}",
          "JCS key sorting")
    check(CO._jcs(1.0) == "1" && CO._jcs(6.000) == "6" &&
          CO._jcs(0.7) == "0.7", "JCS number forms")
end

# ---------------------------------------------------------------------------
# the 38 vectors
# ---------------------------------------------------------------------------
function v01()
    inp = normalize(vec(1)["input"])
    ok, why = validate_schema(inp); check(ok, join(why, "; "))
    ok, why = validate_semantics(inp); check(ok, join(why, "; "))
end

function v02()
    inp = normalize(vec(2)["input"])
    ok, _ = validate_schema(inp); check(ok)
    ok, _ = validate_semantics(inp); check(ok)
    partial, missing_fields = is_partial(inp)
    check(partial && missing_fields == jget(vec(2)["expect"], "missing"),
          join(missing_fields, ", "))
end

function _schema_fails(n, must_mention)
    inp = normalize(vec(n)["input"])
    ok, why = validate_schema(inp)
    check(!ok, "expected schema-invalid")
    check(any(w -> occursin(must_mention, w), why), join(why, "; "))
end

v03() = _schema_fails(3, "effects")
v04() = _schema_fails(4, "causes")
v05() = _schema_fails(5, "modality")
v06() = _schema_fails(6, "colour")
v07() = _schema_fails(7, "causes")

function v08()
    ok, why = validate_schema(normalize(vec(8)["input"]))
    check(ok, join(why, "; "))
end

v09() = _schema_fails(9, "label")
v10() = _schema_fails(10, "category")

function v11()
    ok, why = validate_schema(normalize(vec(11)["input"]))
    check(ok, join(why, "; "))
end

v12() = _schema_fails(12, "confidence")

function v13()
    inp = normalize(vec(13)["input"])
    ok, why = validate_schema(inp); check(ok, join(why, "; "))
    ok, why = validate_semantics(inp); check(ok, join(why, "; "))
end

function _semantics_fails(n, must_mention)
    inp = normalize(vec(n)["input"])
    ok, why = validate_semantics(inp)
    check(!ok, "expected semantically-invalid")
    check(any(w -> occursin(must_mention, w), why), join(why, "; "))
end

function v14()
    inp = normalize(vec(14)["input"])
    ok, _ = validate_schema(inp); check(ok)
    _semantics_fails(14, "minimum_delay")
end

v15() = _semantics_fails(15, "acyclic")
v16() = _semantics_fails(16, "acyclic")

function v17()
    v = vec(17)
    parent = normalize(jget(v["given"], "parent"))
    child = normalize(v["input"])
    ok, reason = refinement_valid(child, parent)
    check(!ok && occursin("rival", reason), reason)
end

v18() = _semantics_fails(18, "not a legal field")
v19() = _semantics_fails(19, "language-tagged")

function v20()
    dog, mam, ani = sym("continuant:dog"), sym("continuant:mammal"), sym("continuant:animal")
    enrich(about, entry, i) = signed(
        "enrichment",
        jobj("about" => about, "field" => "subsumes", "entry" => entry),
        "taxo", i)
    # enforcing tier rejects the cycle-completing write
    s = InMemoryStore(enforcing=true)
    put_record(s, enrich(dog, mam, 1))
    put_record(s, enrich(mam, ani, 2))
    threw = false
    try
        put_record(s, enrich(ani, dog, 3))
    catch e
        e isa RejectedWrite || rethrow()
        check(occursin("cycle", e.msg), e.msg)
        threw = true
    end
    check(threw, "enforcing store accepted a cycle")
    # decentralized merge: the view breaks the cycle deterministically
    s2 = InMemoryStore(enforcing=true)
    put_record(s2, enrich(dog, mam, 1))
    put_record(s2, enrich(mam, ani, 2))
    bad = enrich(ani, dog, 3)
    force_merge_record(s2, bad)
    active, excluded = CO._active_taxonomy_edges(s2, "subsumes")
    check(length(excluded) == 1 && excluded[1]["id"] == bad["id"])
    repair = gaps(s2; kind="inconsistent_hierarchy")
    check(any(g -> g["id"] == bad["id"], repair))
end

function _adm(n)
    g = vec(n)["given"]
    cro = jobj("causes" => Any[sym("occurrent:c")], "effects" => Any[sym("occurrent:e")],
               "temporal" => g["temporal"])
    return admissible(cro, jget(g, "elapsed_seconds"))
end

v21() = check(_adm(21) === true)
v22() = check(_adm(22) === false)
v23() = check(_adm(23) === true)

function v24()
    v = vec(24)
    check(identify(normalize(v["inputA"])) == identify(normalize(v["inputB"])))
end

function v25()
    v = vec(25)
    check(identify(normalize(v["inputA"])) == identify(normalize(v["inputB"])))
end

function v26()
    s = InMemoryStore()
    obj = jobj("type" => "occurrent", "label" => "press_button",
               "category" => "action")
    a = put(s, jcopy(obj))
    b = put(s, jcopy(obj))
    check(a == b && length(s.objects) == 1)
end

function v27()
    s = InMemoryStore()
    occ = put(s, jobj("type" => "occurrent", "label" => "press_button",
                      "category" => "action"))
    entry = jobj("lang" => "en", "text" => "press the button")
    r1 = signed("enrichment", jobj("about" => occ, "field" => "aliases",
                                   "entry" => entry), "alice", 1)
    r2 = signed("enrichment", jobj("about" => occ, "field" => "aliases",
                                   "entry" => entry), "bob", 2)
    check(put_record(s, r1) != put_record(s, r2))  # two records
    view = getobj(s, occ)["enrichments"]["aliases"]
    check(length(view) == 1 && length(view[1]["contributors"]) == 2)
end

function v28()
    s = InMemoryStore()
    claim = jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                 "effects" => Any[sym("occurrent:B")], "modality" => "sufficient")
    i1 = put(s, jcopy(claim))
    i2 = put(s, jcopy(claim))
    check(i1 == i2 && length(s.objects) == 1)
    for (who, tsi) in (("lab1", 1), ("lab2", 2))
        put_record(s, signed(
            "assertion",
            jobj("about" => i1, "evidence_type" => "observation",
                 "strength" => 0.8, "confidence" => 0.8), who, tsi))
    end
    check(length(assertions_about(s, i1)) == 2)
end

function v29()
    rec = signed("assertion",
                 jobj("about" => sym("causal_relation_object:demo"),
                      "evidence_type" => "intervention",
                      "strength" => 0.7, "confidence" => 0.9), "signer")
    check(verify_record(rec) === true)
end

function v30()
    rec = signed("assertion",
                 jobj("about" => sym("causal_relation_object:demo"),
                      "evidence_type" => "intervention",
                      "strength" => 0.7, "confidence" => 0.9), "signer")
    tampered = jcopy(rec)
    jset!(tampered, "confidence", 0.1)
    check(verify_record(tampered) === false)
end

function v31()
    s = InMemoryStore()
    x = put(s, jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                    "effects" => Any[sym("occurrent:B")]))
    a = signed("assertion",
               jobj("about" => x, "evidence_type" => "observation",
                    "confidence" => 0.8), "lab1", 1)
    put_record(s, a)
    put_record(s, signed("retraction", jobj("retracts" => a["id"]),
                         "lab1", 2))
    check(isempty(assertions_about(s, x)))
    hist = assertions_about(s, x; include_retracted=true)
    check(length(hist) == 1 && hist[1]["retracted"] === true)
    foreign = signed("retraction", jobj("retracts" => a["id"]), "mallory", 3)
    threw = false
    try
        put_record(s, foreign)
    catch e
        e isa RejectedWrite || rethrow()
        threw = true
    end
    check(threw, "foreign retraction accepted")
    check(isempty(assertions_about(s, x)))    # still excluded by lab1's own
    check(length(assertions_about(s, x; include_retracted=true)) == 1)
end

function v32()
    s = InMemoryStore()
    occ = put(s, jobj("type" => "occurrent", "label" => "press_button",
                      "category" => "action"))
    e = signed("enrichment",
               jobj("about" => occ, "field" => "aliases",
                    "entry" => jobj("lang" => "ja", "text" => "botan")),
               "bob", 1)
    put_record(s, e)
    check(length(jget(getobj(s, occ)["enrichments"], "aliases", Any[])) == 1)
    put_record(s, signed("retraction", jobj("retracts" => e["id"]), "bob", 2))
    check(isempty(jget(getobj(s, occ)["enrichments"], "aliases", Any[])))
    hist = jget(getobj(s, occ; view="history")["enrichments"],
                "aliases", Any[])
    check(length(hist) == 1)
end

function v33()
    s = InMemoryStore()
    _, k1 = key("K1")
    _, k2 = key("K2")
    a = signed("assertion",
               jobj("about" => sym("causal_relation_object:claim"),
                    "evidence_type" => "observation",
                    "confidence" => 0.9), "K1", 1)
    put_record(s, a)
    succ = signed("succession", jobj("successor" => k2), "K1", 2)
    put_record(s, succ)
    check(k1 in lineage(s, k2) && k2 in lineage(s, k1))
    r = signed("retraction", jobj("retracts" => a["id"]), "K2", 3)
    put_record(s, r)  # successor may retract the predecessor's record
    check(isempty(assertions_about(s, sym("causal_relation_object:claim"))))
end

function v34()
    g = normalize(vec(34)["given"])
    check(conflicts(g["A"], g["B"]) === true)
end

function v35()
    g = normalize(vec(35)["given"])
    check(conflicts(g["A"], g["B"]) === false)
end

function v36()
    A, B, C, D = sym("occurrent:A"), sym("occurrent:B"), sym("occurrent:C"), sym("occurrent:D")
    m1 = jobj("id" => sym("causal_relation_object:m1"), "causes" => Any[A], "effects" => Any[B])
    m2 = jobj("id" => sym("causal_relation_object:m2"), "causes" => Any[B], "effects" => Any[C])
    m3 = jobj("id" => sym("causal_relation_object:m3"), "causes" => Any[D], "effects" => Any[C])
    P = jobj("causes" => Any[A], "effects" => Any[C],
             "mechanism" => Any[m1["id"], m2["id"]])
    check(hierarchy_consistent(
        P, Dict{Any,Any}(m1["id"] => m1, m2["id"] => m2)) == "consistent")
    P2 = jcopy(P)
    jset!(P2, "mechanism", Any[m1["id"], m3["id"]])
    check(hierarchy_consistent(
        P2, Dict{Any,Any}(m1["id"] => m1, m3["id"] => m3)) == "inconsistent")
    check(hierarchy_consistent(
        P, Dict{Any,Any}(m1["id"] => m1)) == "indeterminate")
end

function v37()
    s = InMemoryStore()
    occ = put(s, jobj("type" => "occurrent", "label" => "press_button",
                      "category" => "action"))
    put_record(s, signed(
        "enrichment",
        jobj("about" => occ, "field" => "aliases",
             "entry" => jobj("lang" => "en", "text" => "Press the Button")),
        "alice", 1))
    check(resolve(s, "Press  The   Button", "en") == [occ])  # alias match
    check(resolve(s, "press_button", "en")[1] == occ)        # label, first
end

function v38()
    s = InMemoryStore()
    P = put(s, jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                    "effects" => Any[sym("occurrent:B")]))
    gap_ids = [g["id"] for g in gaps(s; kind="missing_field")]
    check(P in gap_ids)
    R = put(s, jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                    "effects" => Any[sym("occurrent:B")],
                    "temporal" => jobj("minimum_delay" => 0, "maximum_delay" => 1,
                                       "unit" => "seconds"),
                    "modality" => "sufficient", "refines" => P))
    gap_ids = [g["id"] for g in gaps(s; kind="missing_field")]
    check(!(P in gap_ids), "the gap did not close")
    check(!(R in gap_ids), "the refinement itself must be complete")
end

# ---------------------------------------------------------------------------
const VFUNCS = Function[
    v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
    v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
    v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
    v31, v32, v33, v34, v35, v36, v37, v38,
]

function main()
    println("causalontology-julia conformance run")
    print("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
    internal_checks()
    println("ok")
    failures = 0
    for n in 1:38
        name = vecstem(n)
        try
            VFUNCS[n]()
            println("PASS  $name")
        catch err
            failures += 1
            println("FAIL  $name :: $(sprint(showerror, err))")
        end
    end
    println(repeat("-", 60))
    println("$(38 - failures)/38 vectors passed")
    failures > 0 && exit(1)
    println("causalontology-julia is CONFORMANT to the suite " *
            "(vectors frozen at specification 1.0.0).")
end

main()

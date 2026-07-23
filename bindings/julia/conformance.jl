#!/usr/bin/env julia
# The Causalontology conformance runner for causalontology-julia (spec 4.0.0).
#
# Runs every vector in conformance/vectors/ against the Julia binding.  An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure.  Mirrors
# bindings/python/tests/run_conformance.py exactly: V01-V38 are the whole-word
# re-freeze of the 1.0.0 suite (unaltered in meaning), V39-V107 are the 2.0.0
# additions, V108-V119 are the 3.0.0 additions (the ticks unit, the
# cross_stratal_seam, the conduit realized_by), and V120-V137 are the 4.0.0
# additions (the attitude, the predicted_occurrence, the prediction_error).

include(joinpath(@__DIR__, "src", "Causalontology.jl"))

using .Causalontology
using SHA

const CO = Causalontology
const ROOT = normpath(joinpath(@__DIR__, "..", ".."))
const VECDIR = joinpath(ROOT, "conformance", "vectors")

# ---------------------------------------------------------------------------
# whole-word scheme normalization (Principle P7)
# ---------------------------------------------------------------------------
const _SCHEMES = ("occurrent", "causal_relation_object", "continuant",
                  "realizable", "assertion", "enrichment", "retraction",
                  "succession", "stratum", "bridge", "cross_stratal_seam",
                  "port", "conduit",
                  "quality", "token_individual", "token_occurrence",
                  "state_assertion", "token_causal_claim",
                  "attitude", "predicted_occurrence", "prediction_error")
const WHOLE_WORD = Set{String}(vcat(collect(_SCHEMES), ["ed25519"]))
const _KEYS = Dict{String,Tuple{Vector{UInt8},String}}()
const _HEX64 = r"^[0-9a-f]{64}$"
const _SYM_RE = Regex("^(" * join(vcat(collect(_SCHEMES), ["ed25519"]), "|") * "):")

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

"A content object completed with its real content-addressed id."
function mk(obj::JObj)
    o = jcopy(obj)
    jset!(o, "id", identify(o))
    return o
end

_setkw!(o::JObj, kw) = (for (k, v) in kw; jset!(o, String(k), v); end; o)

check(cond::Bool, msg="check failed") = cond ? nothing : error(string(msg))

# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------
function stratum(label, scheme, ordinal, unit=nothing, governs=nothing)
    o = jobj("type" => "stratum", "label" => label, "scheme" => scheme,
             "ordinal" => ordinal)
    unit !== nothing && jset!(o, "unit", unit)
    governs !== nothing && jset!(o, "governs", governs)
    return mk(o)
end

function occ(label, stratum_id=nothing, category="event")
    o = jobj("type" => "occurrent", "label" => label, "category" => category)
    stratum_id !== nothing && jset!(o, "stratum", stratum_id)
    return mk(o)
end

cnt(label, category="object") =
    mk(jobj("type" => "continuant", "label" => label, "category" => category))

function cro(causes, effects; kw...)
    o = jobj("type" => "causal_relation_object", "causes" => causes,
             "effects" => effects)
    _setkw!(o, kw)
    return mk(o)
end

bridge(coarse, fine, relation) =
    mk(jobj("type" => "bridge", "coarse" => coarse, "fine" => fine,
            "relation" => relation))

function port(bearer, label, direction, accepts, realizable=nothing)
    o = jobj("type" => "port", "bearer" => bearer, "label" => label,
             "direction" => direction, "accepts" => accepts)
    realizable !== nothing && jset!(o, "realizable", realizable)
    return mk(o)
end

function conduit(frm, to, carries; label="conn", transform=nothing)
    o = jobj("type" => "conduit", "label" => label, "from" => frm,
             "to" => to, "carries" => carries)
    transform !== nothing && jset!(o, "transform", transform)
    return mk(o)
end

function quality(label, datatype, unit=nothing, stratum_id=nothing)
    o = jobj("type" => "quality", "label" => label, "datatype" => datatype)
    unit !== nothing && jset!(o, "unit", unit)
    stratum_id !== nothing && jset!(o, "stratum", stratum_id)
    return mk(o)
end

function individual(instantiates; designator=nothing, part_of=nothing)
    o = jobj("type" => "token_individual", "instantiates" => instantiates)
    designator !== nothing && jset!(o, "designator", designator)
    part_of !== nothing && jset!(o, "part_of", part_of)
    return mk(o)
end

function token(instantiates, interval; participants=nothing, locus=nothing)
    o = jobj("type" => "token_occurrence", "instantiates" => instantiates,
             "interval" => interval)
    participants !== nothing && jset!(o, "participants", participants)
    locus !== nothing && jset!(o, "locus", locus)
    return mk(o)
end

state(subject, qual, value, interval) =
    mk(jobj("type" => "state_assertion", "subject" => subject,
            "quality" => qual, "value" => value, "interval" => interval))

function tcc(causes, effects; covering_law=nothing, actual_delay=nothing,
             counterfactual=nothing)
    o = jobj("type" => "token_causal_claim", "causes" => causes,
             "effects" => effects)
    covering_law !== nothing && jset!(o, "covering_law", covering_law)
    actual_delay !== nothing && jset!(o, "actual_delay", actual_delay)
    counterfactual !== nothing && jset!(o, "counterfactual", counterfactual)
    return mk(o)
end

# ---------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# ---------------------------------------------------------------------------
function internal_checks()
    sk = hex2bytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = CO.Ed25519.secret_to_public(sk)
    check(bytes2hex(pk) == ("d75a980182b10ab7d54bfed3c964073a" *
                            "0ee172f3daa62325af021a68f707511a"),
          "RFC 8032 TEST 1 public key mismatch: " * bytes2hex(pk))
    sig = CO.Ed25519.sign(sk, UInt8[])
    check(CO.Ed25519.verify(pk, UInt8[], sig),
          "RFC 8032 TEST 1 signature must verify")
    check(CO._jcs(jobj("b" => 2, "a" => 1)) == "{\"a\":1,\"b\":2}",
          "JCS key sorting")
    check(CO._jcs(1.0) == "1" && CO._jcs(6.000) == "6" &&
          CO._jcs(0.7) == "0.7", "JCS number forms")
    check(to_seconds(1, "months") == 2629746, "months constant")
    check(to_seconds(1, "years") == 31556952, "years constant")
end

# ===========================================================================
# V01 - V38: the whole-word re-freeze of the 1.0.0 suite (unaltered in meaning)
# ===========================================================================
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

v08() = begin ok, why = validate_schema(normalize(vec(8)["input"])); check(ok, join(why, "; ")) end

v09() = _schema_fails(9, "label")
v10() = _schema_fails(10, "category")

v11() = begin ok, why = validate_schema(normalize(vec(11)["input"])); check(ok, join(why, "; ")) end

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
        jobj("about" => about, "field" => "subsumes", "entry" => entry), "taxo", i)
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
    c = jobj("causes" => Any[sym("occurrent:c")], "effects" => Any[sym("occurrent:e")],
             "temporal" => g["temporal"])
    return admissible(c, jget(g, "elapsed_seconds"))
end

v21() = check(_adm(21) === true)
v22() = check(_adm(22) === false)
v23() = check(_adm(23) === true)

v24() = begin v = vec(24); check(identify(normalize(v["inputA"])) == identify(normalize(v["inputB"]))) end
v25() = begin v = vec(25); check(identify(normalize(v["inputA"])) == identify(normalize(v["inputB"]))) end

function v26()
    s = InMemoryStore()
    obj = jobj("type" => "occurrent", "label" => "press_button", "category" => "action")
    check(put(s, jcopy(obj)) == put(s, jcopy(obj)) && length(s.objects) == 1)
end

function v27()
    s = InMemoryStore()
    occid = put(s, jobj("type" => "occurrent", "label" => "press_button", "category" => "action"))
    entry = jobj("lang" => "en", "text" => "press the button")
    r1 = signed("enrichment", jobj("about" => occid, "field" => "aliases", "entry" => entry), "alice", 1)
    r2 = signed("enrichment", jobj("about" => occid, "field" => "aliases", "entry" => entry), "bob", 2)
    check(put_record(s, r1) != put_record(s, r2))
    view = getobj(s, occid)["enrichments"]["aliases"]
    check(length(view) == 1 && length(view[1]["contributors"]) == 2)
end

function v28()
    s = InMemoryStore()
    claim = jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                 "effects" => Any[sym("occurrent:B")], "modality" => "sufficient")
    i1 = put(s, jcopy(claim)); i2 = put(s, jcopy(claim))
    check(i1 == i2 && length(s.objects) == 1)
    for (who, tsi) in (("lab1", 1), ("lab2", 2))
        put_record(s, signed("assertion",
            jobj("about" => i1, "evidence_type" => "observation",
                 "strength" => 0.8, "confidence" => 0.8), who, tsi))
    end
    check(length(assertions_about(s, i1)) == 2)
end

function v29()
    rec = signed("assertion", jobj("about" => sym("causal_relation_object:demo"),
        "evidence_type" => "intervention", "strength" => 0.7, "confidence" => 0.9), "signer")
    check(verify_record(rec) === true)
end

function v30()
    rec = signed("assertion", jobj("about" => sym("causal_relation_object:demo"),
        "evidence_type" => "intervention", "strength" => 0.7, "confidence" => 0.9), "signer")
    tampered = jcopy(rec); jset!(tampered, "confidence", 0.1)
    check(verify_record(tampered) === false)
end

function v31()
    s = InMemoryStore()
    x = put(s, jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                    "effects" => Any[sym("occurrent:B")]))
    a = signed("assertion", jobj("about" => x, "evidence_type" => "observation",
                                 "confidence" => 0.8), "lab1", 1)
    put_record(s, a)
    put_record(s, signed("retraction", jobj("retracts" => a["id"]), "lab1", 2))
    check(isempty(assertions_about(s, x)))
    hist = assertions_about(s, x; include_retracted=true)
    check(length(hist) == 1 && hist[1]["retracted"] === true)
    threw = false
    try
        put_record(s, signed("retraction", jobj("retracts" => a["id"]), "mallory", 3))
    catch e
        e isa RejectedWrite || rethrow()
        threw = true
    end
    check(threw, "foreign retraction accepted")
end

function v32()
    s = InMemoryStore()
    occid = put(s, jobj("type" => "occurrent", "label" => "press_button", "category" => "action"))
    e = signed("enrichment", jobj("about" => occid, "field" => "aliases",
               "entry" => jobj("lang" => "ja", "text" => "botan")), "bob", 1)
    put_record(s, e)
    check(length(jget(getobj(s, occid)["enrichments"], "aliases", Any[])) == 1)
    put_record(s, signed("retraction", jobj("retracts" => e["id"]), "bob", 2))
    check(isempty(jget(getobj(s, occid)["enrichments"], "aliases", Any[])))
    hist = jget(getobj(s, occid; view="history")["enrichments"], "aliases", Any[])
    check(length(hist) == 1)
end

function v33()
    s = InMemoryStore()
    _, k1 = key("K1"); _, k2 = key("K2")
    a = signed("assertion", jobj("about" => sym("causal_relation_object:claim"),
        "evidence_type" => "observation", "confidence" => 0.9), "K1", 1)
    put_record(s, a)
    put_record(s, signed("succession", jobj("successor" => k2), "K1", 2))
    check(k1 in lineage(s, k2) && k2 in lineage(s, k1))
    put_record(s, signed("retraction", jobj("retracts" => a["id"]), "K2", 3))
    check(isempty(assertions_about(s, sym("causal_relation_object:claim"))))
end

v34() = begin g = normalize(vec(34)["given"]); check(conflicts(g["A"], g["B"]) === true) end
v35() = begin g = normalize(vec(35)["given"]); check(conflicts(g["A"], g["B"]) === false) end

function v36()
    A, B, C, D = sym("occurrent:A"), sym("occurrent:B"), sym("occurrent:C"), sym("occurrent:D")
    m1 = jobj("id" => sym("causal_relation_object:m1"), "causes" => Any[A], "effects" => Any[B])
    m2 = jobj("id" => sym("causal_relation_object:m2"), "causes" => Any[B], "effects" => Any[C])
    m3 = jobj("id" => sym("causal_relation_object:m3"), "causes" => Any[D], "effects" => Any[C])
    P = jobj("causes" => Any[A], "effects" => Any[C], "mechanism" => Any[m1["id"], m2["id"]])
    check(hierarchy_consistent(P, Dict{Any,Any}(m1["id"] => m1, m2["id"] => m2)) == "consistent")
    P2 = jcopy(P); jset!(P2, "mechanism", Any[m1["id"], m3["id"]])
    check(hierarchy_consistent(P2, Dict{Any,Any}(m1["id"] => m1, m3["id"] => m3)) == "inconsistent")
    check(hierarchy_consistent(P, Dict{Any,Any}(m1["id"] => m1)) == "indeterminate")
end

function v37()
    s = InMemoryStore()
    occid = put(s, jobj("type" => "occurrent", "label" => "press_button", "category" => "action"))
    put_record(s, signed("enrichment", jobj("about" => occid, "field" => "aliases",
        "entry" => jobj("lang" => "en", "text" => "Press the Button")), "alice", 1))
    check(resolve(s, "Press  The   Button", "en") == [occid])
    check(resolve(s, "press_button", "en")[1] == occid)
end

function v38()
    s = InMemoryStore()
    P = put(s, jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                    "effects" => Any[sym("occurrent:B")]))
    check(P in [g["id"] for g in gaps(s; kind="missing_field")])
    R = put(s, jobj("type" => "causal_relation_object", "causes" => Any[sym("occurrent:A")],
                    "effects" => Any[sym("occurrent:B")],
                    "temporal" => jobj("minimum_delay" => 0, "maximum_delay" => 1, "unit" => "seconds"),
                    "modality" => "sufficient", "refines" => P))
    gap_ids = [g["id"] for g in gaps(s; kind="missing_field")]
    check(!(P in gap_ids) && !(R in gap_ids))
end

# ===========================================================================
# V39 - V107: the 2.0.0 additions
# ===========================================================================
function _neuro()
    labels = Dict(4 => "macromolecular", 5 => "subcellular", 6 => "cellular",
                  7 => "synaptic", 9 => "region", 14 => "community_and_society")
    return Dict(o => stratum(labels[o], "neuroendocrine", o) for o in keys(labels))
end

function v39()
    st = stratum("cellular", "neuroendocrine", 6, "cell", ["cell_biology"])
    ok, why = validate_schema(st); check(ok, join(why, "; "))
end

function v40()
    bad = mk(jobj("type" => "stratum", "label" => "cellular", "ordinal" => 6))
    ok, why = validate_schema(bad, "stratum")
    check(!ok && any(w -> occursin("scheme", w), why), join(why, "; "))
end

function v41()
    a = stratum("cellular", "neuroendocrine", 6)
    b = stratum("neuronal", "neuroendocrine", 6)
    for x in (a, b); ok, why = validate_schema(x); check(ok, join(why, "; ")); end
    check(a["id"] != b["id"])
end

function v42()
    s = _neuro()
    s4p = stratum("molecular", "physics", 4)
    c = occ("chronic_social_subordination", s[14]["id"])
    e = occ("gene_expression", s4p["id"])
    smap = Dict(s[14]["id"] => s[14], s4p["id"] => s4p)
    omap = Dict(c["id"] => c, e["id"] => e)
    P = cro([c["id"]], [e["id"]])
    check(classify_cro(P, omap, smap) == "scheme_mismatch")
end

function v43()
    for x in (stratum("macromolecular", "neuroendocrine", 4),
              stratum("region", "neuroendocrine", 9))
        ok, why = validate_schema(x); check(ok, join(why, "; "))
    end
end

function v44()
    st = stratum("cellular", "neuroendocrine", 6)
    o = occ("neuron_fires", st["id"])
    ok, why = validate_schema(o); check(ok, join(why, "; "))
    ok, why = validate_semantics(o); check(ok, join(why, "; "))
end

function v45()
    o = occ("press_button")
    ok, why = validate_schema(o); check(ok, join(why, "; "))
    e = occ("light_on")
    P = cro([o["id"]], [e["id"]])
    check(classify_cro(P, Dict(o["id"] => o, e["id"] => e), Dict()) == "unclassifiable")
end

function v46()
    s = _neuro()
    a = occ("depolarization", s[5]["id"])
    b = occ("depolarization", s[6]["id"])
    check(a["id"] != b["id"])
end

function _bridge_fixture(relation)
    s = _neuro()
    coarse = occ("action_potential_fires", s[6]["id"])
    fine = [occ("sodium_channels_open", s[4]["id"]), occ("sodium_influx", s[4]["id"])]
    b = bridge(coarse["id"], [f["id"] for f in fine], relation)
    omap = Dict(coarse["id"] => coarse)
    for f in fine; omap[f["id"]] = f; end
    smap = Dict(s[4]["id"] => s[4], s[6]["id"] => s[6])
    return b, omap, smap
end

function _valid_bridge(relation)
    b, omap, smap = _bridge_fixture(relation)
    ok, why = validate_schema(b); check(ok, join(why, "; "))
    ok, why = bridge_wellformed(b, omap, smap); check(ok, why)
end

v47() = _valid_bridge("constitutes")
v48() = _valid_bridge("aggregates")
v49() = _valid_bridge("realizes")
v50() = _valid_bridge("supervenes_on")

function v51()
    s = _neuro()
    coarse = occ("x_coarse", s[4]["id"]); fine = occ("x_fine", s[6]["id"])
    b = bridge(coarse["id"], [fine["id"]], "constitutes")
    omap = Dict(coarse["id"] => coarse, fine["id"] => fine)
    smap = Dict(s[4]["id"] => s[4], s[6]["id"] => s[6])
    ok, _ = bridge_wellformed(b, omap, smap); check(!ok)
end

function v52()
    s = _neuro()
    coarse = occ("c", s[6]["id"]); f1 = occ("f1", s[4]["id"]); f2 = occ("f2", s[5]["id"])
    b = bridge(coarse["id"], [f1["id"], f2["id"]], "constitutes")
    omap = Dict(coarse["id"] => coarse, f1["id"] => f1, f2["id"] => f2)
    smap = Dict(s[4]["id"] => s[4], s[5]["id"] => s[5], s[6]["id"] => s[6])
    ok, _ = bridge_wellformed(b, omap, smap); check(!ok)
end

function v53()
    x, y = sym("occurrent:x"), sym("occurrent:y")
    b1 = bridge(x, [y], "constitutes"); b2 = bridge(y, [x], "constitutes")
    edges = Dict{Any,Vector{Any}}()
    for b in (b1, b2)
        for f in b["fine"]; push!(get!(edges, f, Any[]), b["coarse"]); end
    end
    check(has_cycle(edges) === true)
end

function v54()
    a = stratum("cellular", "neuroendocrine", 6); b = stratum("molecular", "physics", 4)
    coarse = occ("c", a["id"]); fine = occ("f", b["id"])
    br = bridge(coarse["id"], [fine["id"]], "constitutes")
    omap = Dict(coarse["id"] => coarse, fine["id"] => fine)
    smap = Dict(a["id"] => a, b["id"] => b)
    ok, _ = bridge_wellformed(br, omap, smap); check(!ok)
end

function v55()
    s = _neuro()
    coarse = occ("decision_made", s[6]["id"])
    f1 = occ("cascade_a", s[4]["id"]); f2 = occ("cascade_b", s[4]["id"])
    b1 = bridge(coarse["id"], [f1["id"]], "realizes")
    b2 = bridge(coarse["id"], [f2["id"]], "realizes")
    check(b1["id"] != b2["id"])
    for b in (b1, b2); ok, why = validate_schema(b); check(ok, join(why, "; ")); end
end

function _reach_fixture()
    s = _neuro()
    ap = occ("action_potential_fires", s[6]["id"])
    nt = occ("neurotransmitter_released", s[6]["id"])
    fa = occ("calcium_enters", s[4]["id"]); fb = occ("vesicle_fuses", s[4]["id"])
    m1 = cro([fa["id"]], [fb["id"]])
    P = cro([ap["id"]], [nt["id"]]; mechanism=[m1["id"]])
    bridges = [bridge(ap["id"], [fa["id"]], "constitutes"),
               bridge(nt["id"], [fb["id"]], "constitutes")]
    return P, Dict(m1["id"] => m1), bridges
end

function v56()
    P, members, bridges = _reach_fixture()
    check(hierarchy_consistent(P, members, bridges) == "consistent")
end

function v57()
    P, members, _ = _reach_fixture()
    check(hierarchy_consistent(P, members, ()) == "inconsistent")
end

function v58()
    P, members, bridges = _reach_fixture()
    literal = hierarchy_consistent(P, members, ())
    bridged = hierarchy_consistent(P, members, bridges)
    check(literal != "consistent" && bridged == "consistent")
end

function _classify(cause_ord, effect_ord)
    s = _neuro()
    c = occ("c", s[cause_ord]["id"]); e = occ("e", s[effect_ord]["id"])
    smap = Dict(s[cause_ord]["id"] => s[cause_ord], s[effect_ord]["id"] => s[effect_ord])
    omap = Dict(c["id"] => c, e["id"] => e)
    return classify_cro(cro([c["id"]], [e["id"]]), omap, smap)
end

v59() = check(_classify(6, 6) == "intra_stratal")
v60() = check(_classify(6, 5) == "adjacent_stratal")
v61() = check(_classify(14, 4) == "skipping")

function _skip_fixture(cause_ord, effect_ord; kw...)
    s = _neuro()
    c = occ("c", s[cause_ord]["id"]); e = occ("e", s[effect_ord]["id"])
    smap = Dict(s[cause_ord]["id"] => s[cause_ord], s[effect_ord]["id"] => s[effect_ord])
    omap = Dict(c["id"] => c, e["id"] => e)
    P = cro([c["id"]], [e["id"]]; kw...)
    return P, classify_cro(P, omap, smap)
end

function v62()
    P, cls = _skip_fixture(14, 4)
    check(skip_gaps(P, cls) == ["incomplete_mechanism"])
end

function v63()
    P, cls = _skip_fixture(14, 4; skips=true)
    check(skip_gaps(P, cls) == String[])
end

function v64()
    P, cls = _skip_fixture(14, 4; skips=true, mechanism=[sym("causal_relation_object:m")])
    check(skip_gaps(P, cls) == ["contradictory_skip"])
    ok, why = validate_semantics(P)
    check(!ok && any(w -> occursin("contradictory_skip", w), why))
end

function v65()
    P, cls = _skip_fixture(6, 6; skips=true)
    check(skip_gaps(P, cls) == ["vacuous_skip"])
end

function v66()
    s = _neuro()
    c = occ("c", s[14]["id"]); e = occ("e", s[4]["id"])
    absent = cro([c["id"]], [e["id"]])
    false_ = cro([c["id"]], [e["id"]]; skips=false)
    check(absent["id"] != false_["id"])
end

function v67()
    s = _neuro()
    c1 = occ("c1", s[4]["id"]); c2 = occ("c2", s[6]["id"]); e = occ("e", s[6]["id"])
    P = cro([c1["id"], c2["id"]], [e["id"]])
    check(endpoints_mixed(P, Dict(c1["id"] => c1, c2["id"] => c2, e["id"] => e)) === true)
end

function v68()
    P = cro([sym("occurrent:a")], [sym("occurrent:b")]; modality="enabling")
    ok, why = validate_schema(P); check(ok, join(why, "; "))
end

function v69()
    a = jobj("causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")], "modality" => "enabling")
    b = jobj("causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")], "modality" => "sufficient")
    check(conflicts(a, b) === false)
end

function v70()
    a = jobj("causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")], "modality" => "enabling")
    b = jobj("causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")], "modality" => "preventive")
    check(conflicts(a, b) === true)
end

function v71()
    b = cnt("hippocampus")
    p = port(b["id"], "perforant_path", "in", [sym("occurrent:signal")])
    ok, why = validate_schema(p); check(ok, join(why, "; "))
end

function v72()
    b = cnt("hippocampus")["id"]; x = sym("occurrent:signal")
    check(port(b, "perforant_path", "in", [x])["id"] != port(b, "fornix", "in", [x])["id"])
end

function _conduit_fixture(; transform=false, bad_carry=false, in_from=false)
    x = sym("occurrent:motor_command"); y = sym("occurrent:error_signal"); z = sym("occurrent:unrelated")
    m1 = cnt("motor_cortex")["id"]; m2 = cnt("spinal_neuron")["id"]
    frm = port(m1, "out_port", in_from ? "in" : "out", [x])
    to = port(m2, "in_port", "in", transform ? [y] : [x])
    carries = bad_carry ? [z] : [x]
    xform = nothing
    cro_map = Dict{Any,Any}()
    if transform
        law = cro([x], [y]); cro_map[law["id"]] = law; xform = law["id"]
    end
    c = conduit(frm["id"], to["id"], carries; transform=xform)
    return c, Dict(frm["id"] => frm, to["id"] => to), cro_map
end

function v73()
    c, pmap, _ = _conduit_fixture()
    ok, why = validate_schema(c); check(ok, join(why, "; "))
    ok, why = conduit_wellformed(c, pmap); check(ok, why)
end

function v74()
    c, pmap, cmap = _conduit_fixture(transform=true)
    ok, why = validate_schema(c); check(ok, join(why, "; "))
    ok, why = conduit_wellformed(c, pmap, cmap); check(ok, why)
end

function v75()
    c, pmap, _ = _conduit_fixture(bad_carry=true)
    ok, _ = conduit_wellformed(c, pmap); check(!ok)
end

function v76()
    c, pmap, _ = _conduit_fixture(in_from=true)
    ok, _ = conduit_wellformed(c, pmap); check(!ok)
end

function v77()
    c, pmap, cmap = _conduit_fixture(transform=true)
    ok, why = conduit_wellformed(c, pmap, cmap); check(ok, why)
    law = collect(values(cmap))[1]
    check(!(law["effects"][1] in c["carries"]))
end

function _rlz(bearer, kind, label=nothing)
    o = jobj("type" => "realizable", "kind" => kind, "bearer" => bearer)
    label !== nothing && jset!(o, "label", label)
    return mk(o)
end

function v78()
    b = cnt("hippocampus")["id"]
    check(_rlz(b, "disposition", "long_term_potentiation")["id"] !=
          _rlz(b, "disposition", "pattern_separation")["id"])
end

function v79()
    b = cnt("hippocampus")["id"]
    u1 = _rlz(b, "disposition"); u2 = _rlz(b, "disposition")
    ok, why = validate_schema(u1); check(ok, join(why, "; "))
    check(u1["id"] == u2["id"])
    check(_rlz(b, "disposition", "some_function")["id"] != u1["id"])
end

function v80()
    parent = occ("fires"); child = occ("fires_action_potential")
    e = jobj("type" => "enrichment", "about" => child["id"],
             "field" => "occurrent_subsumes", "entry" => parent["id"])
    ok, why = validate_semantics(e); check(ok, join(why, "; "))
end

function v81()
    a, b = sym("occurrent:a"), sym("occurrent:b")
    check(has_cycle(Dict(a => [b], b => [a])) === true)
end

function v82()
    whole = occ("eat"); part = occ("chew")
    e = jobj("type" => "enrichment", "about" => part["id"],
             "field" => "occurrent_part_of", "entry" => whole["id"])
    ok, why = validate_semantics(e); check(ok, join(why, "; "))
end

function v83()
    legal_kinds, shape = ENRICHMENT_FIELDS["occurrent_part_of"]
    check(shape == "occurrent" && legal_kinds == ("occurrent",))
    s = InMemoryStore()
    put(s, occ("eat")); put(s, occ("chew"))
    check(!any(o -> jget(o, "type") == "causal_relation_object", values(s.objects)))
end

function v84()
    s = _neuro()
    a = occ("run", s[9]["id"]); b = occ("sprint", s[6]["id"])
    check(a["stratum"] != b["stratum"])
end

function v85()
    c = cnt("human_patient")
    ti = individual(c["id"]; designator="salted_hash_abc123")
    ok, why = validate_schema(ti); check(ok, join(why, "; "))
end

function v86()
    bad = mk(jobj("type" => "token_individual", "designator" => "x"))
    ok, why = validate_schema(bad, "token_individual")
    check(!ok && any(w -> occursin("instantiates", w), why), join(why, "; "))
end

function v87()
    c = cnt("human_patient")["id"]
    check(individual(c; designator="hash_a")["id"] != individual(c; designator="hash_b")["id"])
end

function v88()
    o = occ("bilateral_hippocampal_resection")
    t = token(o["id"], jobj("start" => "1953-08-25T00:00:00Z", "end" => "1953-08-25T00:00:00Z"))
    ok, why = validate_schema(t); check(ok, join(why, "; "))
end

function v89()
    o = occ("amnesia_onset")["id"]
    bounded = token(o, jobj("start" => "1953-08-25T00:00:00Z", "end" => "1953-08-26T00:00:00Z"))
    instantaneous = token(o, jobj("start" => "1953-08-25T00:00:00Z"))
    ongoing = token(o, jobj("start" => "1953-08-25T00:00:00Z", "open" => true))
    check(length(Set([bounded["id"], instantaneous["id"], ongoing["id"]])) == 3)
end

function v90()
    o = occ("resection")["id"]; c = cnt("human_patient")["id"]
    patient = individual(c; designator="p")["id"]
    surgeon = individual(c; designator="s")["id"]
    t = token(o, jobj("start" => "1953-08-25T00:00:00Z");
              participants=[jobj("role" => "patient", "filler" => patient),
                            jobj("role" => "agent", "filler" => surgeon)])
    ok, why = validate_schema(t); check(ok, join(why, "; "))
end

function v91()
    q = quality("cortisol_concentration", "quantity", "ug/dL")
    ok, why = validate_schema(q); check(ok, join(why, "; "))
end

function _state_fixture(datatype, value, unit=nothing)
    q = quality("cortisol_concentration", datatype, unit)
    c = cnt("human_patient")["id"]
    subj = individual(c; designator="p")["id"]
    st = state(subj, q["id"], value,
               jobj("start" => "2026-01-01T00:00:00Z", "end" => "2026-01-01T01:00:00Z"))
    return st, q
end

function v92()
    st, q = _state_fixture("quantity", jobj("quantity" => 15.0, "unit" => "ug/dL"), "ug/dL")
    ok, why = validate_schema(st); check(ok, join(why, "; "))
    check(state_gaps(st, q) == String[])
end

function v93()
    st, q = _state_fixture("categorical", jobj("categorical" => "elevated"))
    ok, why = validate_schema(st); check(ok, join(why, "; "))
    check(state_gaps(st, q) == String[])
end

function v94()
    st, q = _state_fixture("boolean", jobj("boolean" => true))
    ok, why = validate_schema(st); check(ok, join(why, "; "))
    check(state_gaps(st, q) == String[])
end

function v95()
    st, q = _state_fixture("quantity", jobj("categorical" => "elevated"), "ug/dL")
    check(state_gaps(st, q) == ["value_type_mismatch"])
end

function v96()
    st, q = _state_fixture("quantity", jobj("quantity" => 15.0, "unit" => "mg/dL"), "ug/dL")
    check(state_gaps(st, q) == ["unit_mismatch"])
end

function _law_and_tokens()
    o_cause = occ("resection"); o_effect = occ("amnesia_onset")
    law = cro([o_cause["id"]], [o_effect["id"]];
              temporal=jobj("minimum_delay" => 0, "maximum_delay" => 1, "unit" => "days"),
              modality="sufficient")
    t_cause = token(o_cause["id"], jobj("start" => "1953-08-25T00:00:00Z"))
    t_effect = token(o_effect["id"], jobj("start" => "1953-08-25T00:00:00Z", "open" => true))
    return law, o_cause, o_effect, t_cause, t_effect
end

function v97()
    law, _, _, tc, te = _law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]]; covering_law=law["id"],
                actual_delay=jobj("duration" => 0, "unit" => "instant"), counterfactual=true)
    ok, why = validate_schema(claim); check(ok, join(why, "; "))
end

function v98()
    _, _, _, tc, te = _law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]])
    ok, why = validate_schema(claim); check(ok, join(why, "; "))
    check(!jhas(claim, "covering_law"))
end

function v99()
    law, _, _, _, _ = _law_and_tokens()
    check(delay_within_window(jobj("duration" => 0, "unit" => "instant"), law["temporal"]) === true)
end

function v100()
    temporal = jobj("minimum_delay" => 0, "maximum_delay" => 1, "unit" => "hours")
    check(delay_within_window(jobj("duration" => 5, "unit" => "days"), temporal) === false)
end

function v101()
    o = occ("x")["id"]
    cause = token(o, jobj("start" => "2026-01-02T00:00:00Z"))
    effect = token(o, jobj("start" => "2026-01-01T00:00:00Z"))
    claim = tcc([cause["id"]], [effect["id"]])
    check(retrocausal(claim, Dict(cause["id"] => cause, effect["id"] => effect)) === true)
end

function v102()
    other = cro([sym("occurrent:foo")], [sym("occurrent:bar")])
    _, _, _, tc, te = _law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]]; covering_law=other["id"])
    check(covering_law_mismatch(claim, Dict(tc["id"] => tc, te["id"] => te), other) === true)
end

function v103()
    a = signed("assertion", jobj("about" => sym("token_occurrence:t"),
        "evidence_type" => "observation", "confidence" => 0.9), "signer")
    ok, why = validate_schema(a); check(ok, join(why, "; "))
end

function v104()
    ev = Any[sym("token_occurrence:t1"), sym("token_causal_claim:c1")]
    base = jobj("type" => "assertion", "about" => sym("causal_relation_object:law"),
                "source" => key("signer")[2], "evidence_type" => "intervention",
                "strength" => 0.95, "confidence" => 0.99, "timestamp" => "2026-07-14T00:00:00Z")
    a = jcopy(base); jset!(a, "evidenced_by", ev)
    withid = jcopy(a); jset!(withid, "id", identify(a))
    ok, why = validate_schema(withid); check(ok, join(why, "; "))
    check(identify(a) != identify(base))
end

function v105()
    a = signed("assertion", jobj("about" => sym("causal_relation_object:law"),
        "evidence_type" => "simulation", "confidence" => 0.5), "signer")
    ok, why = validate_schema(a); check(ok, join(why, "; "))
    rank = Dict("intervention" => 0, "observation" => 1, "simulation" => 2)
    check(rank["intervention"] < rank["observation"] < rank["simulation"])
end

function v106()
    function scan(node, ids)
        if node isa AbstractString
            m = match(r"^([a-z0-9_]+):[0-9a-f]{64}$", node)
            m !== nothing && push!(ids, m.captures[1])
        elseif node isa AbstractVector
            for x in node; scan(x, ids); end
        elseif node isa JObj
            for (_, v) in node.pairs; scan(v, ids); end
        end
    end
    for n in 1:38
        ids = String[]
        scan(vec(n), ids)
        for scheme in ids
            check(scheme in WHOLE_WORD, "V106: abbreviated scheme $(repr(scheme)) in vector $n")
        end
    end
    rec = jobj("type" => "occurrent", "label" => "press_button", "category" => "action")
    check(identify(rec) == identify(rec))
    check(String(split(identify(rec), ':'; limit=2)[1]) == "occurrent")
end

function v107()
    hexid = "0"^64
    cro_abbr = "c" * "r" * "o"  # intentional abbreviated prefix (negative test)
    abbreviated = jobj("type" => "causal_relation_object", "id" => cro_abbr * ":" * hexid,
                       "causes" => Any["occurrent:" * hexid], "effects" => Any["occurrent:" * hexid])
    ok, _ = validate_schema(abbreviated, "causal_relation_object")
    check(!ok, "abbreviated scheme must be rejected")
    abbr_str = jobj("type" => "stratum", "id" => "str:" * hexid, "label" => "cellular",
                    "scheme" => "neuroendocrine", "ordinal" => 6)
    ok, _ = validate_schema(abbr_str, "stratum"); check(!ok)
    whole = jobj("type" => "causal_relation_object", "id" => "causal_relation_object:" * hexid,
                 "causes" => Any["occurrent:" * hexid], "effects" => Any["occurrent:" * hexid])
    ok, why = validate_schema(whole, "causal_relation_object"); check(ok, join(why, "; "))
end

# ===========================================================================
# V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam, realized_by)
# ===========================================================================
# a cross_stratal_seam content object, completed with its content-addressed id
function seam(source, target, mechanism_status, chain=nothing)
    o = jobj("type" => "cross_stratal_seam", "source" => source,
             "target" => target, "mechanism_status" => mechanism_status)
    (chain !== nothing && !isempty(chain)) && jset!(o, "chain", chain)
    return mk(o)
end

# build a seam over the neuro fixture: (seam, occ_map, stratum_map).
function _seam_fixture(src_ord, tgt_ord, mechanism_status, chain_ords=nothing)
    s = _neuro()
    src = occ("source_event", s[src_ord]["id"])
    tgt = occ("target_event", s[tgt_ord]["id"])
    omap = Dict{Any,Any}(src["id"] => src, tgt["id"] => tgt)
    smap = Dict{Any,Any}(s[src_ord]["id"] => s[src_ord],
                         s[tgt_ord]["id"] => s[tgt_ord])
    chain = nothing
    if chain_ords !== nothing
        chain = Any[]
        for (i, o) in enumerate(chain_ords)
            c = occ("chain_$(i - 1)", s[o]["id"])
            omap[c["id"]] = c
            smap[s[o]["id"]] = s[o]
            push!(chain, c["id"])
        end
    end
    return seam(src["id"], tgt["id"], mechanism_status, chain), omap, smap
end

# a conduit with an optional realized_by reference, completed with its id
function _conduit_realized(realized_by=nothing)
    frm = "port:" * "1"^64
    to = "port:" * "2"^64
    x = "occurrent:" * "3"^64
    o = jobj("type" => "conduit", "label" => "conn", "from" => frm,
             "to" => to, "carries" => Any[x])
    realized_by !== nothing && jset!(o, "realized_by", realized_by)
    return mk(o)
end

# -- Change One: the ordinal (tick) temporal unit --
function v108()
    P = cro([sym("occurrent:a")], [sym("occurrent:b")];
            temporal=jobj("minimum_delay" => 0, "maximum_delay" => 5,
                          "unit" => "ticks"), modality="sufficient")
    ok, why = validate_schema(P); check(ok, join(why, "; "))
    ok, why = validate_semantics(P); check(ok, join(why, "; "))
end

function v109()
    P = cro([sym("occurrent:a")], [sym("occurrent:b")];
            temporal=jobj("minimum_delay" => 2, "maximum_delay" => 5,
                          "unit" => "ticks"))
    check(admissible(P, 3) === true)                 # 3 ticks inside [2, 5]
    check(admissible(P, 2) === true && admissible(P, 5) === true)
    check(admissible(P, 6) === false && admissible(P, 1) === false)
end

function v110()
    tick_window = jobj("minimum_delay" => 0, "maximum_delay" => 5, "unit" => "ticks")
    wall_window = jobj("minimum_delay" => 0, "maximum_delay" => 5, "unit" => "seconds")
    check(delay_within_window(jobj("duration" => 3, "unit" => "ticks"),
                              tick_window) === true)
    check(delay_within_window(jobj("duration" => 1, "unit" => "ticks"),
                              wall_window) === false)
    check(delay_within_window(jobj("duration" => 1, "unit" => "seconds"),
                              tick_window) === false)
    a = jobj("causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")],
             "temporal" => tick_window, "modality" => "sufficient")
    b = jobj("causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")],
             "temporal" => wall_window, "modality" => "preventive")
    check(conflicts(a, b) === false)                 # disjoint dimensions -> no overlap
    threw = false
    try
        to_seconds(1, "ticks")
    catch
        threw = true
    end
    check(threw, "to_seconds must refuse an ordinal unit")
end

function v111()
    base(temporal) = jobj("type" => "causal_relation_object",
        "causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")],
        "modality" => "sufficient", "temporal" => temporal)
    tick = base(jobj("minimum_delay" => 0, "maximum_delay" => 1, "unit" => "ticks"))
    secs = base(jobj("minimum_delay" => 0, "maximum_delay" => 1, "unit" => "seconds"))
    check(identify(tick) != identify(secs))          # the unit is identity-bearing
    # a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
    check(identify(secs) == "causal_relation_object:" *
          "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c")
end

# -- Change Two: the managed cross-stratal seam (eighteenth kind) --
function v112()
    sm, omap, smap = _seam_fixture(14, 4, "unmodeled")
    ok, why = validate_schema(sm); check(ok, join(why, "; "))
    ok, why = validate_semantics(sm); check(ok, join(why, "; "))
    ok, why = seam_wellformed(sm, omap, smap); check(ok, why)
end

function v113()
    a, _, _ = _seam_fixture(14, 4, "unmodeled")
    b, omap, smap = _seam_fixture(14, 4, "absent")
    ok, why = validate_schema(b); check(ok, join(why, "; "))
    ok, why = seam_wellformed(b, omap, smap); check(ok, why)
    check(a["id"] != b["id"])                        # mechanism_status is identity-bearing
end

function v114()
    drawn, omap, smap = _seam_fixture(14, 4, "unmodeled", [9, 7, 6, 5])
    ok, why = validate_schema(drawn); check(ok, join(why, "; "))
    ok, why = seam_wellformed(drawn, omap, smap); check(ok, why)
    bad, omap2, smap2 = _seam_fixture(14, 4, "absent", [9, 7, 6, 5])
    ok, why = validate_semantics(bad)
    check(!ok && any(w -> occursin("contradictory_seam", w), why), join(why, "; "))
    ok2, _ = seam_wellformed(bad, omap2, smap2); check(!ok2)
end

function v115()
    sm, omap, smap = _seam_fixture(14, 4, "unmodeled")
    s = _neuro()
    check(seam_home(sm, omap, smap) == s[14]["id"])  # coarsest (max ordinal) stratum
end

function v116()
    adj, o1, s1 = _seam_fixture(6, 5, "unmodeled")    # adjacent (gap 1)
    ok, _ = seam_wellformed(adj, o1, s1); check(!ok)
    co, o2, s2 = _seam_fixture(6, 6, "unmodeled")     # co-stratal (gap 0)
    ok, _ = seam_wellformed(co, o2, s2); check(!ok)
    sm, _, _ = _seam_fixture(14, 4, "unmodeled")
    check(startswith(sm["id"], "cross_stratal_seam:"))  # a new identity scheme
end

# -- Change Three: the realized_by reference --
function v117()
    c = _conduit_realized("causal_relation_object:" * "a"^64)
    ok, why = validate_schema(c); check(ok, join(why, "; "))
    c2 = _conduit_realized("native:region_stratum_predict")
    ok, why = validate_schema(c2); check(ok, join(why, "; "))  # a native scheme is legal
end

function v118()
    bound = _conduit_realized("native:region_stratum_predict")
    unbound = _conduit_realized()
    check(bound["id"] != unbound["id"])              # realized_by is identity-bearing
    # an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
    check(unbound["id"] == "conduit:" *
          "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6")
end

function v119()
    unbound = _conduit_realized()
    ok, why = validate_schema(unbound); check(ok, join(why, "; "))  # unbound is legal
    bad = jcopy(unbound)
    jset!(bad, "realized_by", "not-a-scheme-qualified-reference")
    ok, _ = validate_schema(bad, "conduit"); check(!ok)
end

# ===========================================================================
# V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
# prediction_error)
# ===========================================================================
attitude(holder, attitude_type, content) =
    mk(jobj("type" => "attitude", "holder" => holder,
            "attitude_type" => attitude_type, "content" => content))

function predicted(instantiates, interval, predictor, strength=nothing)
    o = jobj("type" => "predicted_occurrence", "instantiates" => instantiates,
             "interval" => interval, "predictor" => predictor)
    strength !== nothing && jset!(o, "strength", strength)
    return mk(o)
end

function prediction_error(predicted_id, discrepancy, observed=nothing)
    o = jobj("type" => "prediction_error", "predicted" => predicted_id,
             "discrepancy" => discrepancy)
    observed !== nothing && jset!(o, "observed", observed)
    return mk(o)
end

# a modeled predicting agent (a token individual), by identity
_predictor() =
    individual(cnt("forecasting_mind")["id"]; designator="predictor_p")["id"]

# a modeled believing agent (a token individual), by identity
_believer(designator="holder_h") =
    individual(cnt("believing_mind")["id"]; designator=designator)["id"]

# -- Group X: prediction and prediction error (Section A) --
function v120()
    o = occ("rainfall_begins")
    p = predicted(o["id"], jobj("start_tick" => 3, "end_tick" => 8), _predictor())
    ok, why = validate_schema(p); check(ok, join(why, "; "))
    ok, why = validate_semantics(p); check(ok, join(why, "; "))
    check(startswith(p["id"], "predicted_occurrence:"))
    report = identify(jobj("type" => "token_occurrence", "instantiates" => o["id"],
                           "interval" => jobj("start_tick" => 3, "end_tick" => 8)),
                      "token_occurrence")
    check(p["id"] != report)                         # a forecast is not a report
    check(startswith(report, "token_occurrence:"))
end

function v121()
    o = occ("rainfall_begins")
    wall = jobj("start" => "2026-07-23T00:00:00Z", "end" => "2026-07-24T00:00:00Z")
    who = _predictor()
    with_strength = predicted(o["id"], wall, who, 0.8)
    without = predicted(o["id"], wall, who)
    for p in (with_strength, without)
        ok, why = validate_schema(p); check(ok, join(why, "; "))
        ok, why = validate_semantics(p); check(ok, join(why, "; "))
    end
    check(with_strength["id"] != without["id"])      # strength is identity-bearing
end

function v122()
    o = occ("rainfall_begins")
    bad = mk(jobj("type" => "predicted_occurrence", "instantiates" => o["id"],
                  "interval" => jobj("start_tick" => 3)))
    ok, why = validate_schema(bad, "predicted_occurrence")
    check(!ok && any(w -> occursin("predictor", w), why), join(why, "; "))
end

function v123()
    o = occ("rainfall_begins")
    both = predicted(o["id"], jobj("start" => "2026-07-23T00:00:00Z",
                                   "start_tick" => 3), _predictor())
    ok, why = validate_schema(both); check(ok, join(why, "; "))
    ok, why = validate_semantics(both)
    check(!ok && any(w -> occursin("dimension_conflict", w), why), join(why, "; "))
end

function v124()
    o = occ("rainfall_begins")
    p = predicted(o["id"], jobj("start" => "2026-07-23T00:00:00Z"), _predictor())
    t = token(o["id"], jobj("start" => "2026-07-23T06:00:00Z"))
    err = prediction_error(p["id"], 0.0, t["id"])
    ok, why = validate_schema(err); check(ok, join(why, "; "))
    ok, why = validate_semantics(err); check(ok, join(why, "; "))
    check(prediction_pairing_mismatch(err, p, t) === false)
end

function v125()
    o = occ("rainfall_begins")
    p = predicted(o["id"], jobj("start" => "2026-07-23T00:00:00Z"), _predictor())
    err = prediction_error(p["id"], -1.0)
    ok, why = validate_schema(err); check(ok, join(why, "; "))
    ok, why = validate_semantics(err); check(ok, join(why, "; "))
    check(!jhas(err, "observed"))                    # observed is absent
    check(prediction_pairing_mismatch(err, p, nothing) === false)
end

function v126()
    o = occ("rainfall_begins")
    p = predicted(o["id"], jobj("start_tick" => 0), _predictor())
    bad = mk(jobj("type" => "prediction_error", "predicted" => p["id"]))
    ok, why = validate_schema(bad, "prediction_error")
    check(!ok && any(w -> occursin("discrepancy", w), why), join(why, "; "))
end

function v127()
    o = occ("rainfall_begins"); other = occ("snowfall_begins")
    p = predicted(o["id"], jobj("start" => "2026-07-23T00:00:00Z"), _predictor())
    t = token(other["id"], jobj("start" => "2026-07-23T06:00:00Z"))
    err = prediction_error(p["id"], 1.0, t["id"])
    ok, why = validate_schema(err); check(ok, join(why, "; "))
    check(prediction_pairing_mismatch(err, p, t) === true)  # pairing mismatch
end

# -- Group Y: attitude and theory of mind (Section B) --
function v128()
    st, _ = _state_fixture("quantity", jobj("quantity" => 15.0, "unit" => "ug/dL"),
                           "ug/dL")
    att = attitude(_believer(), "believes", st["id"])
    ok, why = validate_schema(att); check(ok, join(why, "; "))
    ok, why = validate_semantics(att); check(ok, join(why, "; "))
end

function v129()
    a = occ("switch_pressed"); b = occ("light_on")
    actual = cro([a["id"]], [b["id"]]; modality="sufficient")
    believed = cro([a["id"]], [b["id"]]; modality="preventive")
    check(conflicts(believed, actual) === true)      # the CLAIMS contradict
    att = attitude(_believer(), "believes", believed["id"])
    ok, why = validate_schema(att); check(ok, join(why, "; "))
    ok, why = validate_semantics(att); check(ok, join(why, "; "))  # validity unaffected
    s = InMemoryStore()
    put(s, a); put(s, b); put(s, actual); put(s, att)
    check(isempty(gaps(s; kind="conflict")))         # Rule 25: NO conflict raised
end

function v130()
    o = occ("rainfall_begins")
    att = attitude(_believer(), "desires", o["id"])
    ok, why = validate_schema(att); check(ok, join(why, "; "))
    ok, why = validate_semantics(att); check(ok, join(why, "; "))
end

function v131()
    o = occ("press_button")
    att = attitude(_believer(), "intends", o["id"])
    ok, why = validate_schema(att); check(ok, join(why, "; "))
    ok, why = validate_semantics(att); check(ok, join(why, "; "))
end

function v132()
    st, _ = _state_fixture("boolean", jobj("boolean" => true))
    inner = attitude(_believer("holder_b"), "believes", st["id"])
    outer = attitude(_believer("holder_a"), "believes", inner["id"])
    for att in (inner, outer)
        ok, why = validate_schema(att); check(ok, join(why, "; "))
        ok, why = validate_semantics(att); check(ok, join(why, "; "))
    end
    check(outer["id"] != inner["id"])
    check(outer["content"] == inner["id"])           # nested content
end

function v133()
    o = occ("rainfall_begins")
    bad = mk(jobj("type" => "attitude", "holder" => _believer(),
                  "attitude_type" => "suspects", "content" => o["id"]))
    ok, why = validate_schema(bad, "attitude")
    check(!ok && any(w -> occursin("attitude_type", w), why), join(why, "; "))
end

function v134()
    o = occ("rainfall_begins")
    bad = mk(jobj("type" => "attitude", "holder" => _believer(),
                  "attitude_type" => "believes", "content" => o["id"],
                  "strength" => 0.9))
    ok, why = validate_schema(bad, "attitude")
    check(!ok && any(w -> occursin("strength", w), why), join(why, "; "))
end

function v135()
    o = occ("rainfall_begins")
    att = attitude(_believer(), "expects", o["id"])
    a = signed("assertion", jobj("about" => att["id"],
                                 "evidence_type" => "observation",
                                 "confidence" => 0.9), "signer")
    ok, why = validate_schema(a); check(ok, join(why, "; "))
    check(verify_record(a) === true)
    # the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
    check(String(split(att["holder"], ':'; limit=2)[1]) == "token_individual")
    check(String(split(a["source"], ':'; limit=2)[1]) == "ed25519")
    check(att["holder"] != a["source"])
end

function v136()
    # the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
    secs = jobj("type" => "causal_relation_object",
                "causes" => Any[sym("occurrent:a")], "effects" => Any[sym("occurrent:b")],
                "modality" => "sufficient",
                "temporal" => jobj("minimum_delay" => 0, "maximum_delay" => 1,
                                   "unit" => "seconds"))
    check(identify(secs) == "causal_relation_object:" *
          "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c")
    # the V118 unbound conduit, re-pinned under 4.0.0
    unbound = _conduit_realized()
    check(unbound["id"] == "conduit:" *
          "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6")
end

function v137()
    hexid = "0"^64
    # NOTE: the abbreviated prefixes are intentional (the negative test); they
    # must NOT be re-minted.  Each is assembled to survive re-mint tools.
    att_abbr = "a" * "t" * "t"
    prd_abbr = "p" * "r" * "d"
    err_abbr = "e" * "r" * "r"
    bad_att = jobj("type" => "attitude", "id" => att_abbr * ":" * hexid,
                   "holder" => "token_individual:" * hexid,
                   "attitude_type" => "believes",
                   "content" => "state_assertion:" * hexid)
    ok, _ = validate_schema(bad_att, "attitude"); check(!ok)
    bad_prd = jobj("type" => "predicted_occurrence", "id" => prd_abbr * ":" * hexid,
                   "instantiates" => "occurrent:" * hexid,
                   "interval" => jobj("start_tick" => 0),
                   "predictor" => "token_individual:" * hexid)
    ok, _ = validate_schema(bad_prd, "predicted_occurrence"); check(!ok)
    bad_err = jobj("type" => "prediction_error", "id" => err_abbr * ":" * hexid,
                   "predicted" => "predicted_occurrence:" * hexid,
                   "discrepancy" => 0.0)
    ok, _ = validate_schema(bad_err, "prediction_error"); check(!ok)
    whole_att = jcopy(bad_att); jset!(whole_att, "id", "attitude:" * hexid)
    ok, why = validate_schema(whole_att, "attitude"); check(ok, join(why, "; "))
    whole_prd = jcopy(bad_prd); jset!(whole_prd, "id", "predicted_occurrence:" * hexid)
    ok, why = validate_schema(whole_prd, "predicted_occurrence"); check(ok, join(why, "; "))
    whole_err = jcopy(bad_err); jset!(whole_err, "id", "prediction_error:" * hexid)
    ok, why = validate_schema(whole_err, "prediction_error"); check(ok, join(why, "; "))
end

# ---------------------------------------------------------------------------
const VFUNCS = Function[
    v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
    v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
    v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
    v31, v32, v33, v34, v35, v36, v37, v38, v39, v40,
    v41, v42, v43, v44, v45, v46, v47, v48, v49, v50,
    v51, v52, v53, v54, v55, v56, v57, v58, v59, v60,
    v61, v62, v63, v64, v65, v66, v67, v68, v69, v70,
    v71, v72, v73, v74, v75, v76, v77, v78, v79, v80,
    v81, v82, v83, v84, v85, v86, v87, v88, v89, v90,
    v91, v92, v93, v94, v95, v96, v97, v98, v99, v100,
    v101, v102, v103, v104, v105, v106, v107, v108, v109, v110,
    v111, v112, v113, v114, v115, v116, v117, v118, v119, v120,
    v121, v122, v123, v124, v125, v126, v127, v128, v129, v130,
    v131, v132, v133, v134, v135, v136, v137,
]

function main()
    println("causalontology-julia conformance run (specification 4.0.0)")
    print("internal checks (RFC 8032, RFC 8785, fixed constants) ... ")
    internal_checks()
    println("ok")
    failures = 0
    total = 137
    for n in 1:total
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
    println("$(total - failures)/$total vectors passed")
    failures > 0 && exit(1)
    println("causalontology-julia is CONFORMANT to the suite " *
            "(vectors frozen at specification 4.0.0).")
end

main()

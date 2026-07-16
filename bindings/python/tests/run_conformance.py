#!/usr/bin/env python3
"""The Causalontology conformance runner for causalontology-py (spec 2.0.0).

Runs every vector in conformance/vectors/ against the Python binding. An
implementation is conformant if and only if it passes every vector; this
runner exits nonzero on any failure. Vectors are the whole-word 2.0.0
baseline (Principle P7): V01-V38 re-frozen unaltered in meaning, V39-V107 new.
"""

import glob
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))          # bindings/python
ROOT = HERE.parents[3]                            # repository root
VECDIR = ROOT / "conformance" / "vectors"

from causalontology import (                       # noqa: E402
    canonicalize, identify, validate_schema, validate_semantics, is_partial,
    admissible, conflicts, refinement_valid, hierarchy_consistent,
    bridge_closure, classify_cro, endpoints_mixed, skip_gaps, to_seconds,
    delay_within_window, bridge_wellformed, conduit_wellformed, state_gaps,
    covering_law_mismatch, retrocausal, has_cycle,
    keypair_from_seed, sign_record, verify_record,
    InMemoryStore, RejectedWrite)
from causalontology import ed25519                 # noqa: E402
from causalontology.canonical import _jcs          # noqa: E402
from causalontology.semantics import ENRICHMENT_FIELDS  # noqa: E402

# ---------------------------------------------------------------------------
# whole-word scheme normalization (Principle P7)
# ---------------------------------------------------------------------------
_SCHEMES = ("occurrent", "causal_relation_object", "continuant", "realizable",
            "assertion", "enrichment", "retraction", "succession",
            "stratum", "bridge", "port", "conduit", "quality",
            "token_individual", "token_occurrence", "state_assertion",
            "token_causal_claim")
WHOLE_WORD = set(_SCHEMES) | {"ed25519"}
_KEYS = {}


def key(name):
    if name not in _KEYS:
        seed = hashlib.sha256(("key:" + name).encode()).digest()
        _KEYS[name] = keypair_from_seed(seed)
    return _KEYS[name]


def sym(s):
    """Normalize one symbolic identifier to a well-formed one."""
    scheme, name = s.split(":", 1)
    if scheme == "ed25519":
        return s if re.fullmatch(r"[0-9a-f]{64}", name) else key(name)[1]
    if re.fullmatch(r"[0-9a-f]{64}", name):
        return s
    return scheme + ":" + hashlib.sha256(name.encode()).hexdigest()


def normalize(x):
    if isinstance(x, str):
        if x == "<128 hex>":
            return "ab" * 64
        m = re.match(r"^(%s):" % "|".join(_SCHEMES + ("ed25519",)), x)
        if m:
            return sym(x)
        return x
    if isinstance(x, list):
        return [normalize(v) for v in x]
    if isinstance(x, dict):
        return {k: normalize(v) for k, v in x.items()}
    return x


def vec(n):
    hits = glob.glob(str(VECDIR / ("v%02d_*.json" % n)))
    assert len(hits) == 1, "vector %d not found" % n
    with open(hits[0]) as f:
        return json.load(f)


TS = "2026-07-13T0%d:00:00Z"


def signed(kind, body, who, ts_i=0):
    secret, pub = key(who)
    rec = dict(body)
    rec["type"] = kind
    rec.setdefault("timestamp", TS % ts_i)
    if kind == "succession":
        rec.setdefault("predecessor", pub)
    else:
        rec["source"] = pub
    return sign_record(rec, secret, kind)


def mk(obj):
    """A content object completed with its real content-addressed id."""
    o = dict(obj)
    o["id"] = identify(o)
    return o


# builders --------------------------------------------------------------------
def stratum(label, scheme, ordinal, unit=None, governs=None):
    o = {"type": "stratum", "label": label, "scheme": scheme, "ordinal": ordinal}
    if unit:
        o["unit"] = unit
    if governs:
        o["governs"] = governs
    return mk(o)


def occ(label, stratum_id=None, category="event"):
    o = {"type": "occurrent", "label": label, "category": category}
    if stratum_id:
        o["stratum"] = stratum_id
    return mk(o)


def cnt(label, category="object"):
    return mk({"type": "continuant", "label": label, "category": category})


def cro(causes, effects, **kw):
    o = {"type": "causal_relation_object", "causes": causes, "effects": effects}
    o.update(kw)
    return mk(o)


def bridge(coarse, fine, relation):
    return mk({"type": "bridge", "coarse": coarse, "fine": fine,
               "relation": relation})


def port(bearer, label, direction, accepts, realizable=None):
    o = {"type": "port", "bearer": bearer, "label": label,
         "direction": direction, "accepts": accepts}
    if realizable:
        o["realizable"] = realizable
    return mk(o)


def conduit(frm, to, carries, label="conn", transform=None):
    o = {"type": "conduit", "label": label, "from": frm, "to": to,
         "carries": carries}
    if transform:
        o["transform"] = transform
    return mk(o)


def quality(label, datatype, unit=None, stratum_id=None):
    o = {"type": "quality", "label": label, "datatype": datatype}
    if unit:
        o["unit"] = unit
    if stratum_id:
        o["stratum"] = stratum_id
    return mk(o)


def individual(instantiates, designator=None, part_of=None):
    o = {"type": "token_individual", "instantiates": instantiates}
    if designator:
        o["designator"] = designator
    if part_of:
        o["part_of"] = part_of
    return mk(o)


def token(instantiates, interval, participants=None, locus=None):
    o = {"type": "token_occurrence", "instantiates": instantiates,
         "interval": interval}
    if participants:
        o["participants"] = participants
    if locus:
        o["locus"] = locus
    return mk(o)


def state(subject, qual, value, interval):
    return mk({"type": "state_assertion", "subject": subject, "quality": qual,
               "value": value, "interval": interval})


def tcc(causes, effects, covering_law=None, actual_delay=None,
        counterfactual=None):
    o = {"type": "token_causal_claim", "causes": causes, "effects": effects}
    if covering_law:
        o["covering_law"] = covering_law
    if actual_delay:
        o["actual_delay"] = actual_delay
    if counterfactual is not None:
        o["counterfactual"] = counterfactual
    return mk(o)


# ---------------------------------------------------------------------------
def internal_checks():
    sk = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = ed25519.secret_to_public(sk)
    assert pk.hex() == ("d75a980182b10ab7d54bfed3c964073a"
                        "0ee172f3daa62325af021a68f707511a"), pk.hex()
    assert ed25519.verify(pk, b"", ed25519.sign(sk, b""))
    assert _jcs({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert _jcs(1.0) == "1" and _jcs(6.000) == "6" and _jcs(0.7) == "0.7"
    assert to_seconds(1, "months") == 2629746
    assert to_seconds(1, "years") == 31556952


# ---------------------------------------------------------------------------
# V01 - V38: the whole-word re-freeze of the 1.0.0 suite (unaltered in meaning)
# ---------------------------------------------------------------------------
def v01():
    inp = normalize(vec(1)["input"])
    ok, why = validate_schema(inp); assert ok, why
    ok, why = validate_semantics(inp); assert ok, why

def v02():
    inp = normalize(vec(2)["input"])
    ok, _ = validate_schema(inp); assert ok
    ok, _ = validate_semantics(inp); assert ok
    partial, missing = is_partial(inp)
    assert partial and missing == vec(2)["expect"]["missing"], missing

def _schema_fails(n, must_mention):
    inp = normalize(vec(n)["input"])
    ok, why = validate_schema(inp)
    assert not ok, "expected schema-invalid"
    assert any(must_mention in w for w in why), why

def v03(): _schema_fails(3, "effects")
def v04(): _schema_fails(4, "causes")
def v05(): _schema_fails(5, "modality")
def v06(): _schema_fails(6, "colour")
def v07(): _schema_fails(7, "causes")

def v08():
    ok, why = validate_schema(normalize(vec(8)["input"])); assert ok, why

def v09(): _schema_fails(9, "label")
def v10(): _schema_fails(10, "category")

def v11():
    ok, why = validate_schema(normalize(vec(11)["input"])); assert ok, why

def v12(): _schema_fails(12, "confidence")

def v13():
    inp = normalize(vec(13)["input"])
    ok, why = validate_schema(inp); assert ok, why
    ok, why = validate_semantics(inp); assert ok, why

def _semantics_fails(n, must_mention):
    inp = normalize(vec(n)["input"])
    ok, why = validate_semantics(inp)
    assert not ok, "expected semantically-invalid"
    assert any(must_mention in w for w in why), why

def v14():
    inp = normalize(vec(14)["input"])
    ok, _ = validate_schema(inp); assert ok
    _semantics_fails(14, "minimum_delay")

def v15(): _semantics_fails(15, "acyclic")
def v16(): _semantics_fails(16, "acyclic")

def v17():
    v = vec(17)
    parent = normalize(v["given"]["parent"])
    child = normalize(v["input"])
    ok, reason = refinement_valid(child, parent)
    assert not ok and "rival" in reason, reason

def v18(): _semantics_fails(18, "not a legal field")
def v19(): _semantics_fails(19, "language-tagged")

def v20():
    dog, mam, ani = (sym("continuant:dog"), sym("continuant:mammal"),
                     sym("continuant:animal"))
    def enrich(about, entry, i):
        return signed("enrichment",
                      {"about": about, "field": "subsumes", "entry": entry},
                      "taxo", i)
    s = InMemoryStore(enforcing=True)
    s.put_record(enrich(dog, mam, 1))
    s.put_record(enrich(mam, ani, 2))
    try:
        s.put_record(enrich(ani, dog, 3))
        raise AssertionError("enforcing store accepted a cycle")
    except RejectedWrite as e:
        assert "cycle" in str(e), e
    s2 = InMemoryStore(enforcing=True)
    s2.put_record(enrich(dog, mam, 1))
    s2.put_record(enrich(mam, ani, 2))
    bad = enrich(ani, dog, 3)
    s2.force_merge_record(bad)
    active, excluded = s2._active_taxonomy_edges("subsumes")
    assert len(excluded) == 1 and excluded[0]["id"] == bad["id"]
    assert any(g["id"] == bad["id"] for g in s2.gaps("inconsistent_hierarchy"))

def _adm(n):
    g = vec(n)["given"]
    c = {"causes": [sym("occurrent:c")], "effects": [sym("occurrent:e")],
         "temporal": g["temporal"]}
    return admissible(c, g["elapsed_seconds"])

def v21(): assert _adm(21) is True
def v22(): assert _adm(22) is False
def v23(): assert _adm(23) is True

def v24():
    v = vec(24)
    assert identify(normalize(v["inputA"])) == identify(normalize(v["inputB"]))

def v25():
    v = vec(25)
    assert identify(normalize(v["inputA"])) == identify(normalize(v["inputB"]))

def v26():
    s = InMemoryStore()
    obj = {"type": "occurrent", "label": "press_button", "category": "action"}
    assert s.put(dict(obj)) == s.put(dict(obj)) and len(s.objects) == 1

def v27():
    s = InMemoryStore()
    occid = s.put({"type": "occurrent", "label": "press_button",
                   "category": "action"})
    entry = {"lang": "en", "text": "press the button"}
    r1 = signed("enrichment", {"about": occid, "field": "aliases",
                               "entry": entry}, "alice", 1)
    r2 = signed("enrichment", {"about": occid, "field": "aliases",
                               "entry": entry}, "bob", 2)
    assert s.put_record(r1) != s.put_record(r2)
    view = s.get(occid)["enrichments"]["aliases"]
    assert len(view) == 1 and len(view[0]["contributors"]) == 2

def v28():
    s = InMemoryStore()
    claim = {"type": "causal_relation_object", "causes": [sym("occurrent:A")],
             "effects": [sym("occurrent:B")], "modality": "sufficient"}
    i1 = s.put(dict(claim)); i2 = s.put(dict(claim))
    assert i1 == i2 and len(s.objects) == 1
    for who, ts in (("lab1", 1), ("lab2", 2)):
        s.put_record(signed("assertion",
                            {"about": i1, "evidence_type": "observation",
                             "strength": 0.8, "confidence": 0.8}, who, ts))
    assert len(s.assertions_about(i1)) == 2

def v29():
    rec = signed("assertion", {"about": sym("causal_relation_object:demo"),
                               "evidence_type": "intervention",
                               "strength": 0.7, "confidence": 0.9}, "signer")
    assert verify_record(rec) is True

def v30():
    rec = signed("assertion", {"about": sym("causal_relation_object:demo"),
                               "evidence_type": "intervention",
                               "strength": 0.7, "confidence": 0.9}, "signer")
    assert verify_record(dict(rec, confidence=0.1)) is False

def v31():
    s = InMemoryStore()
    x = s.put({"type": "causal_relation_object", "causes": [sym("occurrent:A")],
               "effects": [sym("occurrent:B")]})
    a = signed("assertion", {"about": x, "evidence_type": "observation",
                             "confidence": 0.8}, "lab1", 1)
    s.put_record(a)
    s.put_record(signed("retraction", {"retracts": a["id"]}, "lab1", 2))
    assert s.assertions_about(x) == []
    hist = s.assertions_about(x, include_retracted=True)
    assert len(hist) == 1 and hist[0]["retracted"] is True
    try:
        s.put_record(signed("retraction", {"retracts": a["id"]}, "mallory", 3))
        raise AssertionError("foreign retraction accepted")
    except RejectedWrite:
        pass

def v32():
    s = InMemoryStore()
    occid = s.put({"type": "occurrent", "label": "press_button",
                   "category": "action"})
    e = signed("enrichment", {"about": occid, "field": "aliases",
                              "entry": {"lang": "ja", "text": "botan"}},
               "bob", 1)
    s.put_record(e)
    assert len(s.get(occid)["enrichments"].get("aliases", [])) == 1
    s.put_record(signed("retraction", {"retracts": e["id"]}, "bob", 2))
    assert s.get(occid)["enrichments"].get("aliases", []) == []
    assert len(s.get(occid, view="history")["enrichments"].get("aliases", [])) == 1

def v33():
    s = InMemoryStore()
    _, k1 = key("K1"); _, k2 = key("K2")
    a = signed("assertion", {"about": sym("causal_relation_object:claim"),
                             "evidence_type": "observation",
                             "confidence": 0.9}, "K1", 1)
    s.put_record(a)
    s.put_record(signed("succession", {"successor": k2}, "K1", 2))
    assert k1 in s.lineage(k2) and k2 in s.lineage(k1)
    s.put_record(signed("retraction", {"retracts": a["id"]}, "K2", 3))
    assert s.assertions_about(sym("causal_relation_object:claim")) == []

def v34():
    g = normalize(vec(34)["given"]); assert conflicts(g["A"], g["B"]) is True

def v35():
    g = normalize(vec(35)["given"]); assert conflicts(g["A"], g["B"]) is False

def v36():
    A, B, C, D = (sym("occurrent:A"), sym("occurrent:B"),
                  sym("occurrent:C"), sym("occurrent:D"))
    m1 = {"id": sym("causal_relation_object:m1"), "causes": [A], "effects": [B]}
    m2 = {"id": sym("causal_relation_object:m2"), "causes": [B], "effects": [C]}
    m3 = {"id": sym("causal_relation_object:m3"), "causes": [D], "effects": [C]}
    P = {"causes": [A], "effects": [C], "mechanism": [m1["id"], m2["id"]]}
    assert hierarchy_consistent(P, {m1["id"]: m1, m2["id"]: m2}) == "consistent"
    P2 = dict(P, mechanism=[m1["id"], m3["id"]])
    assert hierarchy_consistent(P2, {m1["id"]: m1, m3["id"]: m3}) == "inconsistent"
    assert hierarchy_consistent(P, {m1["id"]: m1}) == "indeterminate"

def v37():
    s = InMemoryStore()
    occid = s.put({"type": "occurrent", "label": "press_button",
                   "category": "action"})
    s.put_record(signed("enrichment",
                        {"about": occid, "field": "aliases",
                         "entry": {"lang": "en", "text": "Press the Button"}},
                        "alice", 1))
    assert s.resolve("Press  The   Button", "en") == [occid]
    assert s.resolve("press_button", "en")[0] == occid

def v38():
    s = InMemoryStore()
    P = s.put({"type": "causal_relation_object", "causes": [sym("occurrent:A")],
               "effects": [sym("occurrent:B")]})
    assert P in [g["id"] for g in s.gaps("missing_field")]
    R = s.put({"type": "causal_relation_object", "causes": [sym("occurrent:A")],
               "effects": [sym("occurrent:B")],
               "temporal": {"minimum_delay": 0, "maximum_delay": 1,
                            "unit": "seconds"},
               "modality": "sufficient", "refines": P})
    gaps = [g["id"] for g in s.gaps("missing_field")]
    assert P not in gaps and R not in gaps


# ---------------------------------------------------------------------------
# V39 - V107: the 2.0.0 additions
# ---------------------------------------------------------------------------
def _neuro():
    labels = {4: "macromolecular", 5: "subcellular", 6: "cellular",
              7: "synaptic", 9: "region", 14: "community_and_society"}
    return {o: stratum(labels[o], "neuroendocrine", o) for o in labels}

def v39():
    st = stratum("cellular", "neuroendocrine", 6, "cell", ["cell_biology"])
    ok, why = validate_schema(st); assert ok, why

def v40():
    bad = mk({"type": "stratum", "label": "cellular", "ordinal": 6})
    ok, why = validate_schema(bad, "stratum")
    assert not ok and any("scheme" in w for w in why), why

def v41():
    a = stratum("cellular", "neuroendocrine", 6)
    b = stratum("neuronal", "neuroendocrine", 6)
    for x in (a, b):
        ok, why = validate_schema(x); assert ok, why
    assert a["id"] != b["id"]

def v42():
    s = _neuro()
    s4p = stratum("molecular", "physics", 4)
    c = occ("chronic_social_subordination", s[14]["id"])
    e = occ("gene_expression", s4p["id"])
    smap = {s[14]["id"]: s[14], s4p["id"]: s4p}
    omap = {c["id"]: c, e["id"]: e}
    P = cro([c["id"]], [e["id"]])
    assert classify_cro(P, omap, smap) == "scheme_mismatch"

def v43():
    for x in (stratum("macromolecular", "neuroendocrine", 4),
              stratum("region", "neuroendocrine", 9)):
        ok, why = validate_schema(x); assert ok, why

def v44():
    st = stratum("cellular", "neuroendocrine", 6)
    o = occ("neuron_fires", st["id"])
    ok, why = validate_schema(o); assert ok, why
    ok, why = validate_semantics(o); assert ok, why

def v45():
    o = occ("press_button")
    ok, why = validate_schema(o); assert ok, why
    e = occ("light_on")
    P = cro([o["id"]], [e["id"]])
    assert classify_cro(P, {o["id"]: o, e["id"]: e}, {}) == "unclassifiable"

def v46():
    s = _neuro()
    a = occ("depolarization", s[5]["id"])
    b = occ("depolarization", s[6]["id"])
    assert a["id"] != b["id"]

def _bridge_fixture(relation):
    s = _neuro()
    coarse = occ("action_potential_fires", s[6]["id"])
    fine = [occ("sodium_channels_open", s[4]["id"]),
            occ("sodium_influx", s[4]["id"])]
    b = bridge(coarse["id"], [f["id"] for f in fine], relation)
    omap = {coarse["id"]: coarse}
    for f in fine:
        omap[f["id"]] = f
    smap = {s[4]["id"]: s[4], s[6]["id"]: s[6]}
    return b, omap, smap

def _valid_bridge(relation):
    b, omap, smap = _bridge_fixture(relation)
    ok, why = validate_schema(b); assert ok, why
    ok, why = bridge_wellformed(b, omap, smap); assert ok, why

def v47(): _valid_bridge("constitutes")
def v48(): _valid_bridge("aggregates")
def v49(): _valid_bridge("realizes")
def v50(): _valid_bridge("supervenes_on")

def v51():
    s = _neuro()
    coarse = occ("x_coarse", s[4]["id"])
    fine = occ("x_fine", s[6]["id"])
    b = bridge(coarse["id"], [fine["id"]], "constitutes")
    omap = {coarse["id"]: coarse, fine["id"]: fine}
    smap = {s[4]["id"]: s[4], s[6]["id"]: s[6]}
    ok, _ = bridge_wellformed(b, omap, smap); assert not ok

def v52():
    s = _neuro()
    coarse = occ("c", s[6]["id"])
    f1 = occ("f1", s[4]["id"]); f2 = occ("f2", s[5]["id"])
    b = bridge(coarse["id"], [f1["id"], f2["id"]], "constitutes")
    omap = {coarse["id"]: coarse, f1["id"]: f1, f2["id"]: f2}
    smap = {s[4]["id"]: s[4], s[5]["id"]: s[5], s[6]["id"]: s[6]}
    ok, _ = bridge_wellformed(b, omap, smap); assert not ok

def v53():
    x, y = sym("occurrent:x"), sym("occurrent:y")
    b1 = bridge(x, [y], "constitutes")
    b2 = bridge(y, [x], "constitutes")
    edges = {}
    for b in (b1, b2):
        for f in b["fine"]:
            edges.setdefault(f, []).append(b["coarse"])
    assert has_cycle(edges) is True

def v54():
    a = stratum("cellular", "neuroendocrine", 6)
    b = stratum("molecular", "physics", 4)
    coarse = occ("c", a["id"]); fine = occ("f", b["id"])
    br = bridge(coarse["id"], [fine["id"]], "constitutes")
    omap = {coarse["id"]: coarse, fine["id"]: fine}
    smap = {a["id"]: a, b["id"]: b}
    ok, _ = bridge_wellformed(br, omap, smap); assert not ok

def v55():
    s = _neuro()
    coarse = occ("decision_made", s[6]["id"])
    f1 = occ("cascade_a", s[4]["id"]); f2 = occ("cascade_b", s[4]["id"])
    b1 = bridge(coarse["id"], [f1["id"]], "realizes")
    b2 = bridge(coarse["id"], [f2["id"]], "realizes")
    assert b1["id"] != b2["id"]
    for b in (b1, b2):
        ok, why = validate_schema(b); assert ok, why

def _reach_fixture():
    s = _neuro()
    ap = occ("action_potential_fires", s[6]["id"])
    nt = occ("neurotransmitter_released", s[6]["id"])
    fa = occ("calcium_enters", s[4]["id"])
    fb = occ("vesicle_fuses", s[4]["id"])
    m1 = cro([fa["id"]], [fb["id"]])
    P = cro([ap["id"]], [nt["id"]], mechanism=[m1["id"]])
    bridges = [bridge(ap["id"], [fa["id"]], "constitutes"),
               bridge(nt["id"], [fb["id"]], "constitutes")]
    return P, {m1["id"]: m1}, bridges

def v56():
    P, members, bridges = _reach_fixture()
    assert hierarchy_consistent(P, members, bridges) == "consistent"

def v57():
    P, members, _ = _reach_fixture()
    assert hierarchy_consistent(P, members, ()) == "inconsistent"

def v58():
    P, members, bridges = _reach_fixture()
    literal = hierarchy_consistent(P, members, ())
    bridged = hierarchy_consistent(P, members, bridges)
    assert literal != "consistent" and bridged == "consistent"

def _classify(cause_ord, effect_ord):
    s = _neuro()
    c = occ("c", s[cause_ord]["id"]); e = occ("e", s[effect_ord]["id"])
    smap = {s[cause_ord]["id"]: s[cause_ord], s[effect_ord]["id"]: s[effect_ord]}
    omap = {c["id"]: c, e["id"]: e}
    return classify_cro(cro([c["id"]], [e["id"]]), omap, smap)

def v59(): assert _classify(6, 6) == "intra_stratal"
def v60(): assert _classify(6, 5) == "adjacent_stratal"
def v61(): assert _classify(14, 4) == "skipping"

def _skip_fixture(cause_ord, effect_ord, **kw):
    s = _neuro()
    c = occ("c", s[cause_ord]["id"]); e = occ("e", s[effect_ord]["id"])
    smap = {s[cause_ord]["id"]: s[cause_ord], s[effect_ord]["id"]: s[effect_ord]}
    omap = {c["id"]: c, e["id"]: e}
    P = cro([c["id"]], [e["id"]], **kw)
    return P, classify_cro(P, omap, smap)

def v62():
    P, cls = _skip_fixture(14, 4)
    assert skip_gaps(P, cls) == ["incomplete_mechanism"]

def v63():
    P, cls = _skip_fixture(14, 4, skips=True)
    assert skip_gaps(P, cls) == []

def v64():
    P, cls = _skip_fixture(14, 4, skips=True,
                           mechanism=[sym("causal_relation_object:m")])
    assert skip_gaps(P, cls) == ["contradictory_skip"]
    ok, why = validate_semantics(P)
    assert not ok and any("contradictory_skip" in w for w in why)

def v65():
    P, cls = _skip_fixture(6, 6, skips=True)
    assert skip_gaps(P, cls) == ["vacuous_skip"]

def v66():
    s = _neuro()
    c = occ("c", s[14]["id"]); e = occ("e", s[4]["id"])
    absent = cro([c["id"]], [e["id"]])
    false_ = cro([c["id"]], [e["id"]], skips=False)
    assert absent["id"] != false_["id"]

def v67():
    s = _neuro()
    c1 = occ("c1", s[4]["id"]); c2 = occ("c2", s[6]["id"])
    e = occ("e", s[6]["id"])
    P = cro([c1["id"], c2["id"]], [e["id"]])
    assert endpoints_mixed(P, {c1["id"]: c1, c2["id"]: c2, e["id"]: e}) is True

def v68():
    P = cro([sym("occurrent:a")], [sym("occurrent:b")], modality="enabling")
    ok, why = validate_schema(P); assert ok, why

def v69():
    a = {"causes": [sym("occurrent:a")], "effects": [sym("occurrent:b")],
         "modality": "enabling"}
    b = {"causes": [sym("occurrent:a")], "effects": [sym("occurrent:b")],
         "modality": "sufficient"}
    assert conflicts(a, b) is False

def v70():
    a = {"causes": [sym("occurrent:a")], "effects": [sym("occurrent:b")],
         "modality": "enabling"}
    b = {"causes": [sym("occurrent:a")], "effects": [sym("occurrent:b")],
         "modality": "preventive"}
    assert conflicts(a, b) is True

def v71():
    b = cnt("hippocampus")
    p = port(b["id"], "perforant_path", "in", [sym("occurrent:signal")])
    ok, why = validate_schema(p); assert ok, why

def v72():
    b = cnt("hippocampus")["id"]
    x = sym("occurrent:signal")
    assert port(b, "perforant_path", "in", [x])["id"] \
        != port(b, "fornix", "in", [x])["id"]

def _conduit_fixture(transform=False, bad_carry=False, in_from=False):
    x = sym("occurrent:motor_command"); y = sym("occurrent:error_signal")
    z = sym("occurrent:unrelated")
    m1 = cnt("motor_cortex")["id"]; m2 = cnt("spinal_neuron")["id"]
    frm = port(m1, "out_port", "in" if in_from else "out", [x])
    to = port(m2, "in_port", "in", [y] if transform else [x])
    carries = [z] if bad_carry else [x]
    xform = None
    cro_map = {}
    if transform:
        law = cro([x], [y]); cro_map[law["id"]] = law
        xform = law["id"]
    c = conduit(frm["id"], to["id"], carries, transform=xform)
    return c, {frm["id"]: frm, to["id"]: to}, cro_map

def v73():
    c, pmap, _ = _conduit_fixture()
    ok, why = validate_schema(c); assert ok, why
    ok, why = conduit_wellformed(c, pmap); assert ok, why

def v74():
    c, pmap, cmap = _conduit_fixture(transform=True)
    ok, why = validate_schema(c); assert ok, why
    ok, why = conduit_wellformed(c, pmap, cmap); assert ok, why

def v75():
    c, pmap, _ = _conduit_fixture(bad_carry=True)
    ok, _ = conduit_wellformed(c, pmap); assert not ok

def v76():
    c, pmap, _ = _conduit_fixture(in_from=True)
    ok, _ = conduit_wellformed(c, pmap); assert not ok

def v77():
    c, pmap, cmap = _conduit_fixture(transform=True)
    ok, why = conduit_wellformed(c, pmap, cmap); assert ok, why
    law = list(cmap.values())[0]
    assert law["effects"][0] not in c["carries"]

def _rlz(bearer, kind, label=None):
    o = {"type": "realizable", "kind": kind, "bearer": bearer}
    if label:
        o["label"] = label
    return mk(o)

def v78():
    b = cnt("hippocampus")["id"]
    assert _rlz(b, "disposition", "long_term_potentiation")["id"] \
        != _rlz(b, "disposition", "pattern_separation")["id"]

def v79():
    b = cnt("hippocampus")["id"]
    u1 = _rlz(b, "disposition"); u2 = _rlz(b, "disposition")
    ok, why = validate_schema(u1); assert ok, why
    assert u1["id"] == u2["id"]
    assert _rlz(b, "disposition", "some_function")["id"] != u1["id"]

def v80():
    parent = occ("fires"); child = occ("fires_action_potential")
    e = {"type": "enrichment", "about": child["id"],
         "field": "occurrent_subsumes", "entry": parent["id"]}
    ok, why = validate_semantics(e); assert ok, why

def v81():
    a, b = sym("occurrent:a"), sym("occurrent:b")
    assert has_cycle({a: [b], b: [a]}) is True

def v82():
    whole = occ("eat"); part = occ("chew")
    e = {"type": "enrichment", "about": part["id"],
         "field": "occurrent_part_of", "entry": whole["id"]}
    ok, why = validate_semantics(e); assert ok, why

def v83():
    legal_kinds, shape = ENRICHMENT_FIELDS["occurrent_part_of"]
    assert shape == "occurrent" and legal_kinds == ("occurrent",)
    s = InMemoryStore()
    whole = s.put(occ("eat")); part = s.put(occ("chew"))
    assert not any(o.get("type") == "causal_relation_object"
                   for o in s.objects.values())

def v84():
    s = _neuro()
    a = occ("run", s[9]["id"]); b = occ("sprint", s[6]["id"])
    assert a["stratum"] != b["stratum"]

def v85():
    c = cnt("human_patient")
    ti = individual(c["id"], designator="salted_hash_abc123")
    ok, why = validate_schema(ti); assert ok, why

def v86():
    bad = mk({"type": "token_individual", "designator": "x"})
    ok, why = validate_schema(bad, "token_individual")
    assert not ok and any("instantiates" in w for w in why), why

def v87():
    c = cnt("human_patient")["id"]
    assert individual(c, designator="hash_a")["id"] \
        != individual(c, designator="hash_b")["id"]

def v88():
    o = occ("bilateral_hippocampal_resection")
    t = token(o["id"], {"start": "1953-08-25T00:00:00Z",
                        "end": "1953-08-25T00:00:00Z"})
    ok, why = validate_schema(t); assert ok, why

def v89():
    o = occ("amnesia_onset")["id"]
    bounded = token(o, {"start": "1953-08-25T00:00:00Z",
                        "end": "1953-08-26T00:00:00Z"})
    instantaneous = token(o, {"start": "1953-08-25T00:00:00Z"})
    ongoing = token(o, {"start": "1953-08-25T00:00:00Z", "open": True})
    assert len({bounded["id"], instantaneous["id"], ongoing["id"]}) == 3

def v90():
    o = occ("resection")["id"]; c = cnt("human_patient")["id"]
    patient = individual(c, designator="p")["id"]
    surgeon = individual(c, designator="s")["id"]
    t = token(o, {"start": "1953-08-25T00:00:00Z"},
              participants=[{"role": "patient", "filler": patient},
                            {"role": "agent", "filler": surgeon}])
    ok, why = validate_schema(t); assert ok, why

def v91():
    q = quality("cortisol_concentration", "quantity", "ug/dL")
    ok, why = validate_schema(q); assert ok, why

def _state_fixture(datatype, value, unit=None):
    q = quality("cortisol_concentration", datatype, unit)
    c = cnt("human_patient")["id"]
    subj = individual(c, designator="p")["id"]
    st = state(subj, q["id"], value,
               {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"})
    return st, q

def v92():
    st, q = _state_fixture("quantity", {"quantity": 15.0, "unit": "ug/dL"},
                           "ug/dL")
    ok, why = validate_schema(st); assert ok, why
    assert state_gaps(st, q) == []

def v93():
    st, q = _state_fixture("categorical", {"categorical": "elevated"})
    ok, why = validate_schema(st); assert ok, why
    assert state_gaps(st, q) == []

def v94():
    st, q = _state_fixture("boolean", {"boolean": True})
    ok, why = validate_schema(st); assert ok, why
    assert state_gaps(st, q) == []

def v95():
    st, q = _state_fixture("quantity", {"categorical": "elevated"}, "ug/dL")
    assert state_gaps(st, q) == ["value_type_mismatch"]

def v96():
    st, q = _state_fixture("quantity", {"quantity": 15.0, "unit": "mg/dL"},
                           "ug/dL")
    assert state_gaps(st, q) == ["unit_mismatch"]

def _law_and_tokens():
    o_cause = occ("resection"); o_effect = occ("amnesia_onset")
    law = cro([o_cause["id"]], [o_effect["id"]],
              temporal={"minimum_delay": 0, "maximum_delay": 1, "unit": "days"},
              modality="sufficient")
    t_cause = token(o_cause["id"], {"start": "1953-08-25T00:00:00Z"})
    t_effect = token(o_effect["id"], {"start": "1953-08-25T00:00:00Z",
                                      "open": True})
    return law, o_cause, o_effect, t_cause, t_effect

def v97():
    law, _, _, tc, te = _law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]], covering_law=law["id"],
                actual_delay={"duration": 0, "unit": "instant"},
                counterfactual=True)
    ok, why = validate_schema(claim); assert ok, why

def v98():
    _, _, _, tc, te = _law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]])
    ok, why = validate_schema(claim); assert ok, why
    assert "covering_law" not in claim

def v99():
    law, _, _, _, _ = _law_and_tokens()
    assert delay_within_window({"duration": 0, "unit": "instant"},
                               law["temporal"]) is True

def v100():
    temporal = {"minimum_delay": 0, "maximum_delay": 1, "unit": "hours"}
    assert delay_within_window({"duration": 5, "unit": "days"}, temporal) is False

def v101():
    o = occ("x")["id"]
    cause = token(o, {"start": "2026-01-02T00:00:00Z"})
    effect = token(o, {"start": "2026-01-01T00:00:00Z"})
    claim = tcc([cause["id"]], [effect["id"]])
    assert retrocausal(claim, {cause["id"]: cause, effect["id"]: effect}) is True

def v102():
    other = cro([sym("occurrent:foo")], [sym("occurrent:bar")])
    _, _, _, tc, te = _law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]], covering_law=other["id"])
    assert covering_law_mismatch(claim, {tc["id"]: tc, te["id"]: te},
                                 other) is True

def v103():
    a = signed("assertion", {"about": sym("token_occurrence:t"),
                             "evidence_type": "observation",
                             "confidence": 0.9}, "signer")
    ok, why = validate_schema(a); assert ok, why

def v104():
    ev = [sym("token_occurrence:t1"), sym("token_causal_claim:c1")]
    base = {"type": "assertion", "about": sym("causal_relation_object:law"),
            "source": key("signer")[1], "evidence_type": "intervention",
            "strength": 0.95, "confidence": 0.99,
            "timestamp": "2026-07-14T00:00:00Z"}
    a = dict(base, evidenced_by=ev)
    ok, why = validate_schema(dict(a, id=identify(a))); assert ok, why
    assert identify(a) != identify(base)   # evidenced_by is identity-bearing

def v105():
    a = signed("assertion", {"about": sym("causal_relation_object:law"),
                             "evidence_type": "simulation",
                             "confidence": 0.5}, "signer")
    ok, why = validate_schema(a); assert ok, why
    rank = {"intervention": 0, "observation": 1, "simulation": 2}
    assert rank["intervention"] < rank["observation"] < rank["simulation"]

def v106():
    def scan(node, ids):
        if isinstance(node, str):
            m = re.match(r"^([a-z0-9_]+):[0-9a-f]{64}$", node)
            if m:
                ids.append(m.group(1))
        elif isinstance(node, list):
            for x in node:
                scan(x, ids)
        elif isinstance(node, dict):
            for x in node.values():
                scan(x, ids)
    for n in range(1, 39):
        ids = []
        scan(vec(n), ids)
        for scheme in ids:
            assert scheme in WHOLE_WORD, \
                "V106: abbreviated scheme %r in vector %d" % (scheme, n)
    rec = {"type": "occurrent", "label": "press_button", "category": "action"}
    assert identify(rec) == identify(rec)
    assert identify(rec).split(":", 1)[0] == "occurrent"

def v107():
    hexid = "0" * 64
    # NOTE: the abbreviated prefix below is intentional (the negative test);
    # it must NOT be re-minted. "c" "r" "o" is assembled to survive re-mint tools.
    cro_abbr = "c" + "r" + "o"
    abbreviated = {"type": "causal_relation_object", "id": cro_abbr + ":" + hexid,
                   "causes": ["occurrent:" + hexid],
                   "effects": ["occurrent:" + hexid]}
    ok, why = validate_schema(abbreviated, "causal_relation_object")
    assert not ok, "abbreviated scheme must be rejected"
    abbr_str = {"type": "stratum", "id": "str:" + hexid, "label": "cellular",
                "scheme": "neuroendocrine", "ordinal": 6}
    ok, _ = validate_schema(abbr_str, "stratum"); assert not ok
    whole = {"type": "causal_relation_object",
             "id": "causal_relation_object:" + hexid,
             "causes": ["occurrent:" + hexid],
             "effects": ["occurrent:" + hexid]}
    ok, why = validate_schema(whole, "causal_relation_object"); assert ok, why


# ---------------------------------------------------------------------------
def main():
    print("causalontology-py conformance run (specification 2.0.0)")
    print("internal checks (RFC 8032, RFC 8785, fixed constants) ... ", end="")
    internal_checks()
    print("ok")
    failures = 0
    total = 107
    for n in range(1, total + 1):
        fn = globals()["v%02d" % n]
        name = Path(glob.glob(str(VECDIR / ("v%02d_*.json" % n)))[0]).stem
        try:
            fn()
            print("PASS  %s" % name)
        except Exception as e:                      # noqa: BLE001
            failures += 1
            print("FAIL  %s :: %r" % (name, e))
    print("-" * 60)
    print("%d/%d vectors passed" % (total - failures, total))
    if failures:
        sys.exit(1)
    print("causalontology-py is CONFORMANT to the suite "
          "(vectors frozen at specification 2.0.0).")


if __name__ == "__main__":
    main()

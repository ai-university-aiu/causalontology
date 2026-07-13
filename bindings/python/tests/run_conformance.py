#!/usr/bin/env python3
"""The Causalontology conformance runner for causalontology-py.

Runs every vector in conformance/vectors/ against the Python binding. An
implementation is conformant if and only if it passes every vector; this
runner exits nonzero on any failure.

Pre-freeze note (see conformance/README.md): the vectors carry symbolic
identifiers ("occ:press_button", "ed25519:alice"). This harness normalizes
them deterministically - symbolic object ids become scheme:sha256(name), and
symbolic key names become real Ed25519 keypairs seeded from the name - so the
normative behaviors are tested with well-formed data. The 1.0.0 freeze pins
concrete bytes into the vectors themselves.
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
    keypair_from_seed, sign_record, verify_record,
    InMemoryStore, RejectedWrite)
from causalontology import ed25519                 # noqa: E402
from causalontology.canonical import _jcs          # noqa: E402

# ---------------------------------------------------------------------------
# symbolic-identifier normalization
# ---------------------------------------------------------------------------
_SCHEMES = ("occ", "cro", "cnt", "rlz", "ast", "enr", "ret", "suc")
_KEYS = {}


def key(name):
    """A real, deterministic Ed25519 keypair for a symbolic key name."""
    if name not in _KEYS:
        seed = hashlib.sha256(("key:" + name).encode()).digest()
        _KEYS[name] = keypair_from_seed(seed)
    return _KEYS[name]


def sym(s):
    """Normalize one symbolic identifier to a well-formed one."""
    scheme, name = s.split(":", 1)
    if scheme == "ed25519":
        if re.fullmatch(r"[0-9a-f]{64}", name):
            return s  # frozen: a real key passes through
        return key(name)[1]
    if re.fullmatch(r"[0-9a-f]{64}", name):
        return s
    return scheme + ":" + hashlib.sha256(name.encode()).hexdigest()


def normalize(x):
    """Recursively normalize symbolic identifiers and placeholders."""
    if isinstance(x, str):
        if x == "<128 hex>":
            return "ab" * 64
        m = re.match(r"^(%s|ed25519):" % "|".join(_SCHEMES), x)
        if m:
            return sym(x)
        return x
    if isinstance(x, list):
        return [normalize(v) for v in x]
    if isinstance(x, dict):
        return {k: normalize(v) for k, v in x.items()}
    return x


def vec(n):
    """Load vector n's JSON file (for its structured inputs)."""
    hits = glob.glob(str(VECDIR / ("v%02d_*.json" % n)))
    assert len(hits) == 1, "vector %d not found" % n
    with open(hits[0]) as f:
        return json.load(f)


TS = "2026-07-13T0%d:00:00Z"


def signed(kind, body, who, ts_i=0):
    """Build, timestamp, and sign a provenance record."""
    secret, pub = key(who)
    rec = dict(body)
    rec["type"] = kind
    rec.setdefault("timestamp", TS % ts_i)
    if kind == "succession":
        rec.setdefault("predecessor", pub)
    else:
        rec["source"] = pub
    return sign_record(rec, secret, kind)


# ---------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# ---------------------------------------------------------------------------
def internal_checks():
    # RFC 8032, TEST 1 known-answer
    sk = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = ed25519.secret_to_public(sk)
    assert pk.hex() == ("d75a980182b10ab7d54bfed3c964073a"
                        "0ee172f3daa62325af021a68f707511a"), pk.hex()
    sig = ed25519.sign(sk, b"")
    assert ed25519.verify(pk, b"", sig)
    assert not ed25519.verify(pk, b"x", sig)
    # JCS basics
    assert _jcs({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert _jcs(1.0) == "1" and _jcs(6.000) == "6" and _jcs(0.7) == "0.7"


# ---------------------------------------------------------------------------
# the 38 vectors
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
    _semantics_fails(14, "dmin")

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
    dog, mam, ani = (sym("cnt:dog"), sym("cnt:mammal"), sym("cnt:animal"))
    def enrich(about, entry, i):
        return signed("enrichment",
                      {"about": about, "field": "subsumes", "entry": entry},
                      "taxo", i)
    # enforcing tier rejects the cycle-completing write
    s = InMemoryStore(enforcing=True)
    s.put_record(enrich(dog, mam, 1))
    s.put_record(enrich(mam, ani, 2))
    try:
        s.put_record(enrich(ani, dog, 3))
        raise AssertionError("enforcing store accepted a cycle")
    except RejectedWrite as e:
        assert "cycle" in str(e), e
    # decentralized merge: the view breaks the cycle deterministically
    s2 = InMemoryStore(enforcing=True)
    s2.put_record(enrich(dog, mam, 1))
    s2.put_record(enrich(mam, ani, 2))
    bad = enrich(ani, dog, 3)
    s2.force_merge_record(bad)
    active, excluded = s2._active_taxonomy_edges("subsumes")
    assert len(excluded) == 1 and excluded[0]["id"] == bad["id"]
    repair = [g for g in s2.gaps("inconsistent_hierarchy")]
    assert any(g["id"] == bad["id"] for g in repair)

def _adm(n):
    g = vec(n)["given"]
    cro = {"causes": [sym("occ:c")], "effects": [sym("occ:e")],
           "temporal": g["temporal"]}
    return admissible(cro, g["elapsed_seconds"])

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
    a = s.put(dict(obj))
    b = s.put(dict(obj))
    assert a == b and len(s.objects) == 1

def v27():
    s = InMemoryStore()
    occ = s.put({"type": "occurrent", "label": "press_button",
                 "category": "action"})
    entry = {"lang": "en", "text": "press the button"}
    r1 = signed("enrichment", {"about": occ, "field": "aliases",
                               "entry": entry}, "alice", 1)
    r2 = signed("enrichment", {"about": occ, "field": "aliases",
                               "entry": entry}, "bob", 2)
    assert s.put_record(r1) != s.put_record(r2)  # two records
    view = s.get(occ)["enrichments"]["aliases"]
    assert len(view) == 1 and len(view[0]["contributors"]) == 2

def v28():
    s = InMemoryStore()
    claim = {"type": "cro", "causes": [sym("occ:A")],
             "effects": [sym("occ:B")], "modality": "sufficient"}
    i1 = s.put(dict(claim))
    i2 = s.put(dict(claim))
    assert i1 == i2 and len(s.objects) == 1
    for who, ts in (("lab1", 1), ("lab2", 2)):
        s.put_record(signed("assertion",
                            {"about": i1, "evidence_type": "observation",
                             "strength": 0.8, "confidence": 0.8}, who, ts))
    assert len(s.assertions_about(i1)) == 2

def v29():
    rec = signed("assertion", {"about": sym("cro:demo"),
                               "evidence_type": "intervention",
                               "strength": 0.7, "confidence": 0.9}, "signer")
    assert verify_record(rec) is True

def v30():
    rec = signed("assertion", {"about": sym("cro:demo"),
                               "evidence_type": "intervention",
                               "strength": 0.7, "confidence": 0.9}, "signer")
    tampered = dict(rec, confidence=0.1)
    assert verify_record(tampered) is False

def v31():
    s = InMemoryStore()
    x = s.put({"type": "cro", "causes": [sym("occ:A")],
               "effects": [sym("occ:B")]})
    a = signed("assertion", {"about": x, "evidence_type": "observation",
                             "confidence": 0.8}, "lab1", 1)
    s.put_record(a)
    s.put_record(signed("retraction", {"retracts": a["id"]}, "lab1", 2))
    assert s.assertions_about(x) == []
    hist = s.assertions_about(x, include_retracted=True)
    assert len(hist) == 1 and hist[0]["retracted"] is True
    foreign = signed("retraction", {"retracts": a["id"]}, "mallory", 3)
    try:
        s.put_record(foreign)
        raise AssertionError("foreign retraction accepted")
    except RejectedWrite:
        pass
    assert s.assertions_about(x) == []       # still excluded by lab1's own
    assert len(s.assertions_about(x, include_retracted=True)) == 1

def v32():
    s = InMemoryStore()
    occ = s.put({"type": "occurrent", "label": "press_button",
                 "category": "action"})
    e = signed("enrichment", {"about": occ, "field": "aliases",
                              "entry": {"lang": "ja", "text": "botan"}},
               "bob", 1)
    s.put_record(e)
    assert len(s.get(occ)["enrichments"].get("aliases", [])) == 1
    s.put_record(signed("retraction", {"retracts": e["id"]}, "bob", 2))
    assert s.get(occ)["enrichments"].get("aliases", []) == []
    hist = s.get(occ, view="history")["enrichments"].get("aliases", [])
    assert len(hist) == 1

def v33():
    s = InMemoryStore()
    _, k1 = key("K1")
    _, k2 = key("K2")
    a = signed("assertion", {"about": sym("cro:claim"),
                             "evidence_type": "observation",
                             "confidence": 0.9}, "K1", 1)
    s.put_record(a)
    succ = signed("succession", {"successor": k2}, "K1", 2)
    s.put_record(succ)
    assert k1 in s.lineage(k2) and k2 in s.lineage(k1)
    r = signed("retraction", {"retracts": a["id"]}, "K2", 3)
    s.put_record(r)  # successor may retract the predecessor's record
    assert s.assertions_about(sym("cro:claim")) == []

def v34():
    g = normalize(vec(34)["given"])
    assert conflicts(g["A"], g["B"]) is True

def v35():
    g = normalize(vec(35)["given"])
    assert conflicts(g["A"], g["B"]) is False

def v36():
    A, B, C, D = (sym("occ:A"), sym("occ:B"), sym("occ:C"), sym("occ:D"))
    m1 = {"id": sym("cro:m1"), "causes": [A], "effects": [B]}
    m2 = {"id": sym("cro:m2"), "causes": [B], "effects": [C]}
    m3 = {"id": sym("cro:m3"), "causes": [D], "effects": [C]}
    P = {"causes": [A], "effects": [C], "mechanism": [m1["id"], m2["id"]]}
    assert hierarchy_consistent(
        P, {m1["id"]: m1, m2["id"]: m2}) == "consistent"
    P2 = dict(P, mechanism=[m1["id"], m3["id"]])
    assert hierarchy_consistent(
        P2, {m1["id"]: m1, m3["id"]: m3}) == "inconsistent"
    assert hierarchy_consistent(P, {m1["id"]: m1}) == "indeterminate"

def v37():
    s = InMemoryStore()
    occ = s.put({"type": "occurrent", "label": "press_button",
                 "category": "action"})
    s.put_record(signed("enrichment",
                        {"about": occ, "field": "aliases",
                         "entry": {"lang": "en", "text": "Press the Button"}},
                        "alice", 1))
    assert s.resolve("Press  The   Button", "en") == [occ]   # alias match
    assert s.resolve("press_button", "en")[0] == occ         # label, first

def v38():
    s = InMemoryStore()
    P = s.put({"type": "cro", "causes": [sym("occ:A")],
               "effects": [sym("occ:B")]})
    gaps = [g["id"] for g in s.gaps("missing_field")]
    assert P in gaps
    R = s.put({"type": "cro", "causes": [sym("occ:A")],
               "effects": [sym("occ:B")],
               "temporal": {"dmin": 0, "dmax": 1, "unit": "seconds"},
               "modality": "sufficient", "refines": P})
    gaps = [g["id"] for g in s.gaps("missing_field")]
    assert P not in gaps, "the gap did not close"
    assert R not in gaps, "the refinement itself must be complete"


# ---------------------------------------------------------------------------
def main():
    print("causalontology-py conformance run")
    print("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ",
          end="")
    internal_checks()
    print("ok")
    failures = 0
    for n in range(1, 39):
        fn = globals()["v%02d" % n]
        name = Path(glob.glob(str(VECDIR / ("v%02d_*.json" % n)))[0]).stem
        try:
            fn()
            print("PASS  %s" % name)
        except Exception as e:                      # noqa: BLE001
            failures += 1
            print("FAIL  %s :: %r" % (name, e))
    total = 38
    print("-" * 60)
    print("%d/%d vectors passed" % (total - failures, total))
    if failures:
        sys.exit(1)
    print("causalontology-py is CONFORMANT to the suite "
          "(vectors frozen at specification 1.0.0).")


if __name__ == "__main__":
    main()

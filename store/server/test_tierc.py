#!/usr/bin/env python3
"""Tier C test: the CRDT laws, proven on real bundles.

Three replicas write concurrently - including the classic adversary, a
taxonomy cycle formed only by the UNION of writes no single replica would
accept. Merging in every order must produce byte-identical bundles and
identical materialized views, with the same deterministically chosen
cycle-loser everywhere. Plus: tamper evidence via content addressing and
signatures.
"""

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "bindings" / "python"))
sys.path.insert(0, str(HERE.parent))

from causalontology import (InMemoryStore, keypair_from_seed,      # noqa: E402
                            sign_record, identify)
import replicate                                                    # noqa: E402

checks = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


def key(name):
    return keypair_from_seed(hashlib.sha256(("key:" + name).encode()).digest())


def cnt(label):
    return {"type": "continuant", "label": label, "category": "object"}


def bundle_of(store):
    return {"objects": list(store.objects.values()),
            "records": list(store.records.values())}


def canon(bundle):
    return json.dumps(
        {"objects": sorted(bundle["objects"], key=lambda o: o["id"]),
         "records": sorted(bundle["records"], key=lambda r: r["id"])},
        sort_keys=True)


def main():
    dog, mammal, animal = cnt("dog"), cnt("mammal"), cnt("animal")
    ids = {}
    for name, obj in (("dog", dog), ("mammal", mammal), ("animal", animal)):
        ids[name] = identify(obj)

    def enrich(who, about, entry, ts):
        sk, src = key(who)
        return sign_record({"type": "enrichment", "about": ids[about],
                            "field": "subsumes", "entry": ids[entry],
                            "source": src,
                            "timestamp": "2026-07-13T0%d:00:00Z" % ts}, sk)

    # three replicas, concurrent writes; the cycle exists only in the union
    r1, r2, r3 = InMemoryStore(), InMemoryStore(), InMemoryStore()
    for r in (r1, r2, r3):
        for obj in (dog, mammal, animal):
            r.put(dict(obj))
    r1.put_record(enrich("ann", "dog", "mammal", 1))
    r2.put_record(enrich("ben", "mammal", "animal", 2))
    bad = enrich("cal", "animal", "dog", 3)        # innocent alone...
    r3.put_record(bad)                             # ...accepted by replica 3
    sk_a, alice = key("ann")
    r1.put_record(sign_record({"type": "assertion", "about": ids["dog"],
                               "source": alice,
                               "evidence_type": "observation",
                               "confidence": 0.9,
                               "timestamp": "2026-07-13T04:00:00Z"}, sk_a))

    b1, b2, b3 = bundle_of(r1), bundle_of(r2), bundle_of(r3)

    # the CRDT laws
    ab_c = replicate.merge(replicate.merge(b1, b2), b3)
    c_ba = replicate.merge(b3, replicate.merge(b2, b1))
    check("merge order does not matter (commutative + associative)",
          canon(ab_c) == canon(c_ba))
    check("merge is idempotent (A u A = A)",
          canon(replicate.merge(b1, b1)) == canon(b1))

    # every replica, given the union, breaks the cycle the SAME way
    losers = set()
    for bundle in (ab_c, c_ba, replicate.merge(b2, b3, b1)):
        store = replicate.as_store(bundle)
        _, excluded = store._active_taxonomy_edges("subsumes")
        losers.add(tuple(sorted(r["id"] for r in excluded)))
    check("deterministic cycle-breaking is identical on every replica",
          losers == {(bad["id"],)})
    check("the excluded record is the latest-timestamp cycle-completer",
          list(losers)[0][0] == bad["id"])

    # views converge: dog's materialized taxonomy is the same everywhere
    views = set()
    for bundle in (ab_c, c_ba):
        store = replicate.as_store(bundle)
        views.add(json.dumps(store.get(ids["dog"])["enrichments"],
                             sort_keys=True))
    check("materialized views converge", len(views) == 1)

    # tamper evidence: content addressing + signatures
    ok, _ = replicate.verify(ab_c)
    check("clean union verifies (ids + signatures)", ok)
    tampered = json.loads(json.dumps(ab_c))
    for rec in tampered["records"]:
        if rec["type"] == "assertion":
            rec["confidence"] = 0.1                 # the lie
            break
    ok, report = replicate.verify(tampered)
    check("a tampered record is caught by its signature",
          not ok and len(report["bad_signatures"]) == 1)
    tampered2 = json.loads(json.dumps(ab_c))
    tampered2["objects"][0]["label"] = "cat"        # forge content, keep id
    ok, report = replicate.verify(tampered2)
    check("a forged object is caught by its content address",
          not ok and len(report["bad_ids"]) == 1)

    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d Tier C checks passed" % (len(checks) - len(failed),
                                          len(checks)))
    if failed:
        sys.exit(1)
    print("Tier C: replicas converge without a coordinator - "
          "the data model is the consensus.")


if __name__ == "__main__":
    main()

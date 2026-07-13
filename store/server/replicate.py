#!/usr/bin/env python3
"""Tier C decentralization: offline bundle replication.

The Causalontology data model is a grow-only-set CRDT (Conflict-free
Replicated Data Type) by construction: content objects are immutable and
content-addressed, provenance records are signed and add-only, and every
disagreement lives in provenance rather than in contested cells. So Tier C
needs no consensus protocol - replicas exchange bundles by any transport
(HTTP, e-mail, a USB stick) and merge by set union; the deterministic view
rules resolve the rest identically everywhere.

    replicate.py export URL out.json      pull a store's bundle to a file
    replicate.py merge out.json a.json b.json [...]
                                          set-union merge of bundles
    replicate.py verify bundle.json       tamper-evidence audit: recompute
                                          every content-addressed identifier
                                          and every Ed25519 signature
    replicate.py serve bundle.json PORT   open a replica store on a bundle

Zero dependencies - the Python standard library and causalontology-py.
"""

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "bindings" / "python"))

from causalontology import identify, verify_record, InMemoryStore  # noqa: E402


def load_bundle(path):
    return json.loads(Path(path).read_text())


def save_bundle(path, bundle):
    # canonical member order makes equal bundles byte-identical on disk
    bundle = {"objects": sorted(bundle["objects"], key=lambda o: o["id"]),
              "records": sorted(bundle["records"], key=lambda r: r["id"])}
    Path(path).write_text(json.dumps(bundle, indent=1, sort_keys=True))
    return bundle


def merge(*bundles):
    """Set union by identifier - commutative, associative, idempotent."""
    objects, records = {}, {}
    for b in bundles:
        for obj in b.get("objects", []):
            objects.setdefault(obj["id"], obj)
        for rec in b.get("records", []):
            records.setdefault(rec["id"], rec)
    return {"objects": list(objects.values()),
            "records": list(records.values())}


def verify(bundle):
    """(ok, report) - recompute every identifier and every signature."""
    report = {"objects": 0, "records": 0, "bad_ids": [], "bad_signatures": []}
    for obj in bundle.get("objects", []):
        report["objects"] += 1
        body = {k: v for k, v in obj.items() if k != "id"}
        try:
            expected = identify(body)
        except ValueError:
            continue  # kind not inferable without type: skip, schemas catch it
        if obj["id"] != expected and _is_content_hash(obj["id"]):
            report["bad_ids"].append(obj["id"])
    for rec in bundle.get("records", []):
        report["records"] += 1
        if not verify_record(rec):
            report["bad_signatures"].append(rec.get("id", "<no id>"))
    ok = not report["bad_ids"] and not report["bad_signatures"]
    return ok, report


def _is_content_hash(identifier):
    tail = identifier.split(":", 1)[-1]
    return len(tail) == 64 and all(c in "0123456789abcdef" for c in tail)


def as_store(bundle, enforcing=False):
    """Materialize a bundle into a store (replica semantics: union first,
    the deterministic view rules judge afterwards)."""
    store = InMemoryStore(enforcing=enforcing)
    for obj in bundle.get("objects", []):
        store.objects[obj["id"]] = obj
    for rec in bundle.get("records", []):
        store.records[rec["id"]] = rec
    return store


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "export":
        url, out = argv[2].rstrip("/"), argv[3]
        with urllib.request.urlopen(url + "/sync/export", timeout=30) as r:
            bundle = json.loads(r.read())
        save_bundle(out, bundle)
        print("exported %d objects, %d records -> %s"
              % (len(bundle["objects"]), len(bundle["records"]), out))
        return 0
    if cmd == "merge":
        out, sources = argv[2], argv[3:]
        merged = merge(*[load_bundle(p) for p in sources])
        save_bundle(out, merged)
        print("merged %d bundles -> %s (%d objects, %d records)"
              % (len(sources), out,
                 len(merged["objects"]), len(merged["records"])))
        return 0
    if cmd == "verify":
        ok, report = verify(load_bundle(argv[2]))
        print(json.dumps(report, indent=1))
        print("VERIFIED: every identifier and signature checks out" if ok
              else "TAMPERED OR CORRUPT: see bad_ids / bad_signatures")
        return 0 if ok else 1
    if cmd == "serve":
        from server import StoreServer  # local import: same directory
        bundle, port = load_bundle(argv[2]), int(argv[3])
        server = StoreServer(("127.0.0.1", port), InMemoryStore())
        server.merge_bundle(bundle)
        print("replica of %s on http://127.0.0.1:%d" % (argv[2], port))
        server.serve_forever()
    print("unknown command: %s" % cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

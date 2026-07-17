#!/usr/bin/env python3
"""Verify a snapshot dump and stand up a mirror from it (Phase two, Part 21).

Given a snapshot's body and manifest, verify EVERYTHING before touching a
store: the manifest signature (optionally pinned to a publisher you trust), the
Merkle root recomputed from the delivered bytes, every content object's
identifier against the hash of its own bytes, and every provenance record's
Ed25519 signature. Only if all of that passes is the snapshot merged, by set
union, into the target store. Any failure aborts with a clear error and nothing
partial is written. Importing the same snapshot twice is a no-op.

    # verify only, no store needed - prove a downloaded dump before trusting it
    python3 snapshot_import.py --dir dumps --verify-only

    # verify and mirror into a fresh persistent node
    python3 snapshot_import.py --dir dumps --db mirror.db

    # pin the publisher: reject anything not signed by this exact key
    python3 snapshot_import.py --dir dumps --db mirror.db \
        --trust ed25519:<hex>

Point at the files with --dir DIR (+ --name, default commons) or explicitly
with --body FILE --manifest FILE.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "bindings" / "python"))

import snapshot as snap                                         # noqa: E402
from causalontology import InMemoryStore                        # noqa: E402


def _resolve_paths(args):
    if args.body and args.manifest:
        return Path(args.body), Path(args.manifest)
    if args.dir:
        d = Path(args.dir)
        return (d / ("%s.snapshot.ndjson" % args.name),
                d / ("%s.snapshot.manifest.json" % args.name))
    sys.exit("point at the snapshot: --dir DIR [--name NAME] "
             "or --body FILE --manifest FILE")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", help="directory holding the snapshot files")
    ap.add_argument("--name", default="commons", help="artifact base name")
    ap.add_argument("--body", help="explicit path to the .ndjson body")
    ap.add_argument("--manifest", help="explicit path to the .manifest.json")
    ap.add_argument("--db", help="mirror into this persistent SQLite store")
    ap.add_argument("--in-memory", action="store_true",
                    help="mirror into a volatile in-memory store (for checking)")
    ap.add_argument("--trust", help="require signed_by to equal this ed25519: key")
    ap.add_argument("--verify-only", action="store_true",
                    help="verify the dump and report; do not import")
    args = ap.parse_args(argv)

    body_path, manifest_path = _resolve_paths(args)
    body = body_path.read_bytes()
    manifest = json.loads(manifest_path.read_text())

    if args.verify_only or (not args.db and not args.in_memory):
        ok, report = snap.verify_snapshot(body, manifest, trust=args.trust)
        print(json.dumps(report, indent=1))
        if ok:
            print("VERIFIED: manifest signature, Merkle root, every identifier "
                  "and every signature check out (%d content, %d provenance)"
                  % (report["content_objects"], report["provenance_records"]))
            return 0
        print("REJECTED: this snapshot did not verify - see errors / bad_ids / "
              "bad_signatures above")
        return 1

    if args.db:
        from storage import PersistentStore
        store = PersistentStore(db_path=args.db)
        closer = store.close
    else:
        store = InMemoryStore()
        closer = lambda: None  # noqa: E731

    try:
        result = snap.import_snapshot(body, manifest, store, trust=args.trust)
    except snap.SnapshotError as e:
        print("REJECTED: %s" % e)
        closer()
        return 1

    print("MIRRORED: snapshot verified and union-merged (Merkle root %s)"
          % result["merkle_root"])
    print("  content objects: %d added, %d already present"
          % (result["content_added"], result["content_present"]))
    print("  provenance records: %d added, %d already present"
          % (result["records_added"], result["records_present"]))
    closer()
    return 0


if __name__ == "__main__":
    sys.exit(main())

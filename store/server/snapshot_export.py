#!/usr/bin/env python3
"""Export a signed snapshot dump of the commons (Phase two, Part 21).

Read a store - the persistent Tier A node of Phase one, or a plain
{objects, records} bundle - and write a snapshot dump: the body, its signed
manifest, a detached SHA-256 checksum file, and a detached signature. The four
files together are the published artifact; anyone can verify them and stand up
a mirror with snapshot_import.py, with no access to this store.

    # generate a genesis-node signing key once, keep the seed file private
    python3 snapshot_export.py --gen-key genesis.seed

    # export the default (shareable) snapshot from the persistent node
    python3 snapshot_export.py --db store/server/data/causalontology.db \
        --seed-file genesis.seed --out dumps

    # export from a bundle (e.g. a Tier B /sync/export dump)
    python3 snapshot_export.py --from-bundle bundle.json \
        --seed-file genesis.seed --out dumps

The token tier is EXCLUDED BY DEFAULT (privacy, spec/safety.md). Pass
--include-tokens only on an operator's explicit opt-in; the manifest records
which was chosen.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))                                   # snapshot, storage
sys.path.insert(0, str(HERE.parents[1] / "bindings" / "python"))

import snapshot as snap                                         # noqa: E402
from causalontology import InMemoryStore                        # noqa: E402


def _load_seed(args):
    """The 32-byte Ed25519 seed for the publishing key, from a file (hex or
    raw bytes) or from --seed-hex."""
    if args.seed_hex:
        seed = bytes.fromhex(args.seed_hex.strip())
    elif args.seed_file:
        raw = Path(args.seed_file).read_bytes()
        text = raw.strip()
        if len(text) == 64 and all(c in b"0123456789abcdefABCDEF" for c in text):
            seed = bytes.fromhex(text.decode())
        else:
            seed = raw
    else:
        sys.exit("no signing key: pass --seed-file or --seed-hex "
                 "(generate one with --gen-key PATH)")
    if len(seed) != 32:
        sys.exit("signing seed must be exactly 32 bytes (got %d)" % len(seed))
    return seed


def _store_from_bundle(path):
    bundle = json.loads(Path(path).read_text())
    store = InMemoryStore(enforcing=False)
    for obj in bundle.get("objects", []):
        store.objects[obj["id"]] = obj
    for rec in bundle.get("records", []):
        store.records[rec["id"]] = rec
    return store


def _store_from_db(db_path):
    from storage import PersistentStore  # local import: standard-library only
    return PersistentStore(db_path=db_path, enforcing=False)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gen-key", metavar="PATH",
                    help="write a fresh 32-byte hex signing seed to PATH and exit")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--db", help="persistent SQLite store to snapshot")
    src.add_argument("--from-bundle",
                     help="a {objects, records} JSON bundle to snapshot")
    ap.add_argument("--seed-file", help="file holding the 32-byte signing seed")
    ap.add_argument("--seed-hex", help="the 32-byte signing seed as 64 hex chars")
    ap.add_argument("--out", default="dumps", help="output directory (default dumps/)")
    ap.add_argument("--name", default="commons",
                    help="artifact base name (default commons)")
    ap.add_argument("--include-tokens", action="store_true",
                    help="OPT-IN: include the token tier (default excludes it)")
    ap.add_argument("--created-at",
                    help="override the created-at UTC timestamp (for reproducible "
                         "example dumps); excluded from the Merkle root either way")
    args = ap.parse_args(argv)

    if args.gen_key:
        Path(args.gen_key).write_text(os.urandom(32).hex() + "\n")
        try:
            os.chmod(args.gen_key, 0o600)
        except OSError:
            pass
        print("wrote a fresh signing seed to %s (keep it private)" % args.gen_key)
        return 0

    if not args.db and not args.from_bundle:
        ap.error("choose a source: --db PATH or --from-bundle FILE")

    seed = _load_seed(args)
    store = (_store_from_bundle(args.from_bundle) if args.from_bundle
             else _store_from_db(args.db))

    body, manifest = snap.export_snapshot(
        store, seed, include_tokens=args.include_tokens,
        created_at=args.created_at)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    body_name = "%s.snapshot.ndjson" % args.name
    manifest_name = "%s.snapshot.manifest.json" % args.name
    sha_name = "%s.snapshot.sha256" % args.name
    sig_name = "%s.snapshot.sig" % args.name

    manifest_bytes = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
    (out_dir / body_name).write_bytes(body)
    (out_dir / manifest_name).write_bytes(manifest_bytes)
    (out_dir / sha_name).write_text(
        snap.checksum_file(body, manifest_bytes, body_name, manifest_name))
    (out_dir / sig_name).write_text(manifest["signature"] + "\n")

    if hasattr(store, "close"):
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass

    print("snapshot written to %s/" % out_dir)
    print("  %-32s %d content objects, %d provenance records%s"
          % (body_name, manifest["content_objects"], manifest["provenance_records"],
             " (+ token tier)" if manifest["includes_tokens"] else ""))
    print("  %-32s Merkle root %s" % (manifest_name, manifest["merkle_root"]))
    print("  %-32s detached checksums" % sha_name)
    print("  %-32s detached signature by %s" % (sig_name, manifest["signed_by"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

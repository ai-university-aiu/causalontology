#!/usr/bin/env python3
"""Snapshot tests for the genesis node (Phase two, Part 21).

Proves the six properties a signed snapshot dump must have, so that anyone can
download it, verify every byte, and stand up a mirror:

  (a) ROUND-TRIP EQUALITY - export from a populated store, import into a fresh
      EMPTY store, and the two hold the identical set of identifiers and serve
      byte-identical objects and records.
  (b) DETERMINISM / REPRODUCIBLE BYTES - exporting the same store twice yields
      a byte-identical body and an identical Merkle root (created-at excluded).
  (c) TAMPER DETECTION - flip a single byte in the body and the import ABORTS;
      nothing partially loads.
  (d) SIGNATURE VERIFICATION - a manifest signed by the wrong key, or with no
      signature at all, is rejected.
  (e) IDEMPOTENT IMPORT - importing the same valid snapshot twice leaves the
      store unchanged after the first.
  (f) TOKEN-TIER EXCLUSION - a default snapshot of a store holding token-tier
      records excludes them; the opt-in path includes them only when enabled.

Plus a seventh check: the small committed example under dumps/example/ verifies
and round-trips, so the published artifact format is exercised end to end.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))
sys.path.insert(0, str(HERE.parent))

from causalontology import (InMemoryStore, keypair_from_seed,       # noqa: E402
                            sign_record, ed25519)
import snapshot as snap                                             # noqa: E402
from snapshot import _manifest_signing_bytes                        # noqa: E402

# A fixed seed and timestamp so the committed example is reproducible.
EXAMPLE_SEED = hashlib.sha256(b"causalontology-genesis-node").digest()
EXAMPLE_CREATED_AT = "2026-07-16T00:00:00Z"
EXAMPLE_DIR = ROOT / "dumps" / "example"

checks = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


# ---------------------------------------------------------------------------
# a small, fully-populated fixture: type-tier content + provenance, and one
# token-tier individual with an assertion about it (to prove exclusion)
# ---------------------------------------------------------------------------
def build_fixture_store():
    sk, alice = keypair_from_seed(EXAMPLE_SEED)
    store = InMemoryStore()
    press = store.put({"type": "occurrent", "label": "press_button",
                       "category": "action"})
    light = store.put({"type": "occurrent", "label": "light_on",
                       "category": "state_change"})
    cro = store.put({"type": "causal_relation_object",
                     "causes": [press], "effects": [light]})
    button = store.put({"type": "continuant", "label": "button_one",
                        "category": "object"})
    store.put_record(sign_record(
        {"type": "assertion", "about": cro, "source": alice,
         "evidence_type": "observation", "confidence": 0.8,
         "timestamp": "2026-07-13T04:00:00Z"}, sk))
    store.put_record(sign_record(
        {"type": "enrichment", "about": press, "field": "aliases",
         "entry": {"lang": "en", "text": "Press the Button"}, "source": alice,
         "timestamp": "2026-07-13T04:01:00Z"}, sk))
    # token tier: a particular button, and an assertion ABOUT it. Both must be
    # left out of a default snapshot (local-by-default, spec/safety.md).
    token = store.put({"type": "token_individual", "instantiates": button,
                       "designator": "a" * 64})
    store.put_record(sign_record(
        {"type": "assertion", "about": token, "source": alice,
         "evidence_type": "observation", "confidence": 0.9,
         "timestamp": "2026-07-13T04:02:00Z"}, sk))
    return store, sk


# ---------------------------------------------------------------------------
def test_round_trip():
    """(a) export -> import into an empty store -> identical holdings."""
    store, sk = build_fixture_store()
    body, manifest = snap.export_snapshot(store, sk,
                                          created_at=EXAMPLE_CREATED_AT)
    mirror = InMemoryStore()
    snap.import_snapshot(body, manifest, mirror)

    # the default snapshot is the shareable commons: type tier only
    src_ids = {oid for oid, o in store.objects.items()
               if not snap.is_token_content(o)}
    src_recs = {rid for rid, r in store.records.items()
                if not snap.record_touches_token(r)}
    check("(a) mirror holds the identical set of content identifiers",
          set(mirror.objects.keys()) == src_ids)
    check("(a) mirror holds the identical set of provenance identifiers",
          set(mirror.records.keys()) == src_recs)
    same_objs = all(snap.canonical_line(store.objects[i])
                    == snap.canonical_line(mirror.objects[i]) for i in src_ids)
    same_recs = all(snap.canonical_line(store.records[i])
                    == snap.canonical_line(mirror.records[i]) for i in src_recs)
    check("(a) mirror serves byte-identical objects and records",
          same_objs and same_recs)
    # and the mirror re-exports to the very same Merkle root
    body2, manifest2 = snap.export_snapshot(mirror, sk,
                                            created_at=EXAMPLE_CREATED_AT)
    check("(a) the mirror re-exports the identical Merkle root",
          manifest2["merkle_root"] == manifest["merkle_root"] and body2 == body)


def test_determinism():
    """(b) same store, two exports -> identical body and Merkle root; only the
    created-at differs (and it is excluded from the root)."""
    store, sk = build_fixture_store()
    body1, m1 = snap.export_snapshot(store, sk, created_at="2026-07-16T00:00:00Z")
    body2, m2 = snap.export_snapshot(store, sk, created_at="2026-08-01T12:34:56Z")
    check("(b) exporting the same store twice yields a byte-identical body",
          body1 == body2)
    check("(b) the Merkle root is identical across exports",
          m1["merkle_root"] == m2["merkle_root"])
    check("(b) the created-at is excluded from the Merkle root (roots equal "
          "though timestamps differ)",
          m1["created_at"] != m2["created_at"]
          and m1["merkle_root"] == m2["merkle_root"])


def test_tamper():
    """(c) a single flipped byte in the body aborts the import; nothing loads."""
    store, sk = build_fixture_store()
    body, manifest = snap.export_snapshot(store, sk,
                                          created_at=EXAMPLE_CREATED_AT)
    # flip a byte somewhere inside the first object line
    flip_at = body.index(b"{") + 5
    tampered = bytearray(body)
    tampered[flip_at] ^= 0x01
    mirror = InMemoryStore()
    aborted = False
    try:
        snap.import_snapshot(bytes(tampered), manifest, mirror)
    except snap.SnapshotError:
        aborted = True
    check("(c) a flipped body byte aborts the import (Merkle root or a per-"
          "object hash fails)", aborted)
    check("(c) nothing partially loaded from the tampered snapshot",
          len(mirror.objects) == 0 and len(mirror.records) == 0)

    # also: retamper one object's content so its own identifier no longer holds
    entries, _ = snap.parse_body(body)
    victim = next(e for e in entries if e.get("type") == "occurrent")
    victim = dict(victim, label="TAMPERED_LABEL")           # id no longer matches
    lines = [snap.canonical_line(victim if e["id"] == victim["id"] else e)
             for e in entries]
    forged_body = b"".join(l + b"\n" for l in lines)
    # re-sign a manifest over the forged body's real root so the SIGNATURE is
    # valid but the per-object identity check must still catch the edit
    forged_root = snap.merkle_root(lines)
    forged_manifest = dict(manifest, merkle_root=forged_root)
    forged_manifest = snap.sign_manifest(
        {k: v for k, v in forged_manifest.items()
         if k not in ("signature", "signed_by")}, sk)
    caught = False
    try:
        snap.import_snapshot(forged_body, forged_manifest, InMemoryStore())
    except snap.SnapshotError:
        caught = True
    check("(c) an object edited to break its own content address is caught "
          "even under a validly-signed manifest", caught)


def test_signature():
    """(d) wrong-key and unsigned manifests are rejected."""
    store, sk = build_fixture_store()
    body, manifest = snap.export_snapshot(store, sk,
                                          created_at=EXAMPLE_CREATED_AT)
    check("(d) the honestly-signed manifest verifies",
          snap.verify_manifest_signature(manifest))

    wrong_sk, _ = keypair_from_seed(hashlib.sha256(b"impostor").digest())
    forged = dict(manifest)
    forged["signature"] = ed25519.sign(
        wrong_sk, _manifest_signing_bytes(manifest)).hex()
    check("(d) a manifest whose signature is from the wrong key is rejected",
          not snap.verify_manifest_signature(forged))

    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    check("(d) a manifest with no signature is rejected",
          not snap.verify_manifest_signature(unsigned))

    # import must refuse both, loading nothing
    refused = False
    try:
        snap.import_snapshot(body, forged, InMemoryStore())
    except snap.SnapshotError:
        refused = True
    check("(d) import refuses a wrong-key manifest", refused)

    # and the trust-pin: a good signature by an unexpected publisher is refused
    other_sk, _ = keypair_from_seed(hashlib.sha256(b"another-node").digest())
    _, other_pub = keypair_from_seed(hashlib.sha256(b"another-node").digest())
    check("(d) the trust pin rejects a snapshot signed by an unpinned key",
          not snap.verify_manifest_signature(manifest, trust=other_pub))
    check("(d) the trust pin accepts the expected publisher",
          snap.verify_manifest_signature(manifest, trust=manifest["signed_by"]))


def test_idempotent():
    """(e) importing the same valid snapshot twice changes nothing after the
    first."""
    store, sk = build_fixture_store()
    body, manifest = snap.export_snapshot(store, sk,
                                          created_at=EXAMPLE_CREATED_AT)
    mirror = InMemoryStore()
    first = snap.import_snapshot(body, manifest, mirror)
    snapshot_ids = (set(mirror.objects.keys()), set(mirror.records.keys()))
    second = snap.import_snapshot(body, manifest, mirror)
    check("(e) the first import loads the snapshot",
          first["content_added"] > 0 and first["records_added"] > 0)
    check("(e) the second import adds nothing (idempotent by content address)",
          second["content_added"] == 0 and second["records_added"] == 0)
    check("(e) the store is unchanged after the second import",
          (set(mirror.objects.keys()), set(mirror.records.keys()))
          == snapshot_ids)


def test_token_exclusion():
    """(f) token tier out by default; in only on explicit opt-in."""
    store, sk = build_fixture_store()
    has_token_obj = any(snap.is_token_content(o)
                        for o in store.objects.values())
    check("(f) the fixture store really does contain a token-tier object",
          has_token_obj)

    body, manifest = snap.export_snapshot(store, sk,
                                          created_at=EXAMPLE_CREATED_AT)
    entries, _ = snap.parse_body(body)
    no_tokens = not any(e.get("type") in snap.TOKEN_SCHEMES for e in entries)
    no_token_recs = not any(snap.record_touches_token(e)
                            for e in entries if e.get("type") in
                            {"assertion", "enrichment", "retraction", "succession"})
    check("(f) the default snapshot excludes every token-tier content object",
          no_tokens and not manifest["includes_tokens"])
    check("(f) the default snapshot excludes provenance about token records",
          no_token_recs)

    inc_body, inc_manifest = snap.export_snapshot(
        store, sk, include_tokens=True, created_at=EXAMPLE_CREATED_AT)
    inc_entries, _ = snap.parse_body(inc_body)
    has_tokens = any(e.get("type") in snap.TOKEN_SCHEMES for e in inc_entries)
    check("(f) the opt-in snapshot includes the token tier when enabled",
          has_tokens and inc_manifest["includes_tokens"]
          and inc_manifest["content_objects"] > manifest["content_objects"])


def test_committed_example():
    """The published artifact under dumps/example/ verifies and round-trips."""
    body_path = EXAMPLE_DIR / "commons.snapshot.ndjson"
    manifest_path = EXAMPLE_DIR / "commons.snapshot.manifest.json"
    sha_path = EXAMPLE_DIR / "commons.snapshot.sha256"
    if not (body_path.exists() and manifest_path.exists()):
        check("(g) committed example snapshot is present", False)
        return
    body = body_path.read_bytes()
    manifest = json.loads(manifest_path.read_text())
    ok, report = snap.verify_snapshot(body, manifest)
    check("(g) the committed example snapshot verifies end to end", ok)

    # the detached checksum file matches the delivered bytes
    manifest_bytes = manifest_path.read_bytes()
    expect = snap.checksum_file(body, manifest_bytes,
                                "commons.snapshot.ndjson",
                                "commons.snapshot.manifest.json")
    check("(g) the detached SHA-256 checksum file matches the dump",
          sha_path.read_text() == expect)

    mirror = InMemoryStore()
    snap.import_snapshot(body, manifest, mirror)
    check("(g) a mirror stood up from the committed example holds its objects "
          "and records",
          len(mirror.objects) == manifest["content_objects"]
          and len(mirror.records) == manifest["provenance_records"])


# ---------------------------------------------------------------------------
def write_example():
    """(Re)generate the small committed example dump under dumps/example/."""
    store, sk = build_fixture_store()
    body, manifest = snap.export_snapshot(store, sk,
                                          created_at=EXAMPLE_CREATED_AT)
    EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    body_name = "commons.snapshot.ndjson"
    manifest_name = "commons.snapshot.manifest.json"
    manifest_bytes = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
    (EXAMPLE_DIR / body_name).write_bytes(body)
    (EXAMPLE_DIR / manifest_name).write_bytes(manifest_bytes)
    (EXAMPLE_DIR / "commons.snapshot.sha256").write_text(
        snap.checksum_file(body, manifest_bytes, body_name, manifest_name))
    (EXAMPLE_DIR / "commons.snapshot.sig").write_text(manifest["signature"] + "\n")
    print("wrote committed example to %s/" % EXAMPLE_DIR)


def main():
    if "--write-example" in sys.argv:
        write_example()
        return 0
    test_round_trip()
    test_determinism()
    test_tamper()
    test_signature()
    test_idempotent()
    test_token_exclusion()
    test_committed_example()
    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    print("-" * 60)
    print("%d/%d snapshot checks passed" % (passed, total))
    if passed == total:
        print("Genesis node: signed snapshot dumps are deterministic, self-"
              "verifying, tamper-evident, idempotent, and token-safe.")
        return 0
    print("SNAPSHOT TESTS FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())

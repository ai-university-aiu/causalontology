#!/usr/bin/env python3
"""Signed, content-addressed snapshots of the commons.

Phase two of Part 21 of the canon (Commons Storage and Federation Design):
DURABILITY BEFORE ADOPTION. A snapshot is a point-in-time bag of the
commons - every content object and every provenance record - serialized in a
deterministic, streamable form, committed as a whole by one Merkle root, and
authenticated by an Ed25519 signature over its manifest. Anyone can download a
snapshot, verify every byte against the hashes and the manifest signature, and
stand up a mirror by importing it. This gives the commons global redundancy
BEFORE a single live peer is recruited.

The guiding discipline (canon 21.5): a snapshot must be SELF-VERIFYING and
REPRODUCIBLE.

  - Every content object proves itself by its own identifier
    (identifier == scheme + ":" + SHA-256 of its canonical identity-bearing
    bytes, spec/identity.md).
  - Every provenance record proves itself by its own Ed25519 signature
    (spec/provenance.md).
  - The snapshot as a whole is committed by a Merkle root over the sorted
    body and authenticated by a signature over the manifest.
  - The same store always exports a byte-identical body and an identical
    Merkle root (deterministic ordering); the created-at timestamp is the
    only non-reproducible field, and it is EXCLUDED from the root so the root
    is content-only.
  - Importing a snapshot into an empty store reconstructs it exactly, by set
    union, with nothing trusted that cannot be verified. Any verification
    failure aborts the import; a tampered snapshot never partially loads.

PRIVACY - the token tier is excluded by default. A default snapshot is the
SHAREABLE COMMONS: type-tier content plus the provenance about it. Token-tier
records (token_individual, token_occurrence, state_assertion,
token_causal_claim, and - 4.0.0 - attitude, predicted_occurrence,
prediction_error) and any provenance that references them are left out unless
the operator explicitly opts in. This is the standard's local-by-default rule
(spec/safety.md) made concrete: a snapshot is exactly the "laws, not diaries"
boundary.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "bindings" / "python"))

from causalontology import identify, verify_record, infer_kind  # noqa: E402
from causalontology import __version__ as SPEC_VERSION           # noqa: E402
from causalontology import ed25519                               # noqa: E402

# The snapshot-format version - the shape of the manifest and body, versioned
# independently of the specification (which the manifest also records).
SNAPSHOT_FORMAT = "1.0"

# The token tier: content kinds that are LOCAL BY DEFAULT (spec/safety.md R1).
# A default snapshot excludes these content objects and any provenance record
# that references one of them.
TOKEN_SCHEMES = frozenset({
    "token_individual", "token_occurrence",
    "state_assertion", "token_causal_claim",
    "attitude", "predicted_occurrence", "prediction_error",
})

# The two record classes, discriminated by the "type" field on import so the
# body is self-describing (no separate section headers to keep in step).
CONTENT_KINDS = frozenset({
    "occurrent", "causal_relation_object", "continuant", "realizable",
    "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality",
    "token_individual", "token_occurrence", "state_assertion",
    "token_causal_claim",
    "attitude", "predicted_occurrence", "prediction_error",
})
RECORD_KINDS = frozenset({"assertion", "enrichment", "retraction", "succession"})


class SnapshotError(Exception):
    """A snapshot failed verification. The import (if any) is aborted and the
    target store is left untouched."""


# ---------------------------------------------------------------------------
# canonical serialization: the exact bytes of one body entry
# ---------------------------------------------------------------------------
def canonical_line(entry):
    """The deterministic canonical bytes of one content object or record.

    Sorted keys and no incidental whitespace make the encoding a pure function
    of the entry's content, so the same store always serializes to the same
    bytes. UTF-8 throughout, one entry per line (the body is newline-delimited
    so a large snapshot streams without loading wholly into memory)."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _entry_kind(entry):
    kind = entry.get("type")
    if not kind:
        kind = infer_kind(entry)
    return kind


# ---------------------------------------------------------------------------
# the Merkle root: one hash committing to every byte of the sorted body
# ---------------------------------------------------------------------------
# RFC 6962-style domain separation (a distinct prefix for leaves and interior
# nodes) so a leaf can never be reinterpreted as an interior node.
_LEAF = b"\x00"
_NODE = b"\x01"


def _leaf_hash(line_bytes):
    return hashlib.sha256(_LEAF + line_bytes).digest()


def merkle_root(line_byte_list):
    """The Merkle root over an ORDERED list of body-line bytes.

    Each line is a leaf; interior nodes hash the concatenation of their two
    children; an odd node is promoted unchanged to the next level. Any change
    to any byte of any line changes the root. An empty body has the well-defined
    root SHA-256("")."""
    if not line_byte_list:
        return hashlib.sha256(b"").hexdigest()
    level = [_leaf_hash(b) for b in line_byte_list]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hashlib.sha256(_NODE + level[i] + level[i + 1])
                           .digest())
            else:
                nxt.append(level[i])   # odd one out: promote unchanged
        level = nxt
    return level[0].hex()


# ---------------------------------------------------------------------------
# token-tier exclusion (privacy: local-by-default)
# ---------------------------------------------------------------------------
def _is_token_id(value):
    return (isinstance(value, str)
            and value.split(":", 1)[0] in TOKEN_SCHEMES)


def _references_token(value):
    """True if a record's value tree contains any token-tier identifier."""
    if _is_token_id(value):
        return True
    if isinstance(value, dict):
        return any(_references_token(v) for v in value.values())
    if isinstance(value, list):
        return any(_references_token(v) for v in value)
    return False


def is_token_content(obj):
    """A content object belonging to the token tier (local by default)."""
    oid = obj.get("id", "")
    return (obj.get("type") in TOKEN_SCHEMES) or _is_token_id(oid)


def record_touches_token(record):
    """A provenance record that references a token-tier object - excluded from
    the default (shareable) snapshot along with the tokens it is about."""
    return _references_token(record)


# ---------------------------------------------------------------------------
# manifest signing and verification
# ---------------------------------------------------------------------------
def _manifest_signing_bytes(manifest):
    """The canonical bytes the manifest signature covers: the whole manifest
    header except the signature itself (the Merkle root - and hence the whole
    body - and the created-at timestamp are both inside the signed bytes)."""
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest, secret):
    """Return the manifest completed with signed_by (the public key) and an
    Ed25519 signature over its canonical bytes."""
    public = ed25519.secret_to_public(secret)
    signed_by = "ed25519:" + public.hex()
    out = dict(manifest)
    out["signed_by"] = signed_by
    out.pop("signature", None)
    signature = ed25519.sign(secret, _manifest_signing_bytes(out)).hex()
    out["signature"] = signature
    return out


def verify_manifest_signature(manifest, trust=None):
    """True iff the manifest's signature verifies against its own signed_by
    key. If trust is given (an ed25519: public key), the signed_by key must
    also equal it - pinning the publisher a downloader chooses to trust."""
    signed_by = manifest.get("signed_by", "")
    sig_hex = manifest.get("signature")
    if not signed_by.startswith("ed25519:") or not sig_hex:
        return False
    if trust is not None and signed_by != trust:
        return False
    try:
        public = bytes.fromhex(signed_by.split(":", 1)[1])
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    return ed25519.verify(public, _manifest_signing_bytes(manifest), signature)


# ---------------------------------------------------------------------------
# export: a store -> (body bytes, signed manifest)
# ---------------------------------------------------------------------------
def _utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_entries(store, include_tokens=False):
    """The sorted body entries of a snapshot: content objects then records,
    all merged and sorted by identifier so the body is deterministic. Token-
    tier content and the provenance about it are excluded unless opted in."""
    content, records = [], []
    for obj in store.objects.values():
        if not include_tokens and is_token_content(obj):
            continue
        content.append(obj)
    for rec in store.records.values():
        if not include_tokens and record_touches_token(rec):
            continue
        records.append(rec)
    entries = content + records
    entries.sort(key=lambda e: e["id"])
    return entries, len(content), len(records)


def build_body(entries):
    """Serialize the sorted entries into the newline-delimited body bytes and
    the per-line byte list (the Merkle leaves)."""
    lines = [canonical_line(e) for e in entries]
    body = b"".join(line + b"\n" for line in lines)
    return body, lines


def export_snapshot(store, secret, include_tokens=False, created_at=None):
    """Produce (body_bytes, manifest) from a store.

    Deterministic: the same store yields byte-identical body and an identical
    Merkle root; only created_at (excluded from the root) varies between runs.
    The manifest is signed with the publishing node's Ed25519 key."""
    entries, n_content, n_records = collect_entries(store, include_tokens)
    body, lines = build_body(entries)
    root = merkle_root(lines)
    manifest = {
        "snapshot_format": SNAPSHOT_FORMAT,
        "spec_version": SPEC_VERSION,
        "created_at": created_at or _utc_now_iso(),
        "content_objects": n_content,
        "provenance_records": n_records,
        "includes_tokens": bool(include_tokens),
        "merkle_root": root,
    }
    manifest = sign_manifest(manifest, secret)
    return body, manifest


# ---------------------------------------------------------------------------
# verify: check a snapshot with nothing but its own bytes (no store needed)
# ---------------------------------------------------------------------------
def parse_body(body_bytes):
    """The list of entries from newline-delimited body bytes, and the exact
    per-line bytes (recomputing the Merkle leaves from what was delivered, not
    from a re-serialization, so a byte-level tamper is caught)."""
    entries, lines = [], []
    for raw in body_bytes.split(b"\n"):
        if not raw:
            continue
        lines.append(raw)
        entries.append(json.loads(raw.decode("utf-8")))
    return entries, lines


def verify_snapshot(body_bytes, manifest, trust=None):
    """(ok, report) - verify a snapshot end to end WITHOUT a store:

      1. the manifest signature (and the pinned publisher key, if given);
      2. the Merkle root recomputed from the delivered body;
      3. every content object's identifier == the hash of its canonical bytes;
      4. every provenance record's Ed25519 signature;
      5. the manifest's declared counts.

    A downloader can run this against the .ndjson body and the manifest alone,
    proving the snapshot before ever standing up a store."""
    report = {"content_objects": 0, "provenance_records": 0,
              "bad_ids": [], "bad_signatures": [], "errors": []}

    if not verify_manifest_signature(manifest, trust=trust):
        report["errors"].append("manifest signature does not verify"
                                 if trust is None else
                                 "manifest signature/publisher key mismatch")
        return False, report

    try:
        entries, lines = parse_body(body_bytes)
    except (ValueError, UnicodeDecodeError) as e:
        report["errors"].append("body is not valid newline-delimited JSON: %s"
                                % e)
        return False, report

    root = merkle_root(lines)
    if root != manifest.get("merkle_root"):
        report["errors"].append(
            "Merkle root mismatch: body hashes to %s, manifest claims %s"
            % (root, manifest.get("merkle_root")))
        return False, report

    n_content = n_records = 0
    for entry in entries:
        try:
            kind = _entry_kind(entry)
        except ValueError:
            report["bad_ids"].append(entry.get("id", "<no id>"))
            continue
        if kind in CONTENT_KINDS:
            n_content += 1
            body = {k: v for k, v in entry.items() if k != "id"}
            try:
                expected = identify(body, kind)
            except ValueError:
                report["bad_ids"].append(entry.get("id", "<no id>"))
                continue
            if entry.get("id") != expected:
                report["bad_ids"].append(entry.get("id", "<no id>"))
        elif kind in RECORD_KINDS:
            n_records += 1
            if not verify_record(entry, kind):
                report["bad_signatures"].append(entry.get("id", "<no id>"))
        else:
            report["bad_ids"].append(entry.get("id", "<no id>"))

    report["content_objects"] = n_content
    report["provenance_records"] = n_records

    if manifest.get("content_objects") != n_content:
        report["errors"].append(
            "content-object count mismatch: body has %d, manifest claims %s"
            % (n_content, manifest.get("content_objects")))
    if manifest.get("provenance_records") != n_records:
        report["errors"].append(
            "provenance-record count mismatch: body has %d, manifest claims %s"
            % (n_records, manifest.get("provenance_records")))

    ok = (not report["bad_ids"] and not report["bad_signatures"]
          and not report["errors"])
    return ok, report


# ---------------------------------------------------------------------------
# import: verify, then merge by set union into a target store (idempotent)
# ---------------------------------------------------------------------------
def import_snapshot(body_bytes, manifest, store, trust=None):
    """Verify a snapshot in full, THEN merge it into the target store by set
    union. Any verification failure raises SnapshotError before any write, so
    a tampered snapshot never partially loads. Importing the same valid
    snapshot twice is a no-op (idempotent, by content address)."""
    ok, report = verify_snapshot(body_bytes, manifest, trust=trust)
    if not ok:
        raise SnapshotError(
            "snapshot failed verification, nothing imported: %s"
            % json.dumps({k: v for k, v in report.items()
                          if k in ("bad_ids", "bad_signatures", "errors")}))

    entries, _ = parse_body(body_bytes)
    added = {"content_added": 0, "records_added": 0,
             "content_present": 0, "records_present": 0}
    for entry in entries:
        kind = _entry_kind(entry)
        eid = entry["id"]
        if kind in CONTENT_KINDS:
            if eid in store.objects:
                added["content_present"] += 1
            else:
                store.objects[eid] = entry   # integrity re-checked on write
                added["content_added"] += 1
        else:
            if eid in store.records:
                added["records_present"] += 1
            else:
                store.records[eid] = entry
                added["records_added"] += 1
    added["merkle_root"] = manifest.get("merkle_root")
    added["content_objects"] = report["content_objects"]
    added["provenance_records"] = report["provenance_records"]
    return added


# ---------------------------------------------------------------------------
# detached proofs: checksum + signature files a downloader can check offline
# ---------------------------------------------------------------------------
def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def checksum_file(body_bytes, manifest_bytes, body_name, manifest_name):
    """A sha256sum-format checksum file over the body and the manifest, so a
    downloader can confirm both arrived intact before any parsing."""
    return ("%s  %s\n%s  %s\n" % (sha256_hex(body_bytes), body_name,
                                  sha256_hex(manifest_bytes), manifest_name))

# Snapshots: signed, content-addressed dumps of the commons

Phase two of Part 21 (Commons Storage and Federation Design). A snapshot is a
point-in-time dump of the commons that anyone can download, verify byte for
byte, and use to stand up a mirror — durability and global redundancy *before*
a single live peer is recruited. The rule is: **self-verifying and
reproducible**. Every object proves itself by its own hash; every record proves
itself by its own signature; the whole is committed by one Merkle root and
authenticated by one Ed25519 signature over the manifest.

## The two parts: a manifest and a body

A snapshot is a **body** (the data) and a **manifest** (a small signed header).

### Body

Newline-delimited canonical JSON (`.ndjson`): one content object or provenance
record per line, each serialized as its exact canonical bytes
(`json.dumps(entry, sort_keys=True, separators=(",", ":"))`, UTF-8), with all
entries sorted by identifier. The encoding is a pure function of content, so the
same store always emits a byte-identical body, and the stream is read one line
at a time so a large snapshot never loads wholly into memory. Each line carries
its own `type`, so the body is self-describing — no section headers to keep in
step. Content kinds route to the content table on import, record kinds
(`assertion`, `enrichment`, `retraction`, `succession`) to the provenance log.

### Manifest

A small JSON header, signed:

| field | meaning |
|---|---|
| `snapshot_format` | the format version (`1.0`) |
| `spec_version` | the specification version (`2.0.0`) |
| `created_at` | UTC ISO-8601 timestamp — the ONLY non-reproducible field |
| `content_objects` | count of content objects in the body |
| `provenance_records` | count of provenance records in the body |
| `includes_tokens` | `false` by default (the token tier is excluded) |
| `merkle_root` | one hash committing to every byte of the sorted body |
| `signed_by` | the publishing node's key, `ed25519:<hex>` |
| `signature` | Ed25519 signature over the manifest (minus `signature`) |

The `merkle_root` is inside the signed bytes, so the signature authenticates the
whole body. The `created_at` is inside the signed bytes too, but is **excluded
from the Merkle root** — the root is content-only, so the same store yields the
same root forever, while each publication still carries an honest timestamp.

## The Merkle root

Each body line is a leaf; interior nodes hash the concatenation of their two
children; an odd node is promoted unchanged to the next level; the single top
hash is the root. Domain separation follows RFC 6962 — a leaf is
`SHA-256(0x00 ‖ line)`, an interior node `SHA-256(0x01 ‖ left ‖ right)` — so a
leaf can never be reinterpreted as an interior node. An empty body has the
well-defined root `SHA-256("")`. Any change to any byte of any line changes the
root.

## Privacy: the token tier is excluded by default

A default snapshot is the **shareable commons** — type-tier content plus the
provenance about it. It MUST NOT include token-tier records
(`token_individual`, `token_occurrence`, `state_assertion`,
`token_causal_claim`), nor any provenance record that references one, unless the
operator explicitly opts in (`--include-tokens`, recorded as
`includes_tokens: true`). This makes the standard's local-by-default rule
concrete (see [safety.md](safety.md)): a snapshot is exactly the "laws, not
diaries" boundary. Because content addressing is unforgetting, a token
identifier once published is irrevocable — so the default is non-publishing, and
the opt-in is a deliberate operator act.

## Export, verify, import

- **Export** (`store/server/snapshot_export.py`) reads a store — the persistent
  Phase-one node (`--db`) or a `{objects, records}` bundle (`--from-bundle`) —
  and writes four files: the body, the signed manifest, a detached SHA-256
  checksum file (`sha256sum -c`-compatible), and a detached signature.
  Deterministic; signs with the node's Ed25519 key.
- **Verify** (`store/server/snapshot_import.py --verify-only`) checks a dump
  with nothing but its own bytes — no store required:
  1. the manifest signature (optionally pinned to a trusted publisher with
     `--trust ed25519:<hex>`);
  2. the Merkle root recomputed from the delivered body;
  3. every content object's identifier == the hash of its canonical bytes;
  4. every provenance record's Ed25519 signature;
  5. the manifest's declared counts.
- **Import / mirror** (`store/server/snapshot_import.py --db mirror.db`) runs the
  full verification, then merges by **set union** into the target store. Any
  failure raises before any write — a tampered snapshot **never partially
  loads**. Importing the same valid snapshot twice is a **no-op** (idempotent,
  by content address).

## The genesis node

The "genesis" full node is just a persistent Phase-one node run as the durable
anchor, plus the discipline of publishing snapshots from it:

```
# once: generate and privately keep the node's signing key
python3 store/server/snapshot_export.py --gen-key genesis.seed

# each publication: dump the commons from the persistent node
python3 store/server/snapshot_export.py \
    --db store/server/data/causalontology.db \
    --seed-file genesis.seed --out dumps
```

The four files in `dumps/` are the published artifact. Distribution over IPFS,
BitTorrent, or plain HTTPS is an operational choice and is **out of scope for
Phase two** — this phase delivers the artifact and its proofs, not a hosting
pipeline. Real dumps are git-ignored (`dumps/`); a small worked example is
committed under `dumps/example/` and exercised by the tests.

Standing up a mirror needs only the dump and this tool:

```
python3 store/server/snapshot_import.py --dir dumps --verify-only   # prove it
python3 store/server/snapshot_import.py --dir dumps --db mirror.db  # mirror it
```

## What Phase two is not

No live federation, gossip, or anti-entropy (Phase three); no light clients, CDN
caching, or hash-prefix sharding (Phase four). A snapshot is a static,
verifiable dataset — the floor of durability the live network is later built on
top of. Tests: `store/server/test_snapshot.py`.

# causalontology-dart

**The Dart binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero dependencies — pure Dart crypto.** The `pubspec.yaml` has no
dependencies at all: SHA-256 and SHA-512 are hand-written from FIPS 180-4
(gated by empty-string known answers), and Ed25519 (RFC 8032) is ported from
the reference Python over `BigInt` (gated by the RFC 8032 TEST 1 known
answer). Everything else uses `dart:convert`, `dart:io`, and
`dart:typed_data`. Requires **Dart SDK 3.0 or newer**.

| Source file | Implements |
|---|---|
| `lib/jcs.dart` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys (UTF-16 code-unit order, which is Dart's `String.compareTo`), minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`). `dart:convert`'s `jsonDecode` is lossless on the Dart VM (`1` decodes to `int`, `1.0` to `double`, key order preserved), so no custom parser is needed |
| `lib/sha2.dart` | pure-Dart SHA-256 (32-bit words masked into 64-bit ints) and SHA-512 (native 64-bit two's-complement arithmetic with `>>>` logical shifts) |
| `lib/ed25519.dart` | Ed25519 (RFC 8032) over `BigInt`, whose Euclidean `%` gives the non-negative mod-p normalization the reference relies on; deterministic signing, public-key derivation from a 32-byte seed |
| `lib/canonical.dart` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `lib/signing.dart` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `lib/schema.dart` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `lib/semantics.dart` | the 13 semantic rules: temporal admissibility with the fixed unit constants, the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `lib/store.dart` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read — over `LinkedHashMap`s, deliberately mirroring the Python reference's insertion-order iteration |
| `lib/causalontology.dart` | the public API surface (exports) |
| `bin/conformance.dart` | the conformance runner: internal known-answer checks (SHA-2 empty-string digests, RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ dart bindings/dart/bin/conformance.dart
...
38/38 vectors passed
causalontology-dart is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from its own script
location (then the working directory) until it finds `conformance/vectors`;
the schemas are read from `spec/schema` under the same root (overridable
with `CAUSALONTOLOGY_SPEC` naming the `spec/` directory).

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

Ed25519 is deterministic (RFC 8032), and the canonical bytes are pinned by
RFC 8785, so identifiers and signatures are byte-compatible across the
bindings: the same record signed with the same key yields the same id and
the same signature here as in the Python, JavaScript, Go, Java, Rust, and
Swift implementations.

## Thirty-second taste

```dart
import 'package:causalontology/causalontology.dart';

void main() {
  final store = InMemoryStore();
  final press = store.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action'});
  final light = store.put({
    'type': 'occurrent', 'label': 'light_on', 'category': 'state_change'});
  final claim = store.put({
    'type': 'causal_relation_object', 'causes': [press], 'effects': [light]});

  print(claim);
  print(store.gaps('missing_field')); // the degenerate claim is a visible invitation
}
```

## Status

Source complete and ported line-for-line from the Python binding; **verified
locally**: `dart bindings/dart/bin/conformance.dart` prints
`38/38 vectors passed` with the Dart VM, the analyzer reports no issues, and
a cross-check against causalontology-py confirmed identical public keys,
identifiers, and signatures for the same seed and record. Also executed by
GitHub Actions CI (`dart bindings/dart/bin/conformance.dart`), as for every
binding.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

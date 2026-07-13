# causalontology-go

**The Go binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero dependencies.** The Go standard library carries everything the
standard needs natively: `crypto/ed25519` (RFC 8032 signing and
verification, deterministic key derivation from a 32-byte seed),
`crypto/sha256`, `encoding/json`, and `regexp`. The `go.mod` is a
standalone module with no `require` lines at all. Requires **Go 1.22 or
newer**.

| Source file | Implements |
|---|---|
| `causalontology/json.go` | a lossless JSON layer: everything is decoded with `json.Decoder.UseNumber()`, so numbers keep their source literal and the integer-versus-decimal distinction (`1` versus `1.0`) survives to the canonicalizer |
| `causalontology/jcs.go` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `causalontology/canonical.go` | identity-bearing field filtering per kind and SHA-256 content-addressed `Identify()` (spec/identity.md) |
| `causalontology/signing.go` | record-level `SignRecord()` / `VerifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `causalontology/schema.go` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `causalontology/semantics.go` | the 13 semantic rules: temporal admissibility with the fixed unit constants, the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `causalontology/store.go` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `Gaps()` read — with explicit insertion-order bookkeeping, since Go maps iterate in random order where Python dicts do not |
| `conformance/main.go` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ cd bindings/go
$ go run ./conformance
...
38/38 vectors passed
causalontology-go is CONFORMANT to the suite (pre-freeze, symbolic-id normalization).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`; the schemas are read from
`spec/schema` under the same root.

The harness normalizes the vectors' pre-freeze symbolic identifiers
deterministically, exactly as the Python harness does: a symbolic object
id `scheme:name` becomes `scheme:sha256(name)`, and a symbolic key name
`ed25519:name` becomes a real Ed25519 keypair seeded from
`sha256("key:" + name)` — so every normative behavior is exercised with
well-formed data and real signatures. The 1.0.0 freeze pins concrete
bytes into the vectors themselves.

## Thirty-second taste

```go
import co "causalontology/causalontology"

store := co.NewStore(true)
press, _ := store.Put(map[string]any{
        "type": "occurrent", "label": "press_button", "category": "action"}, "")
light, _ := store.Put(map[string]any{
        "type": "occurrent", "label": "light_on", "category": "state_change"}, "")
claim, _ := store.Put(map[string]any{
        "type": "cro", "causes": []any{press}, "effects": []any{light}}, "")

fmt.Println(claim, store.Gaps("missing_field")) // the degenerate claim is a visible invitation
```

## Status

Source complete and ported line-for-line from the Python binding; built
and executed by GitHub Actions CI (`cd bindings/go && go run ./conformance`) —
there is no Go toolchain on the authoring machine, so CI is the gate, as
it is for every binding.

License: "The attribution always; no profit, no problem license." — see
the repository `LICENSE` and `NOTICE`.

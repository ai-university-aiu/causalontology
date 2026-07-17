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
| `causalontology/json.go` | a lossless JavaScript Object Notation (JSON) layer: everything is decoded with `json.Decoder.UseNumber()`, so numbers keep their source literal and the integer-versus-decimal distinction (`1` versus `1.0`) survives to the canonicalizer |
| `causalontology/jcs.go` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `causalontology/canonical.go` | identity-bearing field filtering per kind and Secure Hash Algorithm 256-bit (SHA-256) content-addressed `Identify()` (spec/identity.md) |
| `causalontology/signing.go` | record-level `SignRecord()` / `VerifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `causalontology/schema.go` | validation against the seventeen JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `causalontology/semantics.go` | the 21 semantic rules: temporal admissibility with the fixed unit constants, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, enrichment field/shape rules, and the token-tier coherence checks |
| `causalontology/store.go` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `Gaps()` read — with explicit insertion-order bookkeeping, since Go maps iterate in random order where Python dicts do not |
| `conformance/main.go` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 107 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ cd bindings/go
$ go run ./conformance
...
107/107 vectors passed
causalontology-go is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`; the schemas are read from
`spec/schema` under the same root.

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

## Thirty-second taste

**Import path (2.0.0):** because this is a major version 2 release, the Go
module carries the `/v2` suffix that Go requires for any version 2 or higher.
Install it with `go get github.com/ai-university-aiu/causalontology/bindings/go/v2@v2.0.0`
and import it as shown below (the `/v2` is part of the path). The 1.0.0 line
remains available at the un-suffixed path, `.../bindings/go@v1.0.0`.

```go
import co "github.com/ai-university-aiu/causalontology/bindings/go/v2/causalontology"

store := co.NewStore(true)
press, _ := store.Put(map[string]any{
        "type": "occurrent", "label": "press_button", "category": "action"}, "")
light, _ := store.Put(map[string]any{
        "type": "occurrent", "label": "light_on", "category": "state_change"}, "")
claim, _ := store.Put(map[string]any{
        "type": "causal_relation_object", "causes": []any{press}, "effects": []any{light}}, "")

fmt.Println(claim, store.Gaps("missing_field")) // the degenerate claim is a visible invitation
```

## Status

Source complete and ported line-for-line from the Python binding; built
and executed by GitHub Actions CI (`cd bindings/go && go run ./conformance`) —
there is no Go toolchain on the authoring machine, so CI is the gate, as
it is for every binding.

License: "The attribution always; no profit, no problem license." — see
the repository `LICENSE` and `NOTICE`.

# causalontology-go (the `/v2` module, specification 2.0.0)

> **Looking for 4.0.0? It is a different module: [`v4/`](v4/).**
> This directory is the `/v2` module, frozen at specification 2.0.0 and
> 107 conformance checks. It stays published and unchanged. The current
> release is
> `go get github.com/ai-university-aiu/causalontology/bindings/go/v4@v4.0.1`,
> imported as `.../bindings/go/v4/causalontology`. `v4.0.0` shipped without
> the twenty-one JSON Schemas and is retracted in that module's `go.mod`;
> the proxy serves `v4.0.1`. No `/v3` was ever cut.

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
| `conformance/main.go` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 107 checks of the 2.0.0 suite — 38 driven by the frozen shared vector files, 69 hand-written here — mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

> **This directory is the frozen 2.0.0 (`/v2`) module**, kept because
> `.../bindings/go/v2@v2.0.0` is published and live. Its suite is the 107
> checks of specification 2.0.0. The current Go binding is **`/v4`** in
> [`v4/`](v4/), at 137 checks — see [`v4/README.md`](v4/README.md).

```
$ cd bindings/go
$ go run ./conformance
...
107/107 checks passed (38 from the frozen shared vectors, 69 per-binding)
causalontology-go is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`; the schemas are read from
`spec/schema` under the same root.

The shared vector files are frozen at specification 2.0.0 (2026-07-13). The 38 that carry an executable payload — V01–V38 — hold concrete identifiers, real keys, and a real verifying signature, and the harness's old normalization now simply passes those frozen values through; the rest name their check but delegate it to this runner.

## Thirty-second taste

**Import path (2.0.0):** because this is a major version 2 release, the Go
module carries the `/v2` suffix that Go requires for any version 2 or higher.
Install it with `go get github.com/ai-university-aiu/causalontology/bindings/go/v2@v2.0.0`
and import it as shown below (the `/v2` is part of the path). The 1.0.0 line
remains available at the un-suffixed path, `.../bindings/go@v1.0.0`. For
specification 4.0.0 use the `/v4` module instead - see [`v4/`](v4/).

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
and executed by GitHub Actions CI (`cd bindings/go && go run ./conformance`).
Last run locally on 2026-07-27 with Go 1.22: **107/107 checks passed**
(38 from the frozen shared vectors, 69 per-binding), exit 0. CI runs the
same command on every push, as it does for every binding.

License: "The attribution always; no profit, no problem license." — see
the repository `LICENSE` and `NOTICE`.

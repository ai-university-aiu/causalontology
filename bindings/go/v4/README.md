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
| `causalontology/schema.go` | validation against the twenty-one JSON Schemas (a small interpreter for exactly the keywords those schemas use) |
| `causalontology/embed.go` | the twenty-one JSON Schemas compiled into the module with `//go:embed`, plus the drift guard that compares them byte for byte against `spec/schema` |
| `causalontology/semantics.go` | the 25 semantic rules: temporal admissibility with the fixed unit constants and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `causalontology/store.go` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `Gaps()` read — with explicit insertion-order bookkeeping, since Go maps iterate in random order where Python dicts do not |
| `conformance/main.go` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 checks — 38 driven by the frozen shared vector files, 99 hand-written here — mirroring `bindings/python/tests/run_conformance.py` exactly |

The object model is the twenty-one kinds of specification 4.0.0: the 2.0.0
whole-word kinds, the 3.0.0 `cross_stratal_seam`, and the 4.0.0 `attitude`,
`predicted_occurrence`, and `prediction_error`.

## Conformance

```
$ cd bindings/go/v4
$ go run ./conformance
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-go is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`. That root supplies the
vectors. It also supplies the schemas in the default (in-repository) mode, so
an edit to `spec/schema` is picked up immediately during development.

### Where the schemas come from

The twenty-one JSON Schemas are compiled into the module by `//go:embed` over
`causalontology/spec_schema/`, so `go get` of this module delivers them. A Go
module ships only its own subdirectory, so the repository's `spec/schema` is
*not* delivered; version 4.0.0 read that directory at run time and therefore
failed on the first `ValidateSchema` call for every consumer outside a
checkout. That version is retracted in `go.mod`; use 4.0.1 or newer.

Resolution order is: an explicit `SetSchemaDir` call, then the
`CAUSALONTOLOGY_SPEC` environment variable, then the compiled-in copy. Nothing
else moves the schema source - in particular `CAUSALONTOLOGY_ROOT` locates the
vectors only, because letting it move the schemas too is exactly what once hid
the missing schemas from the conformance run.

### Installed mode

`CAUSALONTOLOGY_TEST_INSTALLED=1` runs the suite the way a consumer does: the
schemas must come from the compiled-in copy, and the runner prints the
directory the binding was compiled from and **exits nonzero if that directory
is inside the repository**. A run that resolves the binding by relative path,
or through a `replace` directive pointing at the checkout, is therefore
rejected rather than reported as a pass.

```
$ cd /some/directory/outside/the/repository
$ env -u CAUSALONTOLOGY_SPEC \
      CAUSALONTOLOGY_TEST_INSTALLED=1 \
      CAUSALONTOLOGY_ROOT=/path/to/causalontology \
      "$(go env GOPATH)/bin/conformance"
binding under test: /.../pkg/mod/github.com/ai-university-aiu/causalontology/bindings/go/v4@v4.0.1/causalontology
module under test: github.com/ai-university-aiu/causalontology/bindings/go/v4 v4.0.1
embedded schemas: 21
schema source: compiled into the module (embed.FS)
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
```

`CAUSALONTOLOGY_ROOT` still points at a checkout in installed mode, because the
vectors themselves live in the repository and are not part of the module. Build
the command without `-trimpath`, or the binding path cannot be reported and
installed mode refuses to run.

> **The summary line above is this repository's, not v4.0.1's.** A Go module
> ships its runner, and `v4.0.1` was tagged before the "137 checks, not 137
> vectors" correction, so a binary installed with
> `go install github.com/ai-university-aiu/causalontology/bindings/go/v4/conformance@v4.0.1`
> prints the old, overstated `137/137 vectors passed` (checked 2026-07-27).
> The checks it runs are the same 137 and the schemas are the same compiled-in
> 21; only the wording is stale. It corrects itself with the next module tag.
> Go is the only channel affected: no other published package ships a runner.

The shared vector files are frozen at specification 4.0.0 (2026-07-22; 137
files, V01–V137). The 38 that carry an executable payload — V01–V38 — hold
concrete identifiers, real keys, and a real verifying signature, and the
harness's old normalization now simply passes those frozen values through;
V39–V137 name their check but delegate it to this runner. V01–V107 are the
whole-word 2.0.0 baseline; V108–V119 are the 3.0.0 additions (the tick unit,
the `cross_stratal_seam`, the conduit `realized_by`);
V120–V137 are the 4.0.0 additions (`attitude`, `predicted_occurrence`,
`prediction_error`).

## Thirty-second taste

**Import path (4.0.0):** Go versions the import path, so a major version 4
release takes a `/v4` suffix; it is the new module directory
`bindings/go/v4`. Install it with
`go get github.com/ai-university-aiu/causalontology/bindings/go/v4@v4.0.1`
and import it as shown below (the `/v4` is part of the path). Do not use
`@v4.0.0`: it shipped without the JSON Schemas and is retracted, so `go get`
of the bare module path will skip it. No `/v3` module
was ever cut — the 3.0.0 delta is folded into 4.0.0 — so the module path steps
from `/v2` straight to `/v4`; the 2.0.0 line remains available at
`.../bindings/go/v2@v2.0.0` and the 1.0.0 line at the un-suffixed path,
`.../bindings/go@v1.0.0`.

```go
import co "github.com/ai-university-aiu/causalontology/bindings/go/v4/causalontology"

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

Source complete and ported line-for-line from the Python binding, at
specification 4.0.0 (twenty-one kinds, 137 checks); verified locally with
`cd bindings/go/v4 && go run ./conformance` at 137/137, and also executed by
GitHub Actions CI.

License: "The attribution always; no profit, no problem license." — see
the repository `LICENSE` and `NOTICE`.

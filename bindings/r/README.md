# causalontology-r

**The R binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

Two dependencies only, both standard CRAN infrastructure:
[sodium](https://cran.r-project.org/package=sodium) (libsodium: Ed25519,
RFC 8032) and [openssl](https://cran.r-project.org/package=openssl)
(SHA-256). Everything else is base R (4.x) — including the JSON parser,
because base R has none and the canonicalizer needs a lossless one anyway.

| Source file | Implements |
|---|---|
| `R/json.R` | a lossless JSON layer: a hand-written recursive-descent parser producing named lists (`co_obj`, insertion-ordered like Python dicts), unnamed lists (`co_arr`), and doubles carrying a shape tag (`attr "co_shape"`: `"int"` when the source literal had no `.`/`e`/`E`) — R's native integer is only 32-bit, so every number is a double, exact to 2^53; JSON `null` is a sentinel object, never R `NULL` (assigning `NULL` into a list deletes the element) |
| `R/jcs.R` | RFC 8785 (JSON Canonicalization Scheme) serialization: code-point key ordering via radix sort (C locale, immune to `LC_COLLATE`), minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `1e-07` → `1e-7`) |
| `R/canonical.R` | identity-bearing field filtering per kind and SHA-256 content-addressed `co_identify()` (spec/identity.md) |
| `R/signing.R` | record-level `co_sign_record()` / `co_verify_record()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `R/schema.R` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `R/semantics.R` | the 13 semantic rules: temporal admissibility with the fixed unit constants (month = 2629746 s, year = 31556952 s), the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `R/store.R` | an in-memory conformant store (an R environment holding insertion-ordered named lists): idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with canonical-entry dedup and contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule (latest `(timestamp, id)` loses, compared code-point-wise, timestamp first then id), and the stigmergy `co_store_gaps()` read |
| `conformance.R` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## The sodium API, pinned down

In the sodium R package the **Ed25519 signing key is the 32-byte seed
itself** — sodium derives the key pair internally. The argument orders,
per the sodium package documentation (`?sig_sign`):

```r
pub <- sodium::sig_pubkey(seed)          # 32-byte seed -> 32-byte public key
sig <- sodium::sig_sign(msg, seed)       # message FIRST, then the key
ok  <- sodium::sig_verify(msg, sig, pub) # message, signature, public key
```

`sig_verify()` **throws an error** on a bad signature rather than
returning `FALSE`, so the binding wraps it in `tryCatch`. All of these
assumptions are gated at runtime by the RFC 8032 TEST 1 known answer
(seed `9d61…7f60` must derive public key `d75a…511a`) before any vector
runs.

## Conformance

```
$ sudo apt-get install -y libsodium-dev libssl-dev
$ Rscript -e "install.packages(c('sodium','openssl'), repos='https://cloud.r-project.org')"
$ Rscript bindings/r/conformance.R
...
38/38 vectors passed
causalontology-r is CONFORMANT to the suite (vectors frozen at specification 1.0.0).
```

The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through.

The runner locates the repository root from its own script path
(`bindings/r/` is two levels down), falling back to the
`CAUSALONTOLOGY_ROOT` environment variable or a walk up from the working
directory; the schemas are read from `spec/schema` under the same root
(override with `CAUSALONTOLOGY_SPEC`).

## Thirty-second taste

```r
source("bindings/r/R/json.R");   source("bindings/r/R/jcs.R")
source("bindings/r/R/canonical.R"); source("bindings/r/R/signing.R")
source("bindings/r/R/schema.R"); source("bindings/r/R/semantics.R")
source("bindings/r/R/store.R")

store <- co_store_new(enforcing = TRUE)
press <- co_store_put(store, co_obj(type = "occurrent",
                                    label = "press_button",
                                    category = "action"))
light <- co_store_put(store, co_obj(type = "occurrent",
                                    label = "light_on",
                                    category = "state_change"))
claim <- co_store_put(store, co_obj(type = "cro",
                                    causes = co_arr(press),
                                    effects = co_arr(light)))

str(co_store_gaps(store, "missing_field"))
# the degenerate claim is a visible invitation
```

## Status

Source complete and ported line-for-line from the Python binding;
executed by GitHub Actions CI (`Rscript bindings/r/conformance.R` after
installing `libsodium-dev`, `libssl-dev`, and the `sodium` and `openssl`
CRAN packages) — there is no R interpreter on the authoring machine, so
CI is the gate, as it is for every binding.

The `DESCRIPTION` file gives the directory the shape of an R package
(`Package: causalontology`, version 1.0.0). Publishing it on CRAN is a
separate, human-driven process — CRAN submissions go through a manual
review by the CRAN team and require a human maintainer to submit,
respond, and confirm; no claim of CRAN presence is made here.

License: Apache License 2.0 — see the `LICENSE` file (copied from the
repository root) and the repository `NOTICE`.

# Conformance

**An implementation is Causalontology-conformant if and only if it passes every
vector in `vectors/` for the specification version it declares.**

> **Read this before quoting `137/137`.** The rule above states the intention.
> It is not what the suite currently measures, and the gap was found by
> measurement on 2026-07-27, not by argument.
>
> **`137/137` counts checks, not vector files.** It is 137 hand-written,
> per-language assertions. Of those, **38 are driven by the files in this
> directory** — exactly V01–V38 — and the other 99 share no data with any other
> binding at all. Re-measured with `strace` on 2026-07-27 across all nineteen
> runners: seventeen of them open exactly those 38 files and open no other
> vector file at all; Rust and Haskell open all 137, but the extra 99 only to
> lift the label printed on the PASS line — replace the contents of V39–V137
> with `{}` and both still print `137/137` and `CONFORMANT`. (Python does not
> even open them: it globs the file NAME for the label and never reads the
> bytes.)
>
> **The cause is in these files, not only in the runners.** All 99 files from
> V39 to V137 carry no executable payload — no `input`, no `given`, no `steps`.
> Their `operation` field reads, literally, `"see bindings/*/conformance
> runner"`. They are named, grouped stubs carrying an `expect` block of booleans
> and a prose note. There is nothing in them to execute, so no runner could read
> them for meaning even if it tried.
>
> The consequence for the sentence above: that passing every vector is what makes
> nineteen independent implementations agree without sharing a line of code holds
> today **for V01–V38 only**. For V39–V137 the agreement rests on nineteen
> separate hand-written implementations of the same prose. That is a real but
> weaker guarantee, and it should not be described as the stronger one.
>
> **The honest headline** is `137/137 conformance checks passed (38 driven by the
> frozen shared vectors; 99 implemented per binding)`. PUBLISHING.md carries the
> full measurement, including the stricter figure: of the 38 files that are read,
> only 26 change any verdict when their bytes are destroyed. Re-measured against
> the Python reference on 2026-07-27, one file at a time: V01–V19, V21–V25, and
> V34–V35 fail the run when replaced with `{}`; V20, V26–V33, and V36–V38 are
> opened but no verdict moves.

There are **137 vectors**. V01–V38 are the original suite, re-frozen unaltered
in meaning under the whole-word schemes (Principle P7); V39–V107 are the 2.0.0
additions; V108–V119 are the 3.0.0 additions (the ordinal tick unit, the managed
cross-stratal seam, and the realized_by reference); V120–V137 are the 4.0.0
additions (prediction and prediction error, attitude and theory of mind, and
the 4.0.0 identity witnesses):

| Group | Covers |
|---|---|
| A–F (V01–V38) | the original six groups: schema/semantic validity, temporal admissibility, identity, signatures, conflict/hierarchy/resolve/stigmergy |
| G–H (V39–V46) | strata and occurrent stratification |
| I (V47–V55) | bridges and stratal well-formedness |
| J (V56–V58) | **bridged reachability** — incl. V58, the negative vector that proves an implementation does BRIDGED, not literal, reachability |
| K (V59–V67) | stratal classification and the **skip asymmetry** (V62/V63) |
| L (V68–V70) | the `enabling` modality |
| M (V71–V77) | ports and conduits (pipe vs computer) |
| N (V78–V79) | the realizable identity-collision repair |
| O (V80–V84) | occurrent taxonomy and mereology |
| P (V85–V102) | the token tier (individuals, occurrences, qualities, states, token causal claims) |
| Q (V103–V105) | provenance widening, `evidenced_by`, `simulation` evidence |
| R (V106) | whole-word baseline hash equality |
| S (V107) | abbreviated scheme is rejected |
| **T (V108–V111)** | **3.0.0 — the ordinal `ticks` temporal unit**: valid tick window, integer-ordered admissibility, tick/wall-clock dimension disjointness, and unit identity-bearing with wall-clock ids unchanged |
| **U (V112–V116)** | **3.0.0 — the managed `cross_stratal_seam` (eighteenth kind)**: valid seam, `mechanism_status` identity-bearing (the honest-ignorance distinction), a drawn chain (and the contradictory `absent`+chain), the coarsest-stratum HOME rule, and non-adjacency + new identity space |
| **W (V117–V119)** | **3.0.0 — the `realized_by` reference**: a bound conduit valid, realized_by identity-bearing with unbound ids unchanged, and unbound-is-legal with a malformed reference rejected |
| **X (V120–V127)** | **4.0.0 — prediction and prediction error**: a valid tick-window prediction (a forecast's id differs from a report's), a valid wall-clock prediction with identity-bearing `strength`, a missing predictor rejected, the exactly-one-temporal-dimension rule (Rule 24 `dimension_conflict`), the fulfilled and the unfulfilled `prediction_error` (an absent `observed` is legal), a missing `discrepancy` rejected, and the `pairing_mismatch` check |
| **Y (V128–V135)** | **4.0.0 — attitude and theory of mind**: a true belief, a false belief valid and QUARANTINED (Rule 25 — no conflict raised), a desire, an intention, a nested attitude (A believes that B believes X), the closed `attitude_type` enumeration, no content-tier strength (Principle P4), and an attitude asserted through ordinary provenance (the holder distinct from the signer) |
| **Z (V136–V137)** | **4.0.0 — identity witnesses**: the exact frozen 3.0.0 bytes re-pinned unchanged under 4.0.0, and abbreviated schemes for the three new kinds rejected (mirrors V107) |

## Inventory, re-verified 2026-07-27

Facts a reviewer can re-derive from this directory in one command each, so that
the next audit need not repeat the work:

- `vectors/` holds exactly **137** files, numbered V1–V137 with no gap and no
  repeat; every file's `vector` field agrees with its filename number, and no
  two files share a `name` or a `vector` id.
- Every file is well-formed JSON. No two are byte-identical.
- Exactly **38** carry a payload (`input`, `inputA`/`inputB`, `given` or
  `steps`), and they are exactly V01–V38. All 99 of V39–V137 carry the stub
  `operation` string and nothing to execute — which is why **twelve groups of
  them are byte-identical once `name`, `vector` and `note` are removed** (for
  example V47–V50, the four bridge relations, differ only in prose). That is not
  duplication to be cleaned up; it is the same absence of content seen from
  another angle.
- The group letters in the table above match the `group` field of every file,
  and each group is a contiguous run. (There is no group V — the letter is
  skipped so it cannot be misread as a vector number.)
- `spec/schema/` holds exactly **21** `*.schema.json` files, one per kind. Every
  one passes the Draft 2020-12 metaschema, and every `$ref` in them resolves —
  including the single cross-file reference,
  `state.schema.json → token.schema.json#/$defs/interval`.
- Every payload vector that declares `expect.schema_valid` was cross-checked
  against its schema with the independent `jsonschema` reference library: 17 of
  17 agree with the vector's own expectation.

## Status: RE-FROZEN at 4.0.0 (three additive kinds over the 3.0.0 baseline)

The vectors carry **concrete bytes**: every identifier is a real, well-formed
whole-word 64-hex identifier, and every key is a real Ed25519 public key. The
single coordinated re-mint + re-freeze was applied by
[`freeze_2_0_0.py`](freeze_2_0_0.py) — deterministic and idempotent, re-run on
2026-07-27 against a copy of this directory, where it reported
`re-frozen: 0 vector files` and left every byte alone. The original
[`freeze_1_0_0.py`](freeze_1_0_0.py) is retained for lineage.

Three honest notes.

**1. Ids in validity vectors are not content addresses.** They are
uniformly-mapped well-formed identifiers, because V15 and V16 deliberately test
self-reference - and a genuinely content-addressed object cannot contain its own
hash, which is exactly why the rule exists. The identity vectors, V24-V26,
exercise true content addressing at run time.

**2. V11's `signature` does not verify.** This page previously said it did;
measured on 2026-07-27, it does not, and neither is V11's `id` the hash of its
own bytes. The signature was real when it was pinned - the harness key `ab12`
signed it - but the whole-word re-mint then rewrote V11's `about` value from
`cro:…` to `causal_relation_object:…`, which changed the canonical bytes
underneath it. `freeze_2_0_0.py` re-pins a signature only where it finds the
literal `"<128 hex>"` placeholder, never one that its own rewrite has just
invalidated, so V11 kept a signature over bytes that no longer exist. Nothing
observes it, which is why it survived: V11's declared `operation` is
`validate_schema`, its only expectation is `schema_valid: true`, and no binding
reads either field - the two hex strings appear nowhere else in the repository.
It is left as it lies rather than quietly re-frozen after release: repairing it
changes the bytes of a frozen vector, and a re-freeze belongs to a version bump
(see [`../GOVERNANCE.md`](../GOVERNANCE.md)). The vector that actually exercises
signature verification, V29, carries no bytes at all - like every vector from
V39 up, it is prose.

**3. The symbolic-id normalization is vestigial.** The harnesses' old
normalization now simply passes frozen values through; it remains only so the
harnesses stay able to run historical pre-freeze vector sets.

## Running the suite

Every binding ships its own runner. The Python one is the reference:

```
python3 bindings/python/tests/run_conformance.py
```

It exits nonzero on any failure and is the authoritative 4.0.0 reference:
**137/137 pass**.

**Status, re-measured 2026-07-27: all nineteen bindings pass 137/137 in this
repository** — C++, C#, Dart, Elixir, Go, Haskell, Java, JavaScript, Julia,
Kotlin, Lua, Perl, PHP, Python, R, Ruby, Rust, Swift and Zig. Each was run from
a working directory outside the checkout, with `CAUSALONTOLOGY_SPEC` set to a
poison value in the parent shell and stripped for the run with
`env -u CAUSALONTOLOGY_SPEC`. (An earlier version of this page said the Python
reference was the only binding at the 4.0.0 gate and that the others sat at the
107-vector 2.0.0 baseline. That was true when written and is no longer.)

Passing here is a weaker fact than it sounds, and the distinction is the whole
of what went wrong on 2026-07-27: a binding does not publish 4.0.0 until the
suite passes against the artifact **installed fresh from its registry**, from
outside any checkout — not against the source tree beside it. See
[`../PUBLISHING.md`](../PUBLISHING.md) and the
[4.0.0 release plan](../docs/Causalontology_4_0_0_Release_Plan.txt).

The 4.0.0 additions are all ADDITIVE and IDENTITY-PRESERVING: every 3.0.0 record
stays valid and keeps its identifier byte-for-byte under 4.0.0 — V136 witnesses
this directly by re-pinning the exact frozen 3.0.0 bytes, and V106, V111, and
V118 continue to witness the earlier baselines.

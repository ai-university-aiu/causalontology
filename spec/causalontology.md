# Causalontology — Normative Specification (specification 4.0.0 — twenty-one kinds; the attitude, the predicted occurrence, and the prediction error added additively over the 3.0.0 baseline)

**Causalontology's purest form is a specification, not a program.** This file is
the normative core; the complete design rationale, glossary, and lay-readable
explanations live in the master document at the repository root,
`Causalontology_Standalone_Design_v27.txt`, which is authoritative where this
summary and it could ever be read to differ.

Every identifier scheme and type value in this standard is a whole English word
(Principle P7): the scheme, the type value, and the id prefix are one string.
The only exceptions are the proper names of external standards (ed25519,
SHA-256, RFC 8785, RFC 3339, UCUM, UTC, JSON, JSON-LD, BFO, RO, PROV).

## The object model: twenty-one kinds

### Type-tier content kinds (identity is content; immutable, content-addressed)

| Kind | Prefix | What it is |
|---|---|---|
| Occurrent | `occurrent:` | a process or event TYPE (a verb) — now optionally pitched at a `stratum` |
| Causal Relation Object | `causal_relation_object:` | a reified causal claim: causes, effects, optional mechanism, temporal window (whose `unit` may be a wall-clock unit or, in 3.0.0, the ordinal `ticks`), modality, context, refines, `skips` |
| Continuant | `continuant:` | a thing that endures (a noun) |
| Realizable entity | `realizable:` | a disposition, function, or role — now with an optional identity-bearing `label` (defect repair) |
| Stratum | `stratum:` | a level of description within a named stratification scheme |
| Bridge | `bridge:` | a cross-stratal identity map: one coarse occurrent IS a set of finer ones |
| Cross Stratal Seam | `cross_stratal_seam:` | **3.0.0.** a managed jump across NON-adjacent strata, recording (via `mechanism_status`) whether an intervening mechanism exists-but-is-unmodeled or is absent, with an optional drawn `chain` of intervening steps and the coarsest-stratum HOME rule |
| Port | `port:` | a typed interface borne by a continuant |
| Conduit | `conduit:` | a directed, typed connection from port to port (transmissive or computational) — now, in 3.0.0, optionally carrying `realized_by`, a reference by identity to the native law or signal that realizes its transform |
| Quality | `quality:` | a property type a thing can bear |

### Token-tier content kinds (immutable, content-addressed, LOCAL BY DEFAULT)

| Kind | Prefix | What it is |
|---|---|---|
| Token Individual | `token_individual:` | a particular thing (one instance of a continuant type) |
| Token Occurrence | `token_occurrence:` | a particular happening, at absolute time, with participants |
| State Assertion | `state_assertion:` | a particular individual bearing a particular value over an interval |
| Token Causal Claim | `token_causal_claim:` | a particular happening causing a particular happening |
| Attitude | `attitude:` | **4.0.0.** what a modeled agent's mind CONTAINS (believes, desires, intends, knows, expects, fears) toward any content object — which may be false, and may be another attitude |
| Predicted Occurrence | `predicted_occurrence:` | **4.0.0.** an EXPECTATION: an occurrent type predicted by a stated predictor over exactly one temporal dimension — the sibling of the token occurrence that has not (yet) happened |
| Prediction Error | `prediction_error:` | **4.0.0.** how a prediction met the world: the signed discrepancy (actual minus expected) between a predicted occurrence and what was, or was not, observed |

### Provenance kinds (signed, add-only records)

| Kind | Prefix | What it says |
|---|---|---|
| Assertion | `assertion:` | "source S asserts claim C, evidence type t, strength s, confidence c, at time T", now optionally citing token evidence via `evidenced_by` |
| Enrichment | `enrichment:` | "I add entry E to field F of object X" (aliases, participants, subsumes, part_of, realized_in, occurrent_subsumes, occurrent_part_of) |
| Retraction | `retraction:` | "I withdraw my own earlier assertion or enrichment" |
| Succession | `succession:` | "key K2 succeeds key K1" (signed by K1) |

**Scope:** this specification models BOTH type-level (generic) causation and
token-level (particular) history. The token tier is shipped as a cascade
(§5.5 of the change order) and is now seven kinds (4.0.0 adds the attitude,
the predicted occurrence, and the prediction error), still LOCAL BY DEFAULT;
see `safety.md`.

## The load-bearing decision

Content is separated from provenance, uniformly. Content objects are pure and
immutable; every mutable datum — every alias, link, claim, withdrawal, key
rotation — is a signed record with an author. The ten 2.0.0 content kinds obey
this without exception: none carries strength, confidence, probability, source, or
timestamp-of-assertion (Principle P4). The three 4.0.0 token kinds obey it too,
with ONE recorded, deliberate carve-out: a `predicted_occurrence`'s optional
`strength` is part of the PREDICTED CONTENT itself — the grade of the
expectation, like a relation's modality — not a provenance evaluation of the
record; confidence in and evidence for the prediction still travel in
assertions (the 4.0.0 locked-decision extension).

## Requiredness

In a Causal Relation Object only `id`, `causes`, and `effects` are required (the required-fields minimalism of Principle P6).
Partial and degenerate objects are first-class. `skips: true` positively
converts the "no mechanism" gap into a finding (Principle P5).

## Conformance clause

An implementation is conformant if and only if it passes every vector in
`../conformance/vectors/` (V01–V137) for specification version 4.0.0. See
`../conformance/README.md`.

## Normative companions

- `identity.md` — canonicalization (RFC 8785), hashing (Secure Hash Algorithm 256-bit (SHA-256)), identity-bearing fields for all twenty-one kinds, merge
- `semantics.md` — the rules beyond the schemas (rules 1–12, six amended; new rules 13–25)
- `provenance.md` — signatures (Ed25519), evidence grading (with simulation), evidenced_by, retraction, succession, trust
- `store.md` — abstract operations, Hypertext Transfer Protocol (HTTP) binding, query, resolve, the complete gap taxonomy
- `safety.md` — abuse resistance, claims of consequence, takedown by tier, TOKEN-TIER SAFETY
- `schema/` — the twenty-one JSON Schemas, the JSON-LD context, the optional Protobuf encoding

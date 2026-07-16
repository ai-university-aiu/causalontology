# Causalontology — Normative Specification (specification 2.0.0 — whole-word baseline, vectors re-frozen)

**Causalontology's purest form is a specification, not a program.** This file is
the normative core; the complete design rationale, glossary, and lay-readable
explanations live in the master document at the repository root,
`Causalontology_Standalone_Design_v15.txt`, which is authoritative where this
summary and it could ever be read to differ.

Every identifier scheme and type value in this standard is a whole English word
(Principle P7): the scheme, the type value, and the id prefix are one string.
The only exceptions are the proper names of external standards (ed25519,
SHA-256, RFC 8785, RFC 3339, UCUM, UTC, JSON, JSON-LD, BFO, RO, PROV).

## The object model: seventeen kinds

### Type-tier content kinds (identity is content; immutable, content-addressed)

| Kind | Prefix | What it is |
|---|---|---|
| Occurrent | `occurrent:` | a process or event TYPE (a verb) — now optionally pitched at a `stratum` |
| Causal Relation Object | `causal_relation_object:` | a reified causal claim: causes, effects, optional mechanism, temporal window, modality, context, refines, `skips` |
| Continuant | `continuant:` | a thing that endures (a noun) |
| Realizable entity | `realizable:` | a disposition, function, or role — now with an optional identity-bearing `label` (defect repair) |
| Stratum | `stratum:` | a level of description within a named stratification scheme |
| Bridge | `bridge:` | a cross-stratal identity map: one coarse occurrent IS a set of finer ones |
| Port | `port:` | a typed interface borne by a continuant |
| Conduit | `conduit:` | a directed, typed connection from port to port (transmissive or computational) |
| Quality | `quality:` | a property type a thing can bear |

### Token-tier content kinds (immutable, content-addressed, LOCAL BY DEFAULT)

| Kind | Prefix | What it is |
|---|---|---|
| Token Individual | `token_individual:` | a particular thing (one instance of a continuant type) |
| Token Occurrence | `token_occurrence:` | a particular happening, at absolute time, with participants |
| State Assertion | `state_assertion:` | a particular individual bearing a particular value over an interval |
| Token Causal Claim | `token_causal_claim:` | a particular happening causing a particular happening |

### Provenance kinds (signed, add-only records)

| Kind | Prefix | What it says |
|---|---|---|
| Assertion | `assertion:` | "source S asserts claim C, evidence type t, strength s, confidence c, at time T", now optionally citing token evidence via `evidenced_by` |
| Enrichment | `enrichment:` | "I add entry E to field F of object X" (aliases, participants, subsumes, part_of, realized_in, occurrent_subsumes, occurrent_part_of) |
| Retraction | `retraction:` | "I withdraw my own earlier assertion or enrichment" |
| Succession | `succession:` | "key K2 succeeds key K1" (signed by K1) |

**Scope:** this specification models BOTH type-level (generic) causation and
token-level (particular) history. The token tier is shipped as a cascade
(§5.5 of the change order) and is LOCAL BY DEFAULT; see `safety.md`.

## The load-bearing decision

Content is separated from provenance, uniformly. Content objects are pure and
immutable; every mutable datum — every alias, link, claim, withdrawal, key
rotation — is a signed record with an author. The nine new content kinds obey
this without exception: none carries strength, confidence, source, or
timestamp-of-assertion (Principle P4).

## Requiredness

In a Causal Relation Object only `id`, `causes`, and `effects` are required.
Partial and degenerate objects are first-class. `skips: true` positively
converts the "no mechanism" gap into a finding (Principle P5).

## Conformance clause

An implementation is conformant if and only if it passes every vector in
`../conformance/vectors/` (V01–V107) for specification version 2.0.0. See
`../conformance/README.md`.

## Normative companions

- `identity.md` — canonicalization (RFC 8785), hashing (SHA-256), identity-bearing fields for all seventeen kinds, merge
- `semantics.md` — the rules beyond the schemas (rules 1–12, four amended; new rules 13–21)
- `provenance.md` — signatures (Ed25519), evidence grading (with simulation), evidenced_by, retraction, succession, trust
- `store.md` — abstract operations, HTTP binding, query, resolve, the complete gap taxonomy
- `safety.md` — abuse resistance, claims of consequence, takedown by tier, TOKEN-TIER SAFETY
- `schema/` — the seventeen JSON Schemas, the JSON-LD context, the optional Protobuf encoding

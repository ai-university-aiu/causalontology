# Causalontology — Normative Specification (specification 1.0.0 — vectors frozen 2026-07-13)

**Causalontology's purest form is a specification, not a program.** This file is
the normative core; the complete design rationale, glossary, and lay-readable
explanations live in the master document at the repository root,
`Causalontology_Standalone_Design_v11.txt`, which is authoritative where this
summary and it could ever be read to differ.

## The object model: eight kinds

Four **content kinds** (identity is content; they carry *only* identity-bearing
fields and are immutable):

| Kind | Prefix | What it is |
|---|---|---|
| Occurrent | `occ:` | a process or event TYPE (a verb): the vocabulary of causes and effects |
| Causal Relation Object (CRO) | `cro:` | a reified causal claim: causes, effects, optional mechanism, temporal window, modality, context, refines |
| Continuant | `cnt:` | a thing that endures (a noun) |
| Realizable entity | `rlz:` | a disposition, function, or role — inheres in a continuant, realized in occurrents |

Four **provenance kinds** (signed, add-only records):

| Kind | Prefix | What it says |
|---|---|---|
| Assertion | `ast:` | "I, source S, assert claim C, evidence type t, strength s, confidence c, at time T" |
| Enrichment | `enr:` | "I add entry E to field F of object X" (aliases, participants, subsumes, part_of, realized_in) |
| Retraction | `ret:` | "I withdraw my own earlier assertion or enrichment" |
| Succession | `suc:` | "key K2 succeeds key K1" (signed by K1) |

**Scope:** this specification models TYPE-LEVEL (generic) causation. The
token-level kind is reserved (prefix `tok:`) for a future version.

## The load-bearing decision

Content is separated from provenance, uniformly. Content objects are pure and
immutable; every mutable datum — every alias, link, claim, withdrawal, key
rotation — is a signed record with an author. Unsigned attribution is forbidden
by design (it enables framing).

## Requiredness

In a CRO only `id`, `causes`, and `effects` are required. Partial and
degenerate objects are first-class: they power the subsumption principle (an
external causal edge imports as a degenerate CRO) and the stigmergy (a partial
object is a visible invitation to enrich it, via `refines`).

## Conformance clause

An implementation is conformant if and only if it passes every vector in
`../conformance/vectors/` for the specification version it declares. See
`../conformance/README.md`.

## Normative companions

- `identity.md` — canonicalization (RFC 8785), hashing (SHA-256), identity-bearing fields, merge
- `semantics.md` — the rules beyond the schemas (13 rules)
- `provenance.md` — signatures (Ed25519), evidence grading, retraction, succession, trust
- `store.md` — abstract operations, HTTP binding, query, resolve, pagination, tiers
- `safety.md` — abuse resistance, claims of consequence, takedown by tier
- `schema/` — the eight JSON Schemas, the JSON-LD context, the optional Protobuf encoding

# Identity: content-addressed identifiers, canonicalization, and merge

## The rule

Every object's identifier is `scheme:localpart` where the scheme is one of
`occ cro cnt rlz ast enr ret suc` and the localpart is the lowercase
hexadecimal SHA-256 digest (64 characters) of the object's canonical
identity-bearing bytes.

## Canonicalization procedure

1. Take the object as a JSON document.
2. Remove the fields that are NOT identity-bearing for its kind (table below).
3. Apply **RFC 8785 (JSON Canonicalization Scheme)** to the remainder.
4. Hash the bytes with SHA-256.
5. Identifier = scheme + ":" + lowercase hex digest.

## Identity-bearing fields, by kind

| Kind | Identity-bearing fields |
|---|---|
| occurrent | type, label, category |
| cro | type, causes, effects, mechanism, temporal, modality, context, refines |
| continuant | type, label, category |
| realizable | type, kind, bearer |
| assertion | type, about, source, evidence_type, evidence, strength, confidence, timestamp |
| enrichment | type, about, field, entry, source, timestamp |
| retraction | type, retracts, source, timestamp |
| succession | type, predecessor, successor, timestamp |

Exclusions: `id` always (it IS the hash); `signature` on the four provenance
kinds (the signature is computed over these same canonical bytes). Nothing
else is excluded — content objects consist of exactly their identity-bearing
fields.

An enrichment's source and timestamp ARE identity-bearing: the same entry from
two sources (or twice from one source) is deliberately two records — that is
corroboration.

## Merge

- Content objects are **immutable**: writing an existing identity is a
  no-operation (idempotent).
- Provenance records are **add-only**: present or not; rewriting is idempotent
  (Ed25519 is deterministic per RFC 8032, so even signature bytes agree).
- Replicas merge by **set union**, in any order, with no coordinator — the
  store is a CRDT by construction. Nothing is removed by merge; removal from
  view is retraction (the author) or suppression (policy).

## Vocabulary convergence

Content-addressing is awkward for bare vocabulary (a label is thin content), so
convergence is bought with three disciplines: the canonical-label rule
(English lowercase snake_case whole words; homonyms qualified:
`charge_battery`, `charge_attack`), the closed category enumerations, and the
REQUIRED resolve-before-mint workflow. Residual near-synonyms are merged
socially, by an assertion marking one item the alias of another.

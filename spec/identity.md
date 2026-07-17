# Identity: content-addressed identifiers, canonicalization, and merge

## The rule

Every object's identifier is `scheme:localpart` where the scheme is one of the
seventeen whole-word schemes

```
occurrent  causal_relation_object  continuant  realizable  stratum  bridge
port  conduit  quality  token_individual  token_occurrence  state_assertion
token_causal_claim  assertion  enrichment  retraction  succession
```

and the localpart is the lowercase hexadecimal Secure Hash Algorithm 256-bit (SHA-256) digest (64 characters)
of the object's canonical identity-bearing bytes. Every scheme is a whole
English word (Principle P7); abbreviations MUST NOT be used. The proper names
of external standards (ed25519, SHA-256, RFC 8785, RFC 3339, UCUM, UTC, JSON,
JSON-LD, BFO, RO, PROV) are kept verbatim.

## Canonicalization procedure

1. Take the object as a JSON document.
2. Remove the fields that are NOT identity-bearing for its kind (table below).
3. Apply **RFC 8785 (JSON Canonicalization Scheme)** to the remainder.
4. Hash the bytes with SHA-256.
5. Identifier = scheme + ":" + lowercase hex digest.

## Identity-bearing fields, by kind

| Kind | Identity-bearing fields |
|---|---|
| occurrent | type, label, category, **stratum** |
| causal_relation_object | type, causes, effects, mechanism, temporal, modality, context, refines, **skips** |
| continuant | type, label, category |
| realizable | type, kind, bearer, **label** |
| stratum | type, label, scheme, ordinal, unit, governs |
| bridge | type, coarse, fine, relation |
| port | type, bearer, label, direction, accepts, realizable |
| conduit | type, label, from, to, carries, transform |
| quality | type, label, datatype, unit, stratum |
| token_individual | type, instantiates, designator, part_of |
| token_occurrence | type, instantiates, interval, participants, locus, observer |
| state_assertion | type, subject, quality, value, interval |
| token_causal_claim | type, causes, effects, covering_law, actual_delay, counterfactual |
| assertion | type, about, source, evidence_type, evidence, strength, confidence, timestamp, **evidenced_by** |
| enrichment | type, about, field, entry, source, timestamp |
| retraction | type, retracts, source, timestamp |
| succession | type, predecessor, successor, timestamp |

Fields added or amended in 2.0.0 are shown in **bold**. All added fields are
OPTIONAL: content addressing hashes only the fields PRESENT, so every
whole-word 1.0.0 record produces the same hash under 2.0.0 (formal proof:
vector V106). The temporal window's fields are `minimum_delay` and
`maximum_delay` (the former `dmin`/`dmax`, spelled out).

Exclusions: `id` always (it IS the hash); `signature` on the four provenance
kinds (the signature is computed over these same canonical bytes). Nothing
else is excluded — content objects consist of exactly their identity-bearing
fields.

An enrichment's source and timestamp ARE identity-bearing: the same entry from
two sources (or twice from one source) is deliberately two records — that is
corroboration.

## Merge

- Content objects are **immutable**: writing an existing identity is a
  no-operation (idempotent). All thirteen content kinds (four original + nine
  new) merge by set union.
- Provenance records are **add-only**: present or not; rewriting is idempotent
  (Ed25519 is deterministic per RFC 8032, so even signature bytes agree).
- Replicas merge by **set union**, in any order, with no coordinator — the
  store is a Conflict-free Replicated Data Type (CRDT) by construction. Nothing
  is removed by merge; removal from
  view is retraction (the author) or suppression (policy).

## Vocabulary convergence

Content-addressing is awkward for bare vocabulary (a label is thin content), so
convergence is bought with three disciplines: the canonical-label rule
(English lowercase snake_case whole words; homonyms qualified:
`charge_battery`, `charge_attack`), the closed category enumerations, and the
REQUIRED resolve-before-mint workflow. Residual near-synonyms are merged
socially, by an assertion marking one item the alias of another.

Note that `occurrent.stratum` is identity-bearing: an occurrent with label
`depolarization` at the subcellular stratum and one at the cellular stratum are
DIFFERENT OBJECTS with DIFFERENT identities. This is the intent (N3.3.2).

# Identity: content-addressed identifiers, canonicalization, and merge

## The rule

Every object's identifier is `scheme:localpart` where the scheme is one of the
twenty-one whole-word schemes

```
occurrent  causal_relation_object  continuant  realizable  stratum  bridge
cross_stratal_seam  port  conduit  quality  token_individual  token_occurrence
state_assertion  token_causal_claim  attitude  predicted_occurrence
prediction_error  assertion  enrichment  retraction  succession
```

and the localpart is the lowercase hexadecimal Secure Hash Algorithm 256-bit (SHA-256) digest (64 characters)
of the object's canonical identity-bearing bytes. Every scheme is a whole
English word (Principle P7); abbreviations MUST NOT be used. The proper names
of external standards (ed25519, SHA-256, RFC 8785, RFC 3339, UCUM, UTC, JSON,
JSON-LD, BFO, RO, PROV) are kept verbatim.

**A Causalontology identifier is not a Uniform Resource Identifier (URI), and
RDF consumers must not assume it is** (recorded 2026-07-27; it had not been
written down anywhere). RFC 3986 allows only letters, digits, `+`, `-` and `.`
in a URI scheme. Eight of the twenty-one schemes carry an underscore —
`causal_relation_object`, `cross_stratal_seam`, `token_individual`,
`token_occurrence`, `state_assertion`, `token_causal_claim`,
`predicted_occurrence`, `prediction_error` — so `causal_relation_object:<hex>`
is neither an absolute URI nor a usable relative reference. Measured with
rdflib 6.1.1 against [`schema/context.jsonld`](schema/context.jsonld): a record
of one of those eight kinds does NOT become a blank node — it is resolved
against the document base, yielding a base-dependent absolute IRI such as
`file:///path/to/cwd/causal_relation_object:aaa…`, while the other thirteen
expand cleanly to `occurrent:aaa…` under a private scheme. The base-dependent
outcome is the more dangerous of the two, because it is silent and looks
plausible: two consumers expanding the same content-addressed record from
different base URIs mint different identifiers for it, and nothing announces
that. Note also that this is processor behaviour, not a property of JSON-LD 1.1
itself — a conforming processor preserves all twenty-one verbatim. This costs nothing in
the JSON form, which is normative, and nothing in any binding — no binding
treats an identifier as a URI. It matters only when projecting to RDF, where a
consumer MUST map `scheme:localpart` into a URI space of its own before
expansion. Choosing an official one is a specification change and is left to
governance rather than decided here.

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
| cross_stratal_seam | type, source, target, mechanism_status, **chain** _(3.0.0)_ |
| port | type, bearer, label, direction, accepts, realizable |
| conduit | type, label, from, to, carries, transform, **realized_by** _(3.0.0)_ |
| quality | type, label, datatype, unit, stratum |
| token_individual | type, instantiates, designator, part_of |
| token_occurrence | type, instantiates, interval, participants, locus, observer |
| state_assertion | type, subject, quality, value, interval |
| token_causal_claim | type, causes, effects, covering_law, actual_delay, counterfactual |
| attitude | type, holder, attitude_type, content _(4.0.0)_ |
| predicted_occurrence | type, instantiates, interval, predictor, strength _(4.0.0)_ |
| prediction_error | type, predicted, observed, discrepancy _(4.0.0)_ |
| assertion | type, about, source, evidence_type, evidence, strength, confidence, timestamp, **evidenced_by** |
| enrichment | type, about, field, entry, source, timestamp |
| retraction | type, retracts, source, timestamp |
| succession | type, predecessor, successor, timestamp |

Fields added or amended in 2.0.0 are shown in **bold** in the prose that
introduced them; the fields marked _(3.0.0)_ above are the 3.0.0 additions. All
added fields are OPTIONAL, and content addressing hashes only the fields
PRESENT, so every whole-word 1.0.0 record produces the same hash under 2.0.0
(formal proof: vector V106) AND every 2.0.0 record that remains valid produces
the same hash under 3.0.0 (formal proof: vectors V111 for a wall-clock temporal
window and V118 for an unbound conduit). The temporal window's fields are
`minimum_delay` and `maximum_delay` (the former `dmin`/`dmax`, spelled out); its
`unit` gained the ordinal value `ticks` in 3.0.0, which is dimensionless and
identity-bearing (a tick-unit record differs in identity from an otherwise
identical wall-clock record). The eighteenth kind `cross_stratal_seam` opens a
new identity scheme and disturbs no existing record.

The rows marked _(4.0.0)_ above are the 4.0.0 additions. Every 3.0.0 record
keeps its identifier byte-for-byte under 4.0.0 (formal proof: vector V136
re-pins the exact V111 wall-clock and V118 unbound-conduit identifiers under
the 4.0.0 implementation). The three new kinds `attitude`,
`predicted_occurrence`, and `prediction_error` open new identity schemes and
disturb no existing record.

Exclusions: `id` always (it IS the hash); `signature` on the four provenance
kinds (the signature is computed over these same canonical bytes). Nothing
else is excluded — content objects consist of exactly their identity-bearing
fields.

An enrichment's source and timestamp ARE identity-bearing: the same entry from
two sources (or twice from one source) is deliberately two records — that is
corroboration.

## Merge

- Content objects are **immutable**: writing an existing identity is a
  no-operation (idempotent). All seventeen content kinds (ten type-tier +
  seven token-tier) merge by set union.
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

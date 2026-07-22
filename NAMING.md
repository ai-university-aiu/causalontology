# Naming conventions

This document records the public naming conventions of the Causalontology
standard. It is normative in spirit but non-normative in force: the binding
source of truth is [`spec/causalontology.md`](spec/causalontology.md) and the
JSON Schemas under [`spec/schema/`](spec/schema/).

## Principle P7 — whole-word identifier schemes

Every identifier scheme, type value, and id prefix in this standard is a single
whole English word (or an underscore-joined phrase of whole English words). The
scheme, the `type` field value, and the content-addressed id prefix are one and
the same string:

```
occurrent:9f2c…        type = "occurrent"
causal_relation_object:1a7b…   type = "causal_relation_object"
```

No abbreviations. There is no `occ:` / `cro:` / `rlz:` shorthand — the
abbreviated schemes of specification 1.0.0 were retired in the 2.0.0 whole-word
re-mint. An implementation MUST reject an abbreviated scheme (conformance
vectors V107 and, for the kinds added in 4.0.0, V137).

## The twenty-one schemes

| Tier | Scheme (whole word) | 1.0.0 abbreviation (retired) |
|---|---|---|
| Type | `occurrent` | `occ` |
| Type | `continuant` | `cnt` |
| Type | `realizable` | `rlz` |
| Type | `causal_relation_object` | `cro` |
| Type | `quality` | `qal` |
| Type | `stratum` | `str` |
| Type | `bridge` | `brg` |
| Type | `port` | `prt` |
| Type | `conduit` | `cdt` |
| Type | `cross_stratal_seam` | (none; new in 3.0.0) |
| Token | `token_individual` | `tid` |
| Token | `token_occurrence` | `tok` |
| Token | `state_assertion` | `stt` |
| Token | `token_causal_claim` | `tcr` |
| Token | `attitude` | (none; new in 4.0.0) |
| Token | `predicted_occurrence` | (none; new in 4.0.0) |
| Token | `prediction_error` | (none; new in 4.0.0) |
| Provenance | `assertion` | `ast` |
| Provenance | `enrichment` | `enr` |
| Provenance | `retraction` | `ret` |
| Provenance | `succession` | `suc` |

The reified causal primitive is spelled **`causal_relation_object`** in full;
the abbreviation `cro` is retired everywhere, including the sister projects
(PrologAI, Mentova) that consume this vocabulary.

## Field renames (2.0.0)

Temporal-window fields are spelled out in full:

| 1.0.0 field | 2.0.0 field |
|---|---|
| `dmin` | `minimum_delay` |
| `dmax` | `maximum_delay` |

## Exempt external proper names

Whole-word spelling applies to Causalontology's own identifier schemes. It does
**not** rewrite the proper names of external standards, algorithms, and
registries, which are kept verbatim as the wider world writes them:

- Cryptography and hashing: `ed25519` (Ed25519, RFC 8032), `SHA-256`, `SHA-512`.
- Canonicalization and formats: `RFC 8785` (JCS), `RFC 3339`, `JSON`, `JSON-LD`,
  `UCUM`, `UTC`.
- Ontology alignment vocabularies: `BFO`, `RO`, `PROV`.

These appear literally in field values, documentation, and the non-normative
encodings ([`spec/schema/context.jsonld`](spec/schema/context.jsonld),
[`spec/schema/causalontology.owl.ttl`](spec/schema/causalontology.owl.ttl),
[`spec/schema/causalontology.proto`](spec/schema/causalontology.proto)) and are
never abbreviated or re-minted.

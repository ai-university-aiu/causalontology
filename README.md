<p align="center">
  <img src="assets/Causalontology_754x176.png" alt="Causalontology" width="754">
</p>

# Causalontology

**A language-neutral standard and a shared global commons for reified causation — the data-structure layer of the book *Causalontology: AGI's Missing Link*.**

![Spec](https://img.shields.io/badge/spec-version%206%20(pre--1.0)-blue)
![Conformance](https://img.shields.io/badge/conformance%20vectors-38-brightgreen)
![Status](https://img.shields.io/badge/status-scaffold%20%2F%20pre--release-orange)
![License](https://img.shields.io/badge/license-Attribution%20always%3B%20no%20profit%2C%20no%20problem%20(Apache--2.0)-lightgrey)

---

## The World's First

Causalontology's identity, stated from five angles — each the same claim, that this is a first-of-its-kind synthesis:

> **Reification / Timing / Learning.** "Causalontology is the world's first synthesis of reified causal representation, temporal-mechanistic modeling, and interventional learning into a single glass-box unified ontology."

> **Noun / Verb Governance.** "Causalontology is the world's first synthesis of a process-first causal calculus, a continuant noun backbone, and a realizable hinge between them — one foundational ontology governing the verbs and hosting the nouns."

> **The Bridge.** "Causalontology is the world's first synthesis of symbolic causal reasoning, the philosophy of process, and embodied interventional learning, unified in a single glass-box ontology."

> **Scholarly Framing.** "Causalontology is the world's first synthesis of process ontology, causal modeling, and constructivist learning into a single foundational ontology."

> **Succinctly.** "Causalontology is the world's first synthesis of reification, temporal causation, and interventional learning in one unified, glass-box ontology."

And this repository adds a further first of its own: to our knowledge, the first specification to deliver reified, provenance-signed causation as a **language-neutral standard** with a **shared, stigmergic commons** — offered, glass-box style, with its evidence: the specification, the conformance vectors, and the running implementations, all inspectable.

Every term above is explained for a newcomer in the master document: [`Causalontology_Standalone_Design_v6.txt`](Causalontology_Standalone_Design_v6.txt) — the complete, self-contained canon of this repository.

---

## What is Causalontology?

**Causalontology's purest form is a specification, not a program.** It separates the *data structure of causation and its rules* (language-neutral) from any *implementation* (Prolog, Python, Java, Swift, ...). Two familiar pictures, held together:

- **A standard** — like a W3C or IETF specification: a normative document plus a conformance test suite, with independent implementations that all agree because they all pass the same tests.
- **A commons** — like Wikidata, specialized to causation: one shared, world-wide, provenance-first store of causal knowledge that developers everywhere (and autonomous minds) draw from and contribute to.

The reference implementation is [**PrologAI**](https://github.com/ai-university-aiu/PrologAI), a glass-box cognitive architecture, driving the synthetic mind [**Mentova**](https://github.com/ai-university-aiu/Mentova).

## The eight kinds of thing

Four **content kinds** — pure, immutable, content-addressed (SHA-256 over RFC 8785 canonical bytes):

| Kind | Prefix | What it is |
|---|---|---|
| Occurrent | `occ:` | a process or event **type** (a verb) — the vocabulary of causes and effects |
| **Causal Relation Object (CRO)** | `cro:` | the fundamental unit: a reified causal claim — causes, effects, mechanism, temporal window, modality, context, `refines` lineage |
| Continuant | `cnt:` | a thing that endures (a noun) |
| Realizable entity | `rlz:` | a disposition, function, or role — the hinge between nouns and verbs |

Four **provenance kinds** — signed (Ed25519), add-only records:

| Kind | Prefix | What it says |
|---|---|---|
| Assertion | `ast:` | who claims it, on what evidence (intervention > observation), how strongly |
| Enrichment | `enr:` | who added which alias, participant, or taxonomy link — **every word has an author** |
| Retraction | `ret:` | a source's honest withdrawal of its own record — history never erased |
| Succession | `suc:` | key rotation with lineage |

**The load-bearing decision:** content is separated from provenance, uniformly. The same claim from any number of sources is *one* object; contradictory claims coexist, each with signed provenance; trust is a consumer-chosen policy, never forced consensus. The whole store merges by set union — a CRDT by construction.

## Quickstart (30 seconds)

```json
{ "type": "occurrent", "label": "press_button", "category": "action" }
{ "type": "occurrent", "label": "light_on",     "category": "state_change" }
{ "type": "cro", "causes": ["occ:press_button"], "effects": ["occ:light_on"] }
```

That third document — a *degenerate* CRO, just cause and effect — is already valid, and the store lists it as a **gap** inviting enrichment (`GET /gaps?kind=missing_field`). Someone (or some mind) later `refines` it with a temporal window and modality, and the gap visibly closes. That is **stigmergy**: the structure's own partiality guides the next contribution. Full walkthrough: [`examples/quickstart.md`](examples/quickstart.md).

## Repository layout

```
causalontology/
  Causalontology_Standalone_Design_v6.txt   the canon (complete, lay-readable)
  spec/
    causalontology.md      normative core
    identity.md            RFC 8785 + SHA-256 identity, merge semantics
    semantics.md           the 13 rules beyond the schemas
    provenance.md          signatures, evidence grading, retraction, succession
    store.md               operations, HTTP binding, query, resolve, tiers
    safety.md              abuse resistance, claims of consequence, takedown
    schema/                8 JSON Schemas + JSON-LD context + optional Protobuf
  conformance/vectors/     38 language-neutral test cases (the meaning of "correct")
  bindings/                per-language SDKs (PrologAI is the reference)
  store/server/            Tier A reference store (planned)
  store/stigmergy/         gap signals + contribution dashboard (planned)
  examples/                the four-language quickstart
  GOVERNANCE.md            semantic versioning, the enumeration rule, change process
  LICENSE · DATA_LICENSE · NOTICE
```

## Conformance

**An implementation is Causalontology-conformant if and only if it passes every vector in [`conformance/vectors/`](conformance/vectors/) for the specification version it declares.** That single rule is how Prolog, Python, Java, and Swift agree without sharing a line of code — down to the length of a month (2,629,746 seconds) and the ranking of a `resolve()`.

## Roadmap (the Minimum Viable Product)

- [x] Step 1 — publish the specification, schemas, and conformance vectors (this repository)
- [ ] Step 2 — `causalontology-py`: the second implementation, proving language independence
- [ ] Step 3 — the Tier A store: HTTP binding, signature verification, materialized views, quarantine
- [ ] Step 4 — the stigmergy read: `GET /gaps` + the contribution dashboard
- [ ] Then — Java and Swift SDKs · SPARQL endpoint · federation (Tier B) · decentralization (Tier C) · Mentova gardening the commons

## Governance

Semantic Versioning; the conformance suite versioned in lock-step; **extending any closed enumeration is a MAJOR change**; releases gated in CI on the vectors; an open change process with conformance impact statements. See [`GOVERNANCE.md`](GOVERNANCE.md).

## Contributing

Before the public launch, contributions land through the change process in `GOVERNANCE.md`. The contribution model of the commons itself is stigmergic: ask the store for the most valuable gaps, close one, sign your work. Vocabulary discipline: **resolve before you mint.**

## License

**"The attribution always; no profit, no problem license."** — one license for everything in this repository and its commons: the code, the data, the specification, and the architecture. It is the friendly name for the [Apache License 2.0](LICENSE) text, the same license carried by PrologAI and Mentova: attribution (the [`NOTICE`](NOTICE) file) is always required, and use without profit is never a problem. The data license ([`DATA_LICENSE`](DATA_LICENSE)) carries the same terms, by the owner's decision of 2026-07-13.

## Citation

> D. R. Dison. *Causalontology: AGI's Missing Link* — the Standalone Standard and the Shared Commons, Version 6 (Book Edition). AI University (AIU), 2026. github.com/ai-university-aiu/causalontology

## Author

**D. R. Dison** — Founder of AIU (Artificial Intelligence University), Creator and Owner of PrologAI and Mentova. ORCID [0009-0001-9246-5758](https://orcid.org/0009-0001-9246-5758) · [linkedin.com/in/d-r-dison](https://www.linkedin.com/in/d-r-dison/)

## Related projects

- [**PrologAI**](https://github.com/ai-university-aiu/PrologAI) — the glass-box cognitive architecture; Causalontology's reference implementation (ARC-AGI-1 public training set: 400/400, pure symbolic induction, no LLM)
- [**Mentova**](https://github.com/ai-university-aiu/Mentova) — the first Synthetic Mind written in PrologAI; the flagship mind and, one day, the first synthetic gardener of the commons

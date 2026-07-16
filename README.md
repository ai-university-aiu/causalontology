<p align="center">
  <img src="assets/Causalontology_754x176.png" alt="Causalontology" width="754">
</p>

<!-- THE RACK — ROW 1: THE HONORS -->
<p align="center">
  <a href="https://github.com/ai-university-aiu/PrologAI"><img src="https://img.shields.io/badge/ARC--AGI--1-400%2F400%3D100%25-FFCE59?style=for-the-badge" alt="ARC-AGI-1 400/400=100%"></a>
  <a href="https://github.com/ai-university-aiu/PrologAI"><img src="https://img.shields.io/badge/ARC--AGI--2-120%2F120%3D100%25-FFB24B?style=for-the-badge" alt="ARC-AGI-2 120/120=100%"></a>
  <img src="https://img.shields.io/badge/WORLD%27S_FIRST-REIFIED_CAUSATION_ONTOLOGY_STANDARD-FF973C?style=for-the-badge" alt="World's First — Reified Causation Ontology Standard">
</p>

<!-- ROW 2: THE STANDARD -->
<p align="center">
  <img src="https://img.shields.io/badge/CONFORMANCE_VECTORS-107-FA842F?style=for-the-badge" alt="Conformance Vectors 107">
  <img src="https://img.shields.io/badge/OBJECT_KINDS-17-F47223?style=for-the-badge" alt="Object Kinds 17">
  <img src="https://img.shields.io/badge/LOCKED_DECISIONS-27-EC5F1C?style=for-the-badge" alt="Locked Decisions 27">
</p>

<!-- ROW 3: THE FOUNDATIONS -->
<p align="center">
  <img src="https://img.shields.io/badge/CANONICAL-RFC_8785-E44B19?style=for-the-badge" alt="Canonical RFC 8785">
  <img src="https://img.shields.io/badge/IDENTITY-SHA--256-D73C17?style=for-the-badge" alt="Identity SHA-256">
  <img src="https://img.shields.io/badge/SIGNED-ED25519-C93118?style=for-the-badge" alt="Signed Ed25519">
  <img src="https://img.shields.io/badge/JSON--LD-LINKED_DATA-B22313?style=for-the-badge" alt="JSON-LD Linked Data">
</p>

<!-- ROW 4: THE CHARACTER -->
<p align="center">
  <img src="https://img.shields.io/badge/GLASS_BOX-ALWAYS-931008?style=for-the-badge" alt="Glass Box Always">
  <img src="https://img.shields.io/badge/STIGMERGY-BUILT_IN-770300?style=for-the-badge" alt="Stigmergy Built In">
  <img src="https://img.shields.io/badge/EVIDENCE-ACTING_%3E_WATCHING-670100?style=for-the-badge" alt="Evidence: Acting over Watching">
</p>

<!-- ROW 5: THE LINEAGE -->
<p align="center">
  <a href="https://github.com/ai-university-aiu/Mentova"><img src="https://img.shields.io/badge/FLAGSHIP_APPLICATION-MENTOVA_PROLOGAI-570000?style=for-the-badge" alt="Flagship Application: Mentova PrologAI"></a>
  <img src="https://img.shields.io/badge/BOOK-AGI%27S_MISSING_LINK-480000?style=for-the-badge" alt="Book: AGI's Missing Link">
  <img src="https://img.shields.io/badge/LICENSE-ATTRIBUTION_ALWAYS%3B_NO_PROFIT%2C_NO_PROBLEM-3A0000?style=for-the-badge" alt="License: Attribution always; no profit, no problem">
</p>

<p align="center"><sub>Benchmark scores by the reference implementation, PrologAI, on the public training sets — pure symbolic induction, no LLM.</sub></p>

<details>
<summary align="center"><b>What do these badges mean? — a plain-language guide to every ribbon (click to open)</b></summary>

<br>

Each badge above is a claim, and every claim deserves a plain explanation. Here they are, row by row, written for a newcomer. (The label side of each ribbon is a neutral grey, matching the PrologAI and Mentova badges; the colored right side runs a single warm fade across the project's official eight-color palette - from bright gold-yellow at the first honor, down through the oranges and reds, to a deep crimson-black at the license. See [BRANDING.md](BRANDING.md).)

**Row 1 — The Honors**

- **`ARC-AGI-1 | 400/400=100%`** — ARC-AGI stands for the *Abstraction and Reasoning Corpus for Artificial General Intelligence*: a famous series of public tests designed to measure whether a machine can genuinely reason about puzzles it has never seen, rather than repeat patterns it memorized. This badge says that Causalontology's reference implementation, **PrologAI**, solved **all 400 of 400** tasks in the first benchmark's public training set — a perfect score — using *pure symbolic induction*: readable logic rules discovered from the puzzle examples, with **no Large Language Model** (no LLM — the text-predicting technology behind modern chatbots) involved at all. The badge links to PrologAI so you can inspect the work.

- **`ARC-AGI-2 | 120/120=100%`** — the same story for the second, harder generation of the benchmark: **all 120 of 120** public tasks solved, a perfect score, by the same glass-box symbolic methods. (Honesty note, exactly as the fine print says: both scores are on the *public training sets* — the openly published task collections — stated precisely and without inflation.)

- **`WORLD'S FIRST | REIFIED CAUSATION ONTOLOGY STANDARD`** — the centerpiece claim. To **reify** means to turn an idea into a thing you can hold, name, and examine — here, turning "A causes B" from a bare arrow into a full object carrying its timing, its strength, its conditions, and its evidence. An **ontology** is an organized inventory of what exists and how things relate. A **standard** is a published specification anyone can implement, in any programming language, with a shared test suite deciding what counts as correct. This badge claims Causalontology is the first to deliver all three in one: causation, made into first-class objects, as an open standard.

**Row 2 — The Standard**

- **`CONFORMANCE VECTORS | 107`** — a *conformance vector* is a published test case: an input and the exact result a correct implementation must produce. There are 107 of them in this repository (V01–V38 the re-frozen original suite, V39–V107 the 2.0.0 additions), and the rule is simple: an implementation is Causalontology-conformant **if and only if it passes every one**. This is how a Python version, a Java version, and a Prolog version can all be guaranteed to agree without sharing a single line of code.

- **`OBJECT KINDS | 17`** — everything in Causalontology is one of exactly seventeen kinds of object: nine *type-tier content* kinds (occurrent, causal_relation_object, continuant, realizable, stratum, bridge, port, conduit, quality), four *token-tier content* kinds (token_individual, token_occurrence, state_assertion, token_causal_claim — a particular history, local by default), and four *provenance* kinds (assertion, enrichment, retraction, succession — the signed records saying who claims, adds, withdraws, or rotates what). Seventeen kinds, no exceptions — a learnable vocabulary for all causal knowledge, at every level of description and for both laws and histories.

- **`LOCKED DECISIONS | 27`** — the specification records 27 design decisions as *locked*: settled on purpose, in writing, so builders can proceed without the ground shifting under them. Changing one requires a formal, versioned process — not a quiet edit.

**Row 3 — The Foundations**

- **`CANONICAL | RFC 8785`** — an RFC (*Request for Comments*) is a published internet standard. RFC 8785 defines one exact, byte-for-byte way to write a piece of JSON data, so that the same information always produces the same bytes regardless of who wrote it or how they formatted it. Causalontology uses it so that identity can never depend on formatting accidents.

- **`IDENTITY | SHA-256`** — SHA-256 (the *Secure Hash Algorithm, 256-bit*) is a mathematical fingerprint function: feed it any content and it produces a unique fixed-length code, and any change to the content changes the code. In Causalontology, **an object's identity IS the fingerprint of its content** — which means two strangers anywhere on Earth who express the same causal claim automatically produce the same identifier, and their contributions merge with no coordinator.

- **`SIGNED | ED25519`** — Ed25519 is a fast, widely trusted *digital signature* scheme. A signature is mathematical proof that a specific keyholder — and nobody else — produced a record. In Causalontology every assertion, every added word, every retraction is signed, so every piece of knowledge in the commons has a verifiable author, and forging someone else's contribution is impossible.

- **`JSON-LD | LINKED DATA`** — JSON-LD (*JSON for Linked Data*) is a way of writing ordinary JSON so that it is simultaneously valid *linked data* — the web-standard format that lets knowledge from different sources connect into one global graph (the technology family behind Wikidata). Causalontology data speaks that language natively, so it can plug into the wider knowledge ecosystem for free.

**Row 4 — The Character**

- **`GLASS BOX | ALWAYS`** — a *black box* gives you an answer but hides its reasons; a **glass box** lets you see every step. Everything here is inspectable: every claim traces to a named rule and a signed author, and you can always ask "why?" and get a readable answer. This is the project's deepest commitment.

- **`STIGMERGY | BUILT IN`** — *stigmergy* is coordination through the shared environment itself: the way a half-built wall shows the next worker exactly where the next brick goes. In Causalontology, incomplete knowledge is visible and queryable — a claim missing its timing, a term nobody has defined, two claims that contradict — so the store itself continuously announces what most needs doing next, and any contributor (human or machine mind) can ask for the most valuable gap and fill it.

- **`EVIDENCE | ACTING > WATCHING`** — Causalontology grades its evidence, and the top grade is **intervention**: the source *acted* and observed what followed, like a child flipping a switch rather than staring at it. Acting breaks the ambiguity that haunts pure observation — a coincidence in the data cannot survive your own hand on the switch. Every piece of knowledge carries its evidence grade, so consumers can weigh doing above watching.

**Row 5 — The Lineage**

- **`FLAGSHIP APPLICATION | MENTOVA PROLOGAI`** — **PrologAI** is the glass-box cognitive architecture that serves as Causalontology's reference implementation, and **Mentova** is the synthetic mind built on it — the first full application of this ontology, and one day the first machine mind to read the commons' gaps and contribute causal knowledge back. The badge links to Mentova.

- **`BOOK | AGI'S MISSING LINK`** — this repository is the data-structure layer of the book *Causalontology: AGI's Missing Link*, whose thesis is that the component most conspicuously missing from today's AI is an explicit, learnable, inspectable model of cause and effect, acquired by acting on the world. The complete, lay-readable canon is right here: [`Causalontology_Standalone_Design_v15.txt`](Causalontology_Standalone_Design_v15.txt).

- **`LICENSE | ATTRIBUTION ALWAYS; NO PROFIT, NO PROBLEM`** — the project's license, in its own words: credit the source always, and using it without profit is never a problem. It is the friendly name for the Apache License 2.0 text (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)), one license covering everything here — the code, the data, the specification, and the architecture.

</details>

# Causalontology

**A verb-first noun-hosting ontology — reality is what happens, and things are its participants. A language-neutral standard and a shared global commons for reified causation — the data-structure layer of the book *Causalontology: AGI's Missing Link*.**

---

## The World's First

Causalontology's identity, stated from five angles — each the same claim, that this is a first-of-its-kind synthesis:

> **Reification / Timing / Learning.** "Causalontology is the world's first synthesis of reified causal representation, temporal-mechanistic modeling, and interventional learning into a single glass-box unified ontology."

> **Noun / Verb Governance.** "Causalontology is the world's first synthesis of a process-first causal calculus, a continuant noun backbone, and a realizable hinge between them — one foundational ontology governing the verbs and hosting the nouns."

> **The Bridge.** "Causalontology is the world's first synthesis of symbolic causal reasoning, the philosophy of process, and embodied interventional learning, unified in a single glass-box ontology."

> **Scholarly Framing.** "Causalontology is the world's first synthesis of process ontology, causal modeling, and constructivist learning into a single foundational ontology."

> **Succinctly.** "Causalontology is the world's first synthesis of reification, temporal causation, and interventional learning in one unified, glass-box ontology."

And this repository adds a further first of its own: to our knowledge, the first specification to deliver reified, provenance-signed causation as a **language-neutral standard** with a **shared, stigmergic commons** — offered, glass-box style, with its evidence: the specification, the conformance vectors, and the running implementations, all inspectable.

Every term above is explained for a newcomer in the master document: [`Causalontology_Standalone_Design_v15.txt`](Causalontology_Standalone_Design_v15.txt) — the complete, self-contained canon of this repository.

---

## What is Causalontology?

**Causalontology is a verb-first noun-hosting ontology.** Verb-first: the atomic building block is the occurrent — the happening — and the fundamental unit reifies the master verb, *causes*, itself; even knowing is verb-first, because knowledge enters by acting (intervention) rather than by watching. Noun-hosting: things (continuants) are first-class citizens, but they are understood through what they do and what happens to them — Causalontology *governs* the verbs and *hosts* the nouns, with realizable entities as the hinge between them.

**Causalontology's purest form is a specification, not a program.** It separates the *data structure of causation and its rules* (language-neutral) from any *implementation* (twenty exist, from Prolog to Kotlin/Native). Two familiar pictures, held together:

- **A standard** — like a W3C or IETF specification: a normative document plus a conformance test suite, with independent implementations that all agree because they all pass the same tests.
- **A commons** — like Wikidata, specialized to causation: one shared, world-wide, provenance-first store of causal knowledge that developers everywhere (and autonomous minds) draw from and contribute to.

The reference implementation is [**PrologAI**](https://github.com/ai-university-aiu/PrologAI), a glass-box cognitive architecture, driving the synthetic mind [**Mentova**](https://github.com/ai-university-aiu/Mentova).

## The seventeen kinds of thing

Nine **type-tier content kinds** — pure, immutable, content-addressed (SHA-256 over RFC 8785 canonical bytes):

| Kind | Prefix | What it is |
|---|---|---|
| Occurrent | `occurrent:` | a process or event **type** (a verb), optionally pitched at a `stratum` |
| Causal Relation Object | `causal_relation_object:` | the fundamental unit: a reified causal claim — causes, effects, mechanism, temporal window, modality, context, `refines` lineage, `skips` |
| Continuant | `continuant:` | a thing that endures (a noun) |
| Realizable entity | `realizable:` | a disposition, function, or role — with an identity-bearing `label` |
| Stratum | `stratum:` | a level of description within a named stratification scheme |
| Bridge | `bridge:` | a cross-stratal identity map: one coarse occurrent IS a set of finer ones |
| Port | `port:` | a typed interface borne by a continuant |
| Conduit | `conduit:` | a typed connection from port to port — a pipe, or a computer |
| Quality | `quality:` | a property type a thing can bear |

Four **token-tier content kinds** — immutable, content-addressed, **local by default** (see `spec/safety.md`):

| Kind | Prefix | What it is |
|---|---|---|
| Token Individual | `token_individual:` | a particular thing (THIS one) |
| Token Occurrence | `token_occurrence:` | a particular happening, at absolute time |
| State Assertion | `state_assertion:` | a particular value over a particular interval |
| Token Causal Claim | `token_causal_claim:` | a particular causing, optionally under a covering law |

Four **provenance kinds** — signed (Ed25519), add-only records:

| Kind | Prefix | What it says |
|---|---|---|
| Assertion | `assertion:` | who claims it, on what evidence (intervention > observation > simulation), how strongly, optionally citing token `evidenced_by` |
| Enrichment | `enrichment:` | who added which alias, participant, or taxonomy link — **every word has an author** |
| Retraction | `retraction:` | a source's honest withdrawal of its own record — history never erased |
| Succession | `succession:` | key rotation with lineage |

**The load-bearing decision:** content is separated from provenance, uniformly. The same claim from any number of sources is *one* object; contradictory claims coexist, each with signed provenance; trust is a consumer-chosen policy, never forced consensus. The whole store merges by set union — a CRDT by construction.

## Quickstart (30 seconds)

```json
{ "type": "occurrent", "label": "press_button", "category": "action" }
{ "type": "occurrent", "label": "light_on",     "category": "state_change" }
{ "type": "causal_relation_object", "causes": ["occurrent:press_button"], "effects": ["occurrent:light_on"] }
```

That third document — a *degenerate* causal_relation_object, just cause and effect — is already valid, and the store lists it as a **gap** inviting enrichment (`GET /gaps?kind=missing_field`). Someone (or some mind) later `refines` it with a temporal window and modality, and the gap visibly closes. That is **stigmergy**: the structure's own partiality guides the next contribution. Full walkthrough: [`examples/quickstart.md`](examples/quickstart.md).

## Install (one line, your language)

| Language | Command |
|---|---|
| Python | `pip install causalontology` |
| JavaScript / TypeScript | `npm install causalontology` (typings included) |
| Rust | `cargo add causalontology` |
| Java | `io.github.ai-university-aiu:causalontology:1.0.0` (Maven Central) |
| Kotlin/Native | `io.github.ai-university-aiu:causalontology-kotlin:1.0.2` (Maven Central) |
| C# / .NET | `dotnet add package causalontology` |
| Ruby | `gem install causalontology` |
| PHP | `composer require causalontology/causalontology` |
| Dart | `dart pub add causalontology` |
| Elixir / Erlang | `{:causalontology, "~> 1.0"}` (Hex) |
| Lua | `luarocks install causalontology` |
| Swift | `.package(url: "https://github.com/ai-university-aiu/causalontology", from: "1.0.0")` |
| Go | `go get github.com/ai-university-aiu/causalontology/bindings/go@v1.0.0` |
| Zig | git URL + tag in `build.zig.zon` |

All published at **specification 1.0.0** (vectors frozen 2026-07-13). Reach, stated precisely: **Kotlin, Scala, Clojure, and Groovy** consume the Java artifact from Maven Central as-is; **Deno and Bun** consume the npm package directly; and **any WebAssembly host** (browsers, edge workers, wasmtime embeddings) can use the [WASM core attached to the v1.0.0 release](https://github.com/ai-university-aiu/causalontology/releases/tag/v1.0.0) — so six direct installs serve ten-plus languages in practice. Nine further implementations — **C#, Ruby, PHP, Dart, Elixir, Haskell, Perl, R, and Lua** — are conformant in the repository (registry publications pending the owner's accounts; see PUBLISHING.md). In review or ripening: **Julia** ([General#161292](https://github.com/JuliaRegistries/General/pull/161292), auto-merges in ~3 days if checks pass), **vcpkg** ([#52892](https://github.com/microsoft/vcpkg/pull/52892)) and **Conan** ([#30612](https://github.com/conan-io/conan-center-index/pull/30612)) for C++, plus Hackage (Haskell) and CPAN (Perl) awaiting their registrars, and CRAN (R) deferred to a quiet week — full status in [PUBLISHING.md](PUBLISHING.md). Anything still missing (OCaml, Scala Native, Fortran, COBOL if you dare, ...) remains the open invitation: **the 38 frozen vectors are the gate**. Details and status: [PUBLISHING.md](PUBLISHING.md).

## Repository layout

```
causalontology/
  Causalontology_Standalone_Design_v15.txt   the canon (complete, lay-readable)
  spec/                    normative core, identity, semantics, provenance,
                           store, safety; schema/ = 8 JSON Schemas + JSON-LD
                           context + Protobuf + the OWL mapping (BFO/RO/PROV)
  conformance/             the 107 vectors (specification 2.0.0, whole-word
                           baseline) + the re-freeze tool; the meaning of "correct"
  bindings/                python · javascript (+ TypeScript typings) · rust
                           (+ the WebAssembly core) · java · swift · go —
                           all conformant; PrologAI is the reference
  store/server/            Tier A store (live), SPARQL subset, N-Triples
                           export, reputation, Tier B federation, Tier C
                           offline replication + the test suites
  store/stigmergy/         the contribution dashboard (served at /dashboard)
  examples/                the quickstart + the Mentova gardener (the first
                           synthetic mind contributing to the commons)
  .github/workflows/       8 CI gates: every implementation, every push
  archive/                 superseded editions of versioned documents
  GOVERNANCE.md · PUBLISHING.md · LICENSE · DATA_LICENSE · NOTICE
```

## Conformance

**An implementation is Causalontology-conformant if and only if it passes every vector in [`conformance/vectors/`](conformance/vectors/) for the specification version it declares.** That single rule is how twenty implementations in twenty languages — Prolog, Python, JavaScript, Rust, Java, Swift, Go, C#, Ruby, PHP, Dart, Elixir, Haskell, Perl, R, Lua, C++, Zig, Julia, and Kotlin/Native — agree without sharing a line of code — down to the length of a month (2,629,746 seconds) and the ranking of a `resolve()`.

> **Specification 2.0.0 status (whole-word re-mint).** The suite is now **107
> vectors** (V01–V38 re-frozen unaltered in meaning under the whole-word
> schemes of Principle P7, plus V39–V107 for the nine new object kinds and the
> five normative algorithms). The **Python reference passes all 107 locally**.
> The `38/38` milestones below record the completed 1.0.0 effort; under 2.0.0
> the other bindings carry the whole-word re-mint and their 2.0.0 semantic port
> (nine new kinds, Algorithms A–E) is the open work. Registry republication is
> pending (Section 10.8 / OC1).

## Roadmap — built, proven, and shipped

- [x] Step 1 — publish the specification, schemas, and conformance vectors (this repository)
- [x] Step 2 — [`causalontology-py`](bindings/python/): the second implementation — **38/38 conformance vectors pass**; language independence is proven
- [x] Step 3 — [the Tier A store](store/server/): the HTTP binding is live — signature verification, materialized views, quarantine, retraction/lineage, pagination, auth; **20/20 end-to-end smoke checks pass**
- [x] Step 4 — [the stigmergy layer](store/stigmergy/): all six gap kinds live (including `demand_supply` from real read telemetry), value-ranked `GET /gaps`, and the contribution dashboard at `/dashboard` — **the commons guides its own growth; the MVP is complete**
- [x] Step 5 — the whole beyond-MVP program:
  - [x] [JavaScript SDK](bindings/javascript/) — **the third verified implementation: 38/38 vectors pass locally**, zero dependencies, byte-identical signatures with Python
  - [x] [Java SDK](bindings/java/) — **38/38 vectors pass in CI (JDK 21)** — complete port, JDK standard library only ([workflow](.github/workflows/conformance.yml))
  - [x] [Swift SDK](bindings/swift/) — **38/38 vectors pass in CI (Swift 5.10)** — complete port, swift-crypto for the primitives
  - [x] SPARQL endpoint — `GET|POST /sparql` (documented SELECT subset) + `GET /export/triples` (N-Triples) + the [OWL mapping](spec/schema/causalontology.owl.ttl) to BFO / RO / PROV
  - [x] Federation (Tier B) — `GET /sync/export` + `POST /sync/pull`: two live stores converge by signed set-union; **11/11 checks**
  - [x] Decentralization (Tier C) — [`replicate.py`](store/server/replicate.py): offline bundles, order-independent merge (the CRDT laws proven **8/8**), tamper evidence from content addresses and signatures alone
  - [x] Reputation — `GET /reputation?source=`: glass-box, computed from the signed history, succession-aware
  - [x] **[Mentova gardening the commons](examples/gardener/)** — a glass-box SWI-Prolog mind reads `/gaps`, intervenes (its own hand on the switch), induces the missing fields, signs with Ed25519, contributes, and the gap closes: **11/11 checks — the first synthetic mind gardening the commons**
  - Reserved for a future MAJOR batch, per governance: the token-level (`tok:`) kind and the bounty layer
- [x] Step 6 — the systems tier:
  - [x] [Rust SDK](bindings/rust/) — **the fourth locally-verified implementation: 38/38 vectors pass** (vetted primitives: sha2, ed25519-dalek)
  - [x] [WebAssembly core](bindings/rust/) — the Rust crate compiles unchanged to `wasm32` (schemas embedded, no filesystem); **6/6 cross-checks in Node prove it byte-identical with the JS binding** — one audited core for every host
  - [x] [TypeScript](bindings/javascript/) — hand-written strict typings over the verified JS binding (no logic duplication, no drift); **tsc-verified locally**
  - [x] [Go SDK](bindings/go/) — zero dependencies (Go's standard library carries Ed25519 natively); **verified by the conformance CI** (no local Go toolchain)
  - Contributed implementations welcome — the 38 vectors are the gate (C#, Ruby, PHP, Kotlin, ...)
- [x] Wave two — **C++, Zig, Julia, Kotlin/Native**: four more conformant implementations, ALL verified on the authoring machine (C++ with a hand-built bignum, 361/361 cross-checks; Zig on its standard-library crypto; Julia in pure stdlib; Kotlin/Native hand-building JSON + SHA-2 + bignum + Ed25519 with no stdlib crypto at all, 38/38 on the binary's first run) — **twenty implementations in twenty languages, twenty-one CI gates**
- [x] The nine-language wave — **C#, Ruby, PHP, Dart, Elixir, Haskell, Perl, R, Lua**: nine more conformant implementations in one wave (four verified on the authoring machine — including pure-Lua Ed25519 over a hand-built bignum layer — five gated in CI), taking the standard to **sixteen implementations in sixteen languages**, all passing the same 38 frozen vectors under seventeen CI gates
- [x] The ceremony — **specification 1.0.0**: the [vector freeze](conformance/freeze_1_0_0.py) pinned concrete bytes into all 38 vectors (real identifiers, real keys, a real verifying signature); every manifest bumped to 1.0.0; tagged `v1.0.0` with a GitHub Release carrying the built artifacts; SwiftPM and Go modules live via tags; and the distribution campaign that followed: **thirteen channels live** — PyPI, npm, crates.io, Maven Central (jar + Kotlin klib), NuGet, RubyGems, Hex, LuaRocks, Packagist, pub.dev, SwiftPM, Go, Zig — with Julia, vcpkg, and Conan in community review ([PUBLISHING.md](PUBLISHING.md))

## Governance

Semantic Versioning; the conformance suite versioned in lock-step; **extending any closed enumeration is a MAJOR change**; releases gated in CI on the vectors; an open change process with conformance impact statements. See [`GOVERNANCE.md`](GOVERNANCE.md).

## Contributing

Before the public launch, contributions land through the change process in `GOVERNANCE.md`. The contribution model of the commons itself is stigmergic: ask the store for the most valuable gaps, close one, sign your work. Vocabulary discipline: **resolve before you mint.**

## License

**"The attribution always; no profit, no problem license."** — one license for everything in this repository and its commons: the code, the data, the specification, and the architecture. It is the friendly name for the [Apache License 2.0](LICENSE) text, the same license carried by PrologAI and Mentova: attribution (the [`NOTICE`](NOTICE) file) is always required, and use without profit is never a problem. The data license ([`DATA_LICENSE`](DATA_LICENSE)) carries the same terms, by the owner's decision of 2026-07-13.

## Citation

> D. R. Dison. *Causalontology: AGI's Missing Link* — the Standalone Standard and the Shared Commons, Version 11 (Release Edition), specification 1.0.0. AI University (AIU), 2026. github.com/ai-university-aiu/causalontology

## Author

**D. R. Dison** — Founder of AIU (Artificial Intelligence University), Creator and Owner of PrologAI and Mentova. ORCID [0009-0001-9246-5758](https://orcid.org/0009-0001-9246-5758) · [linkedin.com/in/d-r-dison](https://www.linkedin.com/in/d-r-dison/)

## Related projects

- [**PrologAI**](https://github.com/ai-university-aiu/PrologAI) — the glass-box cognitive architecture; Causalontology's reference implementation (ARC-AGI-1 public training set: 400/400, pure symbolic induction, no LLM)
- [**Mentova**](https://github.com/ai-university-aiu/Mentova) — the first Synthetic Mind written in PrologAI; the flagship mind and, one day, the first synthetic gardener of the commons

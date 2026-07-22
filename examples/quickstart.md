# Quickstart: one claim, four languages, end to end

The full narrative lives in Part 15 of the master document at the repository
root. The JavaScript Object Notation (JSON) documents below are the artifacts of that story. Identifiers
are shown symbolically here for readability; the conformance suite (V01–V137) is frozen at specification 4.0.0.

## Step 1 — Alice (Python) mints vocabulary and imports a bare edge

```json
{ "type": "occurrent", "label": "press_button", "category": "action" }
{ "type": "occurrent", "label": "light_on", "category": "state_change" }
{ "type": "causal_relation_object", "causes": ["occurrent:press_button"], "effects": ["occurrent:light_on"] }
```

Her signed assertion: `evidence_type: imported, confidence: 0.5`.
The store lists the degenerate claim under `GET /gaps?kind=missing_field`.

## Step 2 — Bob (Java) closes the gap with a refinement, and adds an alias

```json
{ "type": "causal_relation_object",
  "causes": ["occurrent:press_button"], "effects": ["occurrent:light_on"],
  "temporal": { "minimum_delay": 0, "maximum_delay": 1, "unit": "seconds" },
  "modality": "sufficient",
  "refines": "causal_relation_object:<Alice's degenerate claim>" }
```

```json
{ "type": "enrichment", "about": "occurrent:press_button", "field": "aliases",
  "entry": { "lang": "ja", "text": "botan wo osu" },
  "source": "ed25519:bob", "timestamp": "2026-07-13T00:00:00Z" }
```

Alice's claim leaves the gap list — the gap visibly closes.

## Step 3 — Mentova (Prolog) adds intervention-grade evidence

One hundred presses; ninety-eight lights within a second. Signed assertion:
`evidence_type: intervention, strength: 0.98, confidence: 0.95`.
Acting beats watching.

## Step 4 — Alice retracts her superseded word

```json
{ "type": "retraction", "retracts": "assertion:<Alice's imported assertion>",
  "source": "ed25519:alice", "timestamp": "2026-07-13T01:00:00Z" }
```

Default views now show Bob's and Mentova's assertions only; history keeps
everything.

## Step 5 — Carol (Swift) consumes with her own trust policy

Fetch claim + assertions + materialized aliases with contributors; verify the
Ed25519 signatures locally; weight intervention over observation; honor
retractions; apply temporal admissibility with the fixed constants — a light
an hour after the press is NOT attributed to the press.

Four languages, no Foreign Function Interface, no shared code — one data
structure, one store, one visible frontier, an honest exit, and an author on
every word.

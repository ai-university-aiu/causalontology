# Stigmergy: gap signals and the contribution dashboard (roadmap step 4 — done)

Stigmergy is coordination through the shared environment: a half-built wall
shows the next worker where the next brick goes. In Causalontology the
store's own partiality IS the signal — and this layer makes it visible.

## The six gap kinds, all live

| Kind | The invitation | Base value |
|---|---|---|
| `conflict` | two claims that formally contradict — bring evidence | 5 |
| `inconsistent_hierarchy` | a mechanism that fails reachability, or a cycle-excluded record — repair | 4 |
| `missing_field` | a partial claim lacking its temporal window or modality — refine it | 3 |
| `demand_supply` | **high demand, weak supply**: a claim read often but unsupported (or supported only by imported / human-hint evidence) — invest here | 3 + demand |
| `dangling_reference` | a reference to an object nobody has defined — the red link | 2 |
| `empty_mechanism` | a relation not yet decomposed — explain HOW | 1 |

`GET /gaps` returns them **value-ranked** (kind weight + live demand), so the
first item is always "the most valuable gap"; `?near=` narrows to a topic,
`?kind=` to one kind. Demand telemetry comes from real reads: object fetches,
assertion lookups, and resolve hits. When intervention-grade evidence lands on
a hot claim, its `demand_supply` gap closes — tested end to end.

## The dashboard

```
python3 store/server/server.py
open http://127.0.0.1:8785/dashboard
```

A single self-contained page (no external assets), served by the store
itself, in the project's warm gold-on-darkred palette: live totals, the
value-ranked gap list with kind ribbons, surfaced conflicts, a near/topic
filter, and five-second auto-refresh. Humans read the same frontier the
machines do.

## Test it

```
python3 store/server/test_stigmergy.py
...
8/8 stigmergy checks passed
Roadmap step 4: the commons guides its own growth.
```

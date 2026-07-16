# causalontology-py

**The second implementation of the Causalontology standard — the proof of
language independence.** (The first is the PrologAI reference implementation.)

Zero dependencies — Python standard library only:

| Module | Implements |
|---|---|
| `causalontology.canonical` | RFC 8785 (JSON Canonicalization Scheme) serialization, identity-bearing field filtering, SHA-256 content-addressed `identify()` |
| `causalontology.ed25519` | pure-Python Ed25519 (RFC 8032), verified against the RFC's known-answer test |
| `causalontology.signing` | record-level `sign_record()` / `verify_record()` over canonical identity-bearing bytes |
| `causalontology.schema` | validation against the eight JSON Schemas in `spec/schema/` |
| `causalontology.semantics` | the 13 semantic rules: temporal admissibility (fixed constants), formal conflict, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `causalontology.store` | an in-memory conformant store: idempotent immutable puts, signed add-only records, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |

## Conformance

```
$ python3 tests/run_conformance.py
...
38/38 vectors passed
causalontology-py is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

## Thirty-second taste

```python
from causalontology import identify, InMemoryStore, keypair_from_seed, sign_record
import hashlib

store = InMemoryStore()
press = store.put({"type": "occurrent", "label": "press_button", "category": "action"})
light = store.put({"type": "occurrent", "label": "light_on", "category": "state_change"})
claim = store.put({"type": "causal_relation_object", "causes": [press], "effects": [light]})

print(store.gaps("missing_field"))   # the degenerate claim is a visible invitation

sk, source = keypair_from_seed(hashlib.sha256(b"alice").digest())
store.put_record(sign_record({"type": "assertion", "about": claim,
                              "source": source, "evidence_type": "imported",
                              "confidence": 0.5,
                              "timestamp": "2026-07-13T00:00:00Z"}, sk))
```

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

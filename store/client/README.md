# The Causalontology light client (Phase four of Part 21)

A client that holds almost nothing and **trusts no server**. It answers queries
by fetching from full or partial nodes over the Hypertext Transfer Protocol
(HTTP) and verifies everything locally: every content object against its own
hash, every provenance record against its own Ed25519 signature. A lying or
corrupted node — or a stale or hostile content-delivery network (CDN) edge — is
caught by the mathematics, not by reputation, so a light client on a phone or in
a browser can consume the commons safely while storing none of it.

See [`light_client.py`](light_client.py). Zero dependencies beyond the Python
standard library and [`causalontology-py`](../../bindings/python/).

## The trustless core

- **Objects self-certify by hash.** The client recomputes the identifier from
  the returned bytes with the standard's own canonicalization
  (`causalontology.identify`) and **rejects** any object whose bytes do not hash
  to the identifier it asked for — the identity rule of
  [`spec/identity.md`](../../spec/identity.md), enforced on the client.
- **Records self-certify by signature.** Every provenance record is checked
  with `causalontology.verify_record` and **rejected** if its Ed25519 signature
  does not verify — [`spec/provenance.md`](../../spec/provenance.md).
- **A stale or hostile cache cannot deceive it.** Because the check is on the
  bytes, it does not matter which node or CDN edge served them; wrong bytes are
  caught and refused.

## Resolving across a sharded network

On a hash-prefix-sharded network no single node holds everything. The client
consults a **shard map** to find which node holds a given identifier, and falls
back to another node on failure. A partial node asked for an identifier outside
its slice answers with a **pointer** (HTTP 421) to a node that does hold it; the
client follows the pointer and then verifies the object itself, so trust never
leaves the client. `discover_shards()` learns who-holds-what from each node's
`GET /shards`.

## Local trust and retraction

The **server decides nothing** about what a light client believes. The client
applies its own `TrustPolicy` (which sources, which evidence grades, which
confidence floor) to the verified records, and re-derives
retraction-and-succession honoring **locally** from the verified record history
rather than trusting a server's filtered view.

## Use it

```python
from light_client import LightClient, TrustPolicy

lc = LightClient(nodes=["http://node-a.example:8785",
                        "http://node-b.example:8785"])
lc.discover_shards()                       # learn each node's coverage

obj = lc.get_object("causal_relation_object:…")   # fetched, verified by hash
rec = lc.get_record("assertion:…")                # fetched, signature verified

# what THIS consumer believes about an object, retraction-honored locally:
strict = LightClient(nodes=[...],
                     trust=TrustPolicy(min_confidence=0.5))
believed = strict.believe_about("causal_relation_object:…")
```

## Test it

```
python3 store/client/test_light_client.py
...
14/14 light-client checks passed
```

The test proves trustless verification (a valid object and record are accepted;
an altered object and a bad-signature record are rejected), that a hostile CDN
cannot deceive the client, cross-shard pointer following, and local
trust-policy and retraction honoring.

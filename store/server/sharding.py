#!/usr/bin/env python3
"""Hash-prefix sharding: a partial node holds a slice of the commons.

Phase four of Part 21 of the canon (Commons Storage and Federation Design):
horizontal scale. Phases one through three gave the commons a durable node,
signed snapshots, and live federation - but every full node still holds
EVERYTHING. This module lets a node hold only a SLICE, selected by the hash
prefix of an identifier, so the network can scale SIDEWAYS: more partial nodes
mean more capacity, not more strain on any one machine.

Why sharding is trivial here
----------------------------
Because identity is a hash (identifier == scheme + ":" + SHA-256 of the
canonical identity-bearing bytes, spec/identity.md), the identifier alone
decides which slice an object belongs to. A shard is just a RULE over the hash
prefix - for example "hold every identifier whose hash begins with the
hexadecimal digits 0 through 3" - so assignment needs NO coordinator, NO
registry of who-holds-what, and NO rebalancing dance: a node changes the
prefixes it declares and it is done. The hash is already uniformly distributed,
so equal prefix widths give equal-sized slices for free.

The three pieces
----------------
  ShardConfig  a node's declared coverage - a set of leading hexadecimal
               nibbles (0-f) of the identifier hash. A FULL node covers all
               sixteen; a partial node covers a subset. covers(identifier)
               is a pure prefix test.

  ShardMap     the advertised coverage of a set of nodes (self plus known
               peers), so a light client or a peer can find WHICH node holds a
               given identifier. nodes_for(identifier) returns every node whose
               shard covers it.

  coverage     the COVERAGE INVARIANT: the union of all shards must cover the
               whole identifier space (all sixteen nibbles). coverage_report()
               surfaces any gap - a nibble no node holds - as a
               misconfiguration an operator must fix. Overlap is fine
               (redundancy); a gap loses data.

The nibble granularity (one hexadecimal digit, sixteen buckets) matches the
canon's worked example exactly and is plenty for a reference network; the same
design extends to wider prefixes unchanged if a deployment ever needs finer
slices.

Zero dependencies beyond the Python standard library.
"""

HEX = "0123456789abcdef"


# ---------------------------------------------------------------------------
# the shard key of an identifier: the leading nibble of its hash
# ---------------------------------------------------------------------------
def shard_key(identifier):
    """The hash hexadecimal of an identifier - everything after the first ':'.

    An identifier is scheme + ':' + hexadecimal SHA-256 digest, so the part
    after the colon is the content hash whose prefix a shard selects on. A
    malformed identifier (no colon, or non-string) yields the empty string and
    is covered by no shard."""
    if not isinstance(identifier, str) or ":" not in identifier:
        return ""
    return identifier.split(":", 1)[1]


def id_nibble(identifier):
    """The single leading hexadecimal nibble that decides an identifier's shard
    (lowercased), or '' for a malformed identifier."""
    key = shard_key(identifier)
    return key[0].lower() if key else ""


# ---------------------------------------------------------------------------
# a node's declared coverage
# ---------------------------------------------------------------------------
class ShardConfig:
    """The slice of the identifier space a node declares it holds: a set of
    leading hexadecimal nibbles. A FULL node covers all sixteen; a partial node
    covers a subset. Coverage is declared by config or environment variable and
    tested with a single prefix comparison - no coordinator is consulted."""

    def __init__(self, nibbles):
        cleaned = {c.lower() for c in nibbles}
        bad = cleaned - set(HEX)
        if bad:
            raise ValueError("not hexadecimal nibbles: %s" % sorted(bad))
        self.nibbles = frozenset(cleaned)

    # ------------------------------------------------------------- construct
    @classmethod
    def full(cls):
        """The full-node coverage: every nibble, the whole identifier space."""
        return cls(set(HEX))

    @classmethod
    def parse(cls, spec):
        """Parse a coverage spec into a ShardConfig.

        Accepted forms (case-insensitive, whitespace ignored):
          '*' / 'all' / 'full'   the whole space (a full node)
          '0-3'                  an inclusive nibble range
          '0-3,c-f'              several ranges and/or singletons, comma-joined
          '5'                    a single nibble
        A range's endpoints are ordered by their position in 0123456789abcdef.
        An empty spec is rejected (it would declare a node that holds nothing
        and silently drops its slice); pass '*' for a full node instead."""
        if spec is None:
            raise ValueError("shard spec is required (use '*' for a full node)")
        s = spec.strip().lower()
        if s in ("*", "all", "full"):
            return cls.full()
        if not s:
            raise ValueError("empty shard spec (use '*' for a full node)")
        out = set()
        for part in s.replace(" ", "").split(","):
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a not in HEX or b not in HEX:
                    raise ValueError("bad nibble range: %r" % part)
                lo, hi = HEX.index(a), HEX.index(b)
                if lo > hi:
                    lo, hi = hi, lo
                out.update(HEX[lo:hi + 1])
            else:
                if part not in HEX:
                    raise ValueError("not a hexadecimal nibble: %r" % part)
                out.add(part)
        if not out:
            raise ValueError("shard spec matched no nibbles: %r" % spec)
        return cls(out)

    # ------------------------------------------------------------- interrogate
    def covers(self, identifier):
        """True iff this shard holds the given identifier (a pure prefix test)."""
        nb = id_nibble(identifier)
        return bool(nb) and nb in self.nibbles

    def is_full(self):
        return self.nibbles == set(HEX)

    def to_spec(self):
        """A compact, canonical spec string ('0-3,c-f'), collapsing runs of
        contiguous nibbles into ranges. Round-trips through parse()."""
        if self.is_full():
            return "*"
        ordered = [h for h in HEX if h in self.nibbles]
        parts, i = [], 0
        while i < len(ordered):
            j = i
            while (j + 1 < len(ordered)
                   and HEX.index(ordered[j + 1]) == HEX.index(ordered[j]) + 1):
                j += 1
            if j == i:
                parts.append(ordered[i])
            elif j == i + 1:
                parts.append(ordered[i])
                parts.append(ordered[j])
            else:
                parts.append("%s-%s" % (ordered[i], ordered[j]))
            i = j + 1
        return ",".join(parts)

    def as_json(self):
        """The advertisable shape of this coverage (for GET /shards)."""
        return {"spec": self.to_spec(),
                "nibbles": [h for h in HEX if h in self.nibbles],
                "full": self.is_full()}

    def __repr__(self):
        return "ShardConfig(%r)" % self.to_spec()

    def __eq__(self, other):
        return isinstance(other, ShardConfig) and self.nibbles == other.nibbles

    def __hash__(self):
        return hash(self.nibbles)


# ---------------------------------------------------------------------------
# the coverage invariant over a set of shards
# ---------------------------------------------------------------------------
def coverage_report(configs):
    """Confirm the COVERAGE INVARIANT over a set of ShardConfigs: the union of
    their nibbles must be the whole space. Returns a report naming any missing
    nibble (a gap - a misconfiguration that loses data) and any nibble held by
    more than one shard (overlap - harmless redundancy). 'complete' is True iff
    every nibble is covered by at least one shard."""
    covered, overlap_count = set(), {}
    for cfg in configs:
        for nb in cfg.nibbles:
            overlap_count[nb] = overlap_count.get(nb, 0) + 1
            covered.add(nb)
    missing = [h for h in HEX if h not in covered]
    overlap = [h for h in HEX if overlap_count.get(h, 0) > 1]
    return {"complete": not missing,
            "covered": [h for h in HEX if h in covered],
            "missing": missing,
            "overlap": overlap}


# ---------------------------------------------------------------------------
# the shard map: who holds what, so any identifier resolves to a node
# ---------------------------------------------------------------------------
class ShardMap:
    """The advertised coverage of a set of nodes, so a light client or a peer
    can find which node holds a given identifier. Entries are (base URL,
    ShardConfig) pairs. The map needs no central registry: each node advertises
    its own coverage over GET /shards, and a client assembles the map from the
    nodes it knows."""

    def __init__(self, entries=None):
        self._entries = {}
        for url, cfg in (entries or []):
            self.add(url, cfg)

    def add(self, url, config):
        """Record (or update) a node's coverage. config may be a ShardConfig or
        a spec string."""
        if isinstance(config, str):
            config = ShardConfig.parse(config)
        self._entries[url.rstrip("/")] = config
        return self

    def remove(self, url):
        self._entries.pop(url.rstrip("/"), None)
        return self

    def nodes(self):
        return dict(self._entries)

    def nodes_for(self, identifier):
        """Every node whose shard covers the identifier, in a stable order.
        Overlap means more than one; a returned list of length zero means a
        coverage gap - no known node holds this identifier's slice."""
        return sorted(url for url, cfg in self._entries.items()
                      if cfg.covers(identifier))

    def coverage(self):
        """The coverage invariant across every node in the map."""
        return coverage_report(self._entries.values())

    def as_json(self):
        return {"nodes": [{"url": url, "shard": cfg.as_json()}
                          for url, cfg in sorted(self._entries.items())],
                "coverage": self.coverage()}

    @classmethod
    def from_json(cls, doc):
        """Rebuild a ShardMap from a /shards advertisement or an as_json() doc.
        Accepts both the map shape ({'nodes': [...]}) and a single node's
        self-advertisement ({'node': url, 'shard': {...}})."""
        m = cls()
        if isinstance(doc, dict) and "nodes" in doc:
            for entry in doc["nodes"]:
                m.add(entry["url"], entry["shard"]["spec"])
        if isinstance(doc, dict) and doc.get("node") and doc.get("shard"):
            m.add(doc["node"], doc["shard"]["spec"])
        return m

    def __len__(self):
        return len(self._entries)

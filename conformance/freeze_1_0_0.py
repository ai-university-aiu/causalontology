#!/usr/bin/env python3
"""The 1.0.0 vector freeze.

Replaces every pre-freeze symbolic identifier in conformance/vectors/ with
the concrete bytes the harnesses have always derived deterministically:

- "scheme:name"        -> "scheme:" + SHA-256(name)          (well-formed ids)
- "ed25519:name"       -> the real public key of the keypair seeded from
                          SHA-256("key:" + name)             (real keys)
- "<128 hex>"          -> the record's REAL Ed25519 signature, computed with
                          that key over the canonical identity-bearing bytes
                          (the frozen record verifies for real)

Identity vectors (V24-V26 territory) exercise true content addressing at run
time and carry no ids to freeze. Validity vectors keep uniformly-mapped
well-formed ids so deliberate self-references (V15, V16) stay intact - a
genuinely content-addressed object cannot contain its own hash, which is
exactly why the rule exists.

Idempotent: already-frozen values (64/128 hex) pass through unchanged.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "bindings" / "python"))

from causalontology import keypair_from_seed, sign_record  # noqa: E402

SCHEMES = ("occ", "cro", "cnt", "rlz", "ast", "enr", "ret", "suc")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def key(name):
    seed = hashlib.sha256(("key:" + name).encode()).digest()
    return keypair_from_seed(seed)


def freeze_string(s):
    if s == "<128 hex>":
        return s  # handled at the record level (a real signature)
    if ":" not in s:
        return s
    scheme, name = s.split(":", 1)
    if scheme == "ed25519":
        return s if HEX64.match(name) else key(name)[1]
    if scheme in SCHEMES:
        return s if HEX64.match(name) else \
            scheme + ":" + hashlib.sha256(name.encode()).hexdigest()
    return s


def freeze_value(v):
    if isinstance(v, str):
        return freeze_string(v)
    if isinstance(v, list):
        return [freeze_value(x) for x in v]
    if isinstance(v, dict):
        return {k: freeze_value(x) for k, x in v.items()}
    return v


def pin_real_signature(record):
    """Replace the '<128 hex>' placeholder with the record's real signature."""
    source = record.get("source", "")
    who = None
    # the freeze derives keys from names; recover the seed name by matching
    # the already-frozen key against the known pre-freeze names
    for name in ("ab12", "alice", "bob", "lab1", "lab2", "K1", "K2",
                 "mallory", "signer", "taxo"):
        if key(name)[1] == source:
            who = name
            break
    if who is None:
        raise SystemExit("cannot recover the signing seed for %s" % source)
    secret, _ = key(who)
    body = {k: v for k, v in record.items() if k not in ("signature",)}
    signed = sign_record(body, secret)
    record["signature"] = signed["signature"]
    return record


def main():
    frozen = 0
    for path in sorted((HERE / "vectors").glob("v*.json")):
        vec = json.loads(path.read_text())
        before = json.dumps(vec)
        vec = freeze_value(vec)
        for section in ("input", "given"):
            node = vec.get(section)
            if isinstance(node, dict) and node.get("signature") == "<128 hex>":
                pin_real_signature(node)
        after = json.dumps(vec)
        if before != after:
            frozen += 1
            path.write_text(json.dumps(vec, indent=2) + "\n")
    print("frozen: %d vector files rewritten with concrete bytes" % frozen)
    print("the suite is now specification 1.0.0")


if __name__ == "__main__":
    main()

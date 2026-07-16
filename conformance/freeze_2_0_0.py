#!/usr/bin/env python3
"""The 2.0.0 vector re-freeze (the single, coordinated whole-word re-mint).

Principle P7 replaces every three-letter identifier scheme of the originally
published 1.0.0 line with the whole English word it stood for, in ONE
coordinated re-mint of both lines. This script performs that re-mint over
conformance/vectors/ and re-pins any real signatures, idempotently:

  scheme:X    ->  whole_word:X        (occ -> occurrent, cro ->
                  causal_relation_object, and the rest of the seventeen-scheme
                  mapping; ed25519 and other external proper names untouched)
  "type":"cro"->  "type":"causal_relation_object"
  dmin/dmax   ->  minimum_delay/maximum_delay   (the two field renames)
  "<128 hex>" ->  a real Ed25519 signature over the record's canonical bytes

Whole tokens only: a scheme is re-minted only where it is the text before the
colon of an identifier, or the exact "type"/reference value. Ordinary words in
prose (across, macro, instrument) are never touched.

Idempotent: a second run changes nothing. After this single re-freeze the
whole-word forms are the immutable 2.0.0 baseline.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "bindings" / "python"))

from causalontology import keypair_from_seed, sign_record  # noqa: E402

# The whole-word re-mint. Old three-letter scheme -> whole English word.
REMINT = {
    "occ": "occurrent",
    "cro": "causal_relation_object",
    "cnt": "continuant",
    "rlz": "realizable",
    "ast": "assertion",
    "enr": "enrichment",
    "ret": "retraction",
    "suc": "succession",
    # the nine 2.0.0 schemes are already whole words and need no re-mint,
    # but are listed so a stray abbreviation would be caught if introduced:
    "str": "stratum", "brg": "bridge", "prt": "port", "cdt": "conduit",
    "qal": "quality", "tid": "token_individual", "tok": "token_occurrence",
    "stt": "state_assertion", "tcr": "token_causal_claim",
}
FIELD_RENAME = {"dmin": "minimum_delay", "dmax": "maximum_delay"}
OLD_SCHEMES = tuple(REMINT)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def key(name):
    seed = hashlib.sha256(("key:" + name).encode()).digest()
    return keypair_from_seed(seed)


def remint_string(s):
    """Re-mint an identifier string's scheme; leave everything else alone."""
    if ":" not in s:
        # a bare type value like "cro"
        return REMINT.get(s, s)
    scheme, name = s.split(":", 1)
    if scheme in REMINT:
        return REMINT[scheme] + ":" + name
    return s


def remint_value(v):
    if isinstance(v, str):
        return remint_string(v)
    if isinstance(v, list):
        return [remint_value(x) for x in v]
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            k2 = FIELD_RENAME.get(k, k)
            out[k2] = remint_value(x)
        return out
    return v


def pin_real_signature(record):
    """Replace a '<128 hex>' placeholder (or a signature stale after re-mint)
    with the record's real Ed25519 signature over its new canonical bytes."""
    source = record.get("source", "")
    who = None
    for name in ("ab12", "alice", "bob", "lab1", "lab2", "K1", "K2",
                 "mallory", "signer", "taxo"):
        if key(name)[1] == source:
            who = name
            break
    if who is None:
        return record  # not a harness-seeded key; leave as-is
    secret, _ = key(who)
    body = {k: v for k, v in record.items() if k != "signature"}
    signed = sign_record(body, secret)
    record["signature"] = signed["signature"]
    record["id"] = signed["id"]
    return record


def main():
    frozen = 0
    for path in sorted((HERE / "vectors").glob("v*.json")):
        vec = json.loads(path.read_text())
        before = json.dumps(vec, sort_keys=True)
        vec = remint_value(vec)
        for section in ("input", "given"):
            node = vec.get(section)
            if isinstance(node, dict) and node.get("signature") == "<128 hex>":
                pin_real_signature(node)
        after = json.dumps(vec, sort_keys=True)
        if before != after:
            frozen += 1
            path.write_text(json.dumps(vec, indent=2) + "\n")
    print("re-frozen: %d vector files re-minted to whole-word schemes" % frozen)
    print("the suite is now specification 2.0.0 (whole-word baseline)")


if __name__ == "__main__":
    main()

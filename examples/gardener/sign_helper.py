#!/usr/bin/env python3
"""Ed25519 signing helper for the gardener.

Reads an unsigned record (JSON) on stdin, signs it with the deterministic
key seeded from sha256(argv[1]), sets the source field, and writes the
signed record (JSON) to stdout. The gardener reasons in Prolog; the byte
plumbing reuses the reference SDK - glass-box composition.
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "bindings" / "python"))

from causalontology import keypair_from_seed, sign_record  # noqa: E402


def main():
    seed_name = sys.argv[1] if len(sys.argv) > 1 else "mentova"
    secret, source = keypair_from_seed(
        hashlib.sha256(seed_name.encode()).digest())
    record = json.load(sys.stdin)
    record["source"] = source
    json.dump(sign_record(record, secret), sys.stdout)


if __name__ == "__main__":
    main()

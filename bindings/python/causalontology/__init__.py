"""causalontology - the Python binding of the Causalontology standard.

The second implementation (after the PrologAI reference), proving language
independence: standard library only, conformant when it passes every vector
in conformance/vectors/ (run tests/run_conformance.py).

Causalontology is a verb-first noun-hosting ontology: reality is what
happens, and things are its participants.
"""

__version__ = "1.0.0"  # specification 1.0.0 (vectors frozen 2026-07-13)

from .canonical import canonicalize, identify, identity_bearing, infer_kind
from .schema import validate_schema
from .semantics import (validate_semantics, is_partial, admissible,
                        conflicts, refinement_valid, hierarchy_consistent,
                        UNIT_SECONDS)
from .signing import keypair_from_seed, sign_record, verify_record
from .store import InMemoryStore, RejectedWrite

__all__ = [
    "canonicalize", "identify", "identity_bearing", "infer_kind",
    "validate_schema", "validate_semantics", "is_partial", "admissible",
    "conflicts", "refinement_valid", "hierarchy_consistent", "UNIT_SECONDS",
    "keypair_from_seed", "sign_record", "verify_record",
    "InMemoryStore", "RejectedWrite", "__version__",
]

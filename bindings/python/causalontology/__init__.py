"""causalontology - the Python binding of the Causalontology standard.

The second implementation (after the PrologAI reference), proving language
independence: standard library only, conformant when it passes every vector
in conformance/vectors/ (run tests/run_conformance.py).

Causalontology is a verb-first noun-hosting ontology: reality is what
happens, and things are its participants.
"""

__version__ = "4.0.0"  # specification 4.0.0 (attitude, predicted_occurrence, prediction_error)

from .canonical import canonicalize, identify, identity_bearing, infer_kind
from .schema import validate_schema
from .semantics import (validate_semantics, is_partial, admissible,
                        conflicts, refinement_valid, hierarchy_consistent,
                        UNIT_SECONDS, ORDINAL_UNITS,
                        # 2.0.0 normative algorithms and rules
                        bridge_closure, classify_cro, endpoints_mixed,
                        skip_gaps, to_seconds, delay_within_window,
                        bridge_wellformed, conduit_wellformed, state_gaps,
                        covering_law_mismatch, retrocausal, has_cycle,
                        # 3.0.0 additions
                        seam_wellformed, seam_home,
                        # 4.0.0 additions
                        prediction_pairing_mismatch)
from .signing import keypair_from_seed, sign_record, verify_record
from .store import InMemoryStore, RejectedWrite

__all__ = [
    "canonicalize", "identify", "identity_bearing", "infer_kind",
    "validate_schema", "validate_semantics", "is_partial", "admissible",
    "conflicts", "refinement_valid", "hierarchy_consistent", "UNIT_SECONDS",
    "ORDINAL_UNITS",
    "bridge_closure", "classify_cro", "endpoints_mixed", "skip_gaps",
    "to_seconds", "delay_within_window", "bridge_wellformed",
    "conduit_wellformed", "state_gaps", "covering_law_mismatch",
    "retrocausal", "has_cycle", "seam_wellformed", "seam_home",
    "prediction_pairing_mismatch",
    "keypair_from_seed", "sign_record", "verify_record",
    "InMemoryStore", "RejectedWrite", "__version__",
]

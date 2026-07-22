"""Canonicalization and content-addressed identity.

Implements the identity procedure of spec/identity.md:
  1. take the object as JSON,
  2. keep only the identity-bearing fields for its kind (with "type" injected),
  3. serialize with the JSON Canonicalization Scheme (RFC 8785),
  4. hash with SHA-256,
  5. identifier = scheme + ":" + lowercase hex digest.

2.0.0: every identifier scheme is a whole English word (Principle P7); the
scheme, the type value, and the id prefix are one and the same string. The
number serialization implements the RFC 8785 rules for the value ranges
Causalontology uses (integers, integer-valued floats, and short decimals);
full ECMAScript exponent formatting for extreme magnitudes is pinned at the
2.0.0 conformance freeze.
"""

import hashlib
import math

# The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds the
# cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the attitude,
# the predicted_occurrence, and the prediction_error - all additive and
# identity-preserving - a record that omits a new field keeps its earlier
# identifier byte-for-byte, and the new kinds open new identity schemes that
# disturb no existing record). "type" is always injected, so it is not listed
# here. Order does not matter (JCS sorts keys).
IDENTITY_FIELDS = {
    # ---- type tier ----
    "occurrent":  ["label", "category", "stratum"],
    "causal_relation_object": ["causes", "effects", "mechanism", "temporal",
                               "modality", "context", "refines", "skips"],
    "continuant": ["label", "category"],
    "realizable": ["kind", "bearer", "label"],
    "stratum":    ["label", "scheme", "ordinal", "unit", "governs"],
    "bridge":     ["coarse", "fine", "relation"],
    "cross_stratal_seam": ["source", "target", "mechanism_status", "chain"],
    "port":       ["bearer", "label", "direction", "accepts", "realizable"],
    "conduit":    ["label", "from", "to", "carries", "transform", "realized_by"],
    "quality":    ["label", "datatype", "unit", "stratum"],
    # ---- token tier ----
    "token_individual":   ["instantiates", "designator", "part_of"],
    "token_occurrence":   ["instantiates", "interval", "participants",
                           "locus", "observer"],
    "state_assertion":    ["subject", "quality", "value", "interval"],
    "token_causal_claim": ["causes", "effects", "covering_law",
                           "actual_delay", "counterfactual"],
    "attitude":             ["holder", "attitude_type", "content"],
    "predicted_occurrence": ["instantiates", "interval", "predictor",
                             "strength"],
    "prediction_error":     ["predicted", "observed", "discrepancy"],
    # ---- provenance tier ----
    "assertion":  ["about", "source", "evidence_type", "evidence", "strength",
                   "confidence", "timestamp", "evidenced_by"],
    "enrichment": ["about", "field", "entry", "source", "timestamp"],
    "retraction": ["retracts", "source", "timestamp"],
    "succession": ["predecessor", "successor", "timestamp"],
}

# Whole-word re-mint (P7): the scheme IS the type value for every kind.
PREFIX = {k: k for k in IDENTITY_FIELDS}
KIND_OF_PREFIX = {v: k for k, v in PREFIX.items()}


def infer_kind(obj):
    """Infer an object's kind from its type field, id prefix, or shape."""
    if "type" in obj:
        return obj["type"]
    if "id" in obj and isinstance(obj["id"], str) and ":" in obj["id"]:
        pre = obj["id"].split(":", 1)[0]
        if pre in KIND_OF_PREFIX:
            return KIND_OF_PREFIX[pre]
    if "coarse" in obj and "fine" in obj:
        return "bridge"
    if "causes" in obj and "effects" in obj:
        return "causal_relation_object"
    if "retracts" in obj:
        return "retraction"
    if "predecessor" in obj and "successor" in obj:
        return "succession"
    if "field" in obj and "entry" in obj:
        return "enrichment"
    if "evidence_type" in obj or ("about" in obj and "confidence" in obj):
        return "assertion"
    if "kind" in obj and "bearer" in obj:
        return "realizable"
    raise ValueError(
        "cannot infer kind (occurrents and continuants share a shape); "
        "pass kind= explicitly")


def identity_bearing(obj, kind=None):
    """The identity-bearing subset of an object, with type always present."""
    kind = kind or infer_kind(obj)
    if kind not in IDENTITY_FIELDS:
        raise ValueError("unknown kind: %r" % (kind,))
    out = {"type": kind}
    for field in IDENTITY_FIELDS[kind]:
        if field in obj:
            out[field] = obj[field]
    return kind, out


# ---------------------------------------------------------------------------
# RFC 8785 (JSON Canonicalization Scheme) serialization
# ---------------------------------------------------------------------------

_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t",
    "\n": "\\n", "\f": "\\f", "\r": "\\r",
}


def _jcs_string(s):
    parts = ['"']
    for ch in s:
        if ch in _ESCAPES:
            parts.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            parts.append("\\u%04x" % ord(ch))
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _jcs_number(n):
    if isinstance(n, bool):  # bool is an int subclass; handle first
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    if not math.isfinite(n):
        raise ValueError("NaN and Infinity are not permitted (RFC 8785)")
    if n == 0:
        return "0"
    if float(n).is_integer() and abs(n) < 1e21:
        return str(int(n))
    r = repr(float(n))  # shortest round-trip decimal (matches ES6 for our range)
    if "e" in r:  # normalize exponent: 1e-07 -> 1e-7, keep e+NN as ES6 does
        mant, exp = r.split("e")
        sign = "-" if exp.startswith("-") else "+"
        digits = exp.lstrip("+-").lstrip("0") or "0"
        r = mant + "e" + (sign if sign == "-" else "+") + digits
    return r


def _jcs(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: [ord(c) for c in kv[0]])
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v)
                              for k, v in items) + "}"
    raise TypeError("cannot canonicalize %r" % type(value))


def canonicalize(obj, kind=None):
    """The RFC 8785 identity-bearing bytes of an object."""
    _, ib = identity_bearing(obj, kind)
    return _jcs(ib).encode("utf-8")


def identify(obj, kind=None):
    """The content-addressed identifier: scheme + ':' + SHA-256 hex."""
    kind, ib = identity_bearing(obj, kind)
    digest = hashlib.sha256(_jcs(ib).encode("utf-8")).hexdigest()
    return PREFIX[kind] + ":" + digest

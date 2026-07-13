"""Record-level signing and verification (spec/provenance.md).

The signature is computed over the record's canonical identity-bearing bytes
(the RFC 8785 form with id and signature removed - exactly the bytes that are
hashed for the record's identifier), so verification needs nothing but the
record itself. Ed25519 is deterministic (RFC 8032): re-signing the same record
with the same key yields the same signature, so re-submission is idempotent.
"""

from . import ed25519
from .canonical import canonicalize, identify, infer_kind


def keypair_from_seed(seed32):
    """(secret, 'ed25519:<hex>') from a 32-byte seed."""
    public = ed25519.secret_to_public(seed32)
    return seed32, "ed25519:" + public.hex()


def sign_record(record, secret, kind=None):
    """Return the record completed with its id and Ed25519 signature."""
    kind = kind or infer_kind(record)
    body = dict(record)
    body.pop("signature", None)
    message = canonicalize(body, kind)
    signature = ed25519.sign(secret, message).hex()
    out = dict(body)
    out["id"] = identify(body, kind)
    out["signature"] = signature
    return out


def _signer_key_hex(record, kind):
    if kind == "succession":
        field = "predecessor"  # a succession is signed by the predecessor key
    else:
        field = "source"
    value = record.get(field, "")
    if not value.startswith("ed25519:"):
        return None
    return value.split(":", 1)[1]


def verify_record(record, kind=None):
    """True iff the record's signature verifies against its own key field."""
    kind = kind or infer_kind(record)
    sig_hex = record.get("signature")
    key_hex = _signer_key_hex(record, kind)
    if not sig_hex or not key_hex:
        return False
    try:
        public = bytes.fromhex(key_hex)
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    body = dict(record)
    body.pop("signature", None)
    message = canonicalize(body, kind)
    return ed25519.verify(public, message, signature)

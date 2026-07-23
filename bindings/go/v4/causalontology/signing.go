// Record-level signing and verification (spec/provenance.md).
//
// The signature is computed over the record's canonical identity-bearing
// bytes (the RFC 8785 form with id and signature removed - exactly the
// bytes that are hashed for the record's identifier), so verification
// needs nothing but the record itself. Ed25519 is deterministic (RFC
// 8032): re-signing the same record with the same key yields the same
// signature, so re-submission is idempotent. The Go standard library
// carries Ed25519 natively in crypto/ed25519.
package causalontology

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
)

// KeypairFromSeed derives (secret, "ed25519:<hex public key>") from a
// 32-byte seed, per RFC 8032 (crypto/ed25519's NewKeyFromSeed).
func KeypairFromSeed(seed []byte) (ed25519.PrivateKey, string) {
	secret := ed25519.NewKeyFromSeed(seed)
	public := secret.Public().(ed25519.PublicKey)
	return secret, "ed25519:" + hex.EncodeToString(public)
}

// SignRecord returns the record completed with its id and Ed25519
// signature. An empty kind means: infer it.
func SignRecord(record map[string]any, secret ed25519.PrivateKey, kind string) (map[string]any, error) {
	if kind == "" {
		inferred, err := InferKind(record)
		if err != nil {
			return nil, err
		}
		kind = inferred
	}
	body := CopyMap(record)
	delete(body, "signature")
	message, err := Canonicalize(body, kind)
	if err != nil {
		return nil, err
	}
	id, err := Identify(body, kind)
	if err != nil {
		return nil, err
	}
	out := CopyMap(body)
	out["id"] = id
	out["signature"] = hex.EncodeToString(ed25519.Sign(secret, message))
	return out, nil
}

// signerKeyHex extracts the hex public key the record must verify
// against: the "source" field, except that a succession is signed by its
// "predecessor" key.
func signerKeyHex(record map[string]any, kind string) string {
	field := "source"
	if kind == "succession" {
		field = "predecessor"
	}
	value, _ := record[field].(string)
	if !strings.HasPrefix(value, "ed25519:") {
		return ""
	}
	return strings.TrimPrefix(value, "ed25519:")
}

// VerifyRecord reports whether the record's signature verifies against
// its own key field. Malformed hex, missing fields, or a wrongly sized
// key all yield false rather than an error.
func VerifyRecord(record map[string]any, kind string) bool {
	if kind == "" {
		inferred, err := InferKind(record)
		if err != nil {
			return false
		}
		kind = inferred
	}
	signatureHex, _ := record["signature"].(string)
	keyHex := signerKeyHex(record, kind)
	if signatureHex == "" || keyHex == "" {
		return false
	}
	public, err := hex.DecodeString(keyHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	body := CopyMap(record)
	delete(body, "signature")
	message, err := Canonicalize(body, kind)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(public), message, signature)
}

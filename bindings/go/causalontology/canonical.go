// Canonicalization and content-addressed identity.
//
// Implements the identity procedure of spec/identity.md:
//  1. take the object as JSON,
//  2. keep only the identity-bearing fields for its kind (with "type"
//     injected),
//  3. serialize with the JSON Canonicalization Scheme (RFC 8785),
//  4. hash with SHA-256,
//  5. identifier = scheme + ":" + lowercase hex digest.
package causalontology

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// IdentityFields lists, per kind, exactly the fields that participate in
// the identity hash; everything else (id, signature, annotations) is
// excluded by construction. 2.0.0: all seventeen whole-word kinds.
var IdentityFields = map[string][]string{
	// ---- type tier ----
	"occurrent": {"label", "category", "stratum"},
	"causal_relation_object": {"causes", "effects", "mechanism", "temporal",
		"modality", "context", "refines", "skips"},
	"continuant": {"label", "category"},
	"realizable": {"kind", "bearer", "label"},
	"stratum":    {"label", "scheme", "ordinal", "unit", "governs"},
	"bridge":     {"coarse", "fine", "relation"},
	"port":       {"bearer", "label", "direction", "accepts", "realizable"},
	"conduit":    {"label", "from", "to", "carries", "transform"},
	"quality":    {"label", "datatype", "unit", "stratum"},
	// ---- token tier ----
	"token_individual":   {"instantiates", "designator", "part_of"},
	"token_occurrence":   {"instantiates", "interval", "participants", "locus", "observer"},
	"state_assertion":    {"subject", "quality", "value", "interval"},
	"token_causal_claim": {"causes", "effects", "covering_law", "actual_delay", "counterfactual"},
	// ---- provenance tier ----
	"assertion":  {"about", "source", "evidence_type", "evidence", "strength", "confidence", "timestamp", "evidenced_by"},
	"enrichment": {"about", "field", "entry", "source", "timestamp"},
	"retraction": {"retracts", "source", "timestamp"},
	"succession": {"predecessor", "successor", "timestamp"},
}

// Prefix maps each kind to its identifier scheme; whole-word (P7): the
// scheme IS the kind string.
var Prefix = func() map[string]string {
	out := map[string]string{}
	for kind := range IdentityFields {
		out[kind] = kind
	}
	return out
}()

// KindOfPrefix is the inverse of Prefix: identifier scheme to kind.
var KindOfPrefix = func() map[string]string {
	out := map[string]string{}
	for kind := range IdentityFields {
		out[kind] = kind
	}
	return out
}()

// InferKind infers an object's kind from its type field, id prefix, or
// shape, exactly as the Python binding does.
func InferKind(obj map[string]any) (string, error) {
	if raw, present := obj["type"]; present {
		if kind, ok := raw.(string); ok {
			return kind, nil
		}
	}
	if id, ok := obj["id"].(string); ok {
		if colon := strings.IndexByte(id, ':'); colon >= 0 {
			if kind, known := KindOfPrefix[id[:colon]]; known {
				return kind, nil
			}
		}
	}
	has := func(field string) bool {
		_, present := obj[field]
		return present
	}
	if has("coarse") && has("fine") {
		return "bridge", nil
	}
	if has("causes") && has("effects") {
		return "causal_relation_object", nil
	}
	if has("retracts") {
		return "retraction", nil
	}
	if has("predecessor") && has("successor") {
		return "succession", nil
	}
	if has("field") && has("entry") {
		return "enrichment", nil
	}
	if has("evidence_type") || (has("about") && has("confidence")) {
		return "assertion", nil
	}
	if has("kind") && has("bearer") {
		return "realizable", nil
	}
	return "", errors.New(
		"cannot infer kind (occurrents and continuants share a shape); pass kind explicitly")
}

// IdentityBearing returns the identity-bearing subset of an object, with
// "type" always present. An empty kind means: infer it.
func IdentityBearing(obj map[string]any, kind string) (string, map[string]any, error) {
	if kind == "" {
		inferred, err := InferKind(obj)
		if err != nil {
			return "", nil, err
		}
		kind = inferred
	}
	fields, known := IdentityFields[kind]
	if !known {
		return "", nil, fmt.Errorf("unknown kind: %q", kind)
	}
	out := map[string]any{"type": kind}
	for _, field := range fields {
		if value, present := obj[field]; present {
			out[field] = value
		}
	}
	return kind, out, nil
}

// Canonicalize returns the RFC 8785 identity-bearing bytes of an object.
func Canonicalize(obj map[string]any, kind string) ([]byte, error) {
	_, bearing, err := IdentityBearing(obj, kind)
	if err != nil {
		return nil, err
	}
	canonical, err := SerializeJCS(bearing)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

// Identify returns the content-addressed identifier:
// scheme + ":" + SHA-256 hex of the canonical identity-bearing bytes.
func Identify(obj map[string]any, kind string) (string, error) {
	resolvedKind, bearing, err := IdentityBearing(obj, kind)
	if err != nil {
		return "", err
	}
	canonical, err := SerializeJCS(bearing)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(canonical))
	return Prefix[resolvedKind] + ":" + hex.EncodeToString(digest[:]), nil
}

// Package causalontology is the Go binding of the Causalontology standard:
// canonicalization and content-addressed identity (spec/identity.md),
// record-level Ed25519 signing (spec/provenance.md), schema validation
// against spec/schema/*.schema.json, the 13 semantic rules
// (spec/semantics.md), and an in-memory conformant store (spec/store.md).
// It is a faithful port of the Python reference binding, causalontology-py,
// and passes the same 38-vector conformance suite.
//
// This file is the lossless JSON layer. Everything is decoded with
// json.Decoder.UseNumber(), so every number arrives as a json.Number that
// preserves its source literal. The integer-versus-decimal distinction of
// the literal ("1" versus "1.0") survives into canonicalization, where RFC
// 8785 collapses it deterministically ("1" and "1.0" both serialize as "1",
// while "0.7" stays "0.7").
package causalontology

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
)

// DecodeJSON parses JSON bytes into the value model used throughout this
// binding: map[string]any, []any, string, json.Number, bool, and nil.
func DecodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// DecodeJSONFile reads and parses one JSON file with DecodeJSON.
func DecodeJSONFile(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeJSON(data)
}

// IsIntegerNumber reports whether a json.Number came from an integer
// literal: one containing no decimal point and no exponent marker.
func IsIntegerNumber(n json.Number) bool {
	return !strings.ContainsAny(n.String(), ".eE")
}

// AsFloat converts any of the numeric value forms this binding handles
// (json.Number, int, int64, float64) to a float64. A json.Number integer 1
// and a float 1.0 are semantically the same number here, exactly as they
// are in the Python binding.
func AsFloat(value any) (float64, bool) {
	switch n := value.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// CopyMap returns a shallow copy of a JSON object, the equivalent of
// Python's dict(obj). A nil input yields an empty, writable map.
func CopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for key, value := range m {
		out[key] = value
	}
	return out
}

// stringList extracts the string members of a JSON array value; a non-array
// (including nil) yields nil, mirroring Python's obj.get(field, []).
func stringList(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, isString := item.(string); isString {
			out = append(out, text)
		}
	}
	return out
}

// Command conformance is the Causalontology conformance runner for
// causalontology-go.
//
// It runs every vector in conformance/vectors/ against the Go binding. An
// implementation is conformant if and only if it passes every vector;
// this runner exits nonzero on any failure.
//
// Pre-freeze note (see conformance/README.md): the vectors carry symbolic
// identifiers ("occ:press_button", "ed25519:alice"). This harness
// normalizes them deterministically - symbolic object ids become
// scheme:sha256(name), and symbolic key names become real Ed25519
// keypairs seeded from sha256("key:" + name) - so the normative behaviors
// are tested with well-formed data. The 1.0.0 freeze pins concrete bytes
// into the vectors themselves.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	co "github.com/ai-university-aiu/causalontology/bindings/go/causalontology"
)

// vectorsDir is the conformance/vectors directory, set by main.
var vectorsDir string

// symbolicPrefix recognizes the identifier schemes the vectors use.
var symbolicPrefix = regexp.MustCompile(`^(occ|cro|cnt|rlz|ast|enr|ret|suc|ed25519):`)

// hex64 recognizes an already-normalized 64-character lowercase hex name.
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// keyPair pairs an Ed25519 secret with its "ed25519:<hex>" public id.
type keyPair struct {
	secret ed25519.PrivateKey
	public string
}

// keyCache holds one deterministic keypair per symbolic key name.
var keyCache = map[string]keyPair{}

// key returns a real, deterministic Ed25519 keypair for a symbolic key
// name, seeded from sha256("key:" + name).
func key(name string) keyPair {
	if cached, ok := keyCache[name]; ok {
		return cached
	}
	seed := sha256.Sum256([]byte("key:" + name))
	secret, public := co.KeypairFromSeed(seed[:])
	pair := keyPair{secret, public}
	keyCache[name] = pair
	return pair
}

// sym normalizes one symbolic identifier to a well-formed one.
func sym(s string) string {
	scheme, name, found := strings.Cut(s, ":")
	if !found {
		return s
	}
	if scheme == "ed25519" {
		if hex64.MatchString(name) {
			return s // frozen: a real key passes through
		}
		return key(name).public
	}
	if hex64.MatchString(name) {
		return s
	}
	digest := sha256.Sum256([]byte(name))
	return scheme + ":" + hex.EncodeToString(digest[:])
}

// normalize recursively normalizes symbolic identifiers and placeholders.
func normalize(value any) any {
	switch v := value.(type) {
	case string:
		if v == "<128 hex>" {
			return strings.Repeat("ab", 64)
		}
		if symbolicPrefix.MatchString(v) {
			return sym(v)
		}
		return v
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = normalize(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = normalize(item)
		}
		return out
	}
	return value
}

// findRepoRoot locates the repository root: the CAUSALONTOLOGY_ROOT
// environment variable when set, otherwise a walk up from the working
// directory looking for conformance/vectors.
func findRepoRoot() (string, error) {
	if root := os.Getenv("CAUSALONTOLOGY_ROOT"); root != "" {
		return root, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, "conformance", "vectors")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New(
		"no conformance/vectors above the working directory; set CAUSALONTOLOGY_ROOT")
}

// vec loads vector n's JSON file (for its structured inputs).
func vec(n int) (map[string]any, error) {
	pattern := filepath.Join(vectorsDir, fmt.Sprintf("v%02d_*.json", n))
	hits, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(hits) != 1 {
		return nil, fmt.Errorf("vector %d not found", n)
	}
	value, err := co.DecodeJSONFile(hits[0])
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vector %d is not a JSON object", n)
	}
	return obj, nil
}

// vectorName returns the vector's display name (its file stem).
func vectorName(n int) string {
	pattern := filepath.Join(vectorsDir, fmt.Sprintf("v%02d_*.json", n))
	hits, err := filepath.Glob(pattern)
	if err != nil || len(hits) != 1 {
		return fmt.Sprintf("v%02d", n)
	}
	return strings.TrimSuffix(filepath.Base(hits[0]), ".json")
}

// normalizedInput returns the normalized "input" object of vector n.
func normalizedInput(n int) (map[string]any, error) {
	v, err := vec(n)
	if err != nil {
		return nil, err
	}
	input, ok := normalize(v["input"]).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vector %d input is not a JSON object", n)
	}
	return input, nil
}

// signed builds, timestamps, and signs a provenance record.
func signed(kind string, body map[string]any, who string, tsIndex int) (map[string]any, error) {
	pair := key(who)
	rec := co.CopyMap(body)
	rec["type"] = kind
	if _, present := rec["timestamp"]; !present {
		rec["timestamp"] = fmt.Sprintf("2026-07-13T0%d:00:00Z", tsIndex)
	}
	if kind == "succession" {
		if _, present := rec["predecessor"]; !present {
			rec["predecessor"] = pair.public
		}
	} else {
		rec["source"] = pair.public
	}
	return co.SignRecord(rec, pair.secret, kind)
}

// mentions reports whether any reason contains the substring.
func mentions(reasons []string, substring string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, substring) {
			return true
		}
	}
	return false
}

// schemaOK asserts vector n's normalized input is schema-valid.
func schemaOK(n int) error {
	input, err := normalizedInput(n)
	if err != nil {
		return err
	}
	ok, why, err := co.ValidateSchema(input, "")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

// semanticsOK asserts vector n's normalized input is semantically valid.
func semanticsOK(n int) error {
	input, err := normalizedInput(n)
	if err != nil {
		return err
	}
	ok, why, err := co.ValidateSemantics(input, "")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("semantics: %v", why)
	}
	return nil
}

// schemaFails asserts vector n's input is schema-invalid for a reason
// mentioning the given substring.
func schemaFails(n int, mustMention string) error {
	input, err := normalizedInput(n)
	if err != nil {
		return err
	}
	ok, why, err := co.ValidateSchema(input, "")
	if err != nil {
		return err
	}
	if ok {
		return errors.New("expected schema-invalid")
	}
	if !mentions(why, mustMention) {
		return fmt.Errorf("reasons %v do not mention %q", why, mustMention)
	}
	return nil
}

// semanticsFails asserts vector n's input is semantically invalid for a
// reason mentioning the given substring.
func semanticsFails(n int, mustMention string) error {
	input, err := normalizedInput(n)
	if err != nil {
		return err
	}
	ok, why, err := co.ValidateSemantics(input, "")
	if err != nil {
		return err
	}
	if ok {
		return errors.New("expected semantically-invalid")
	}
	if !mentions(why, mustMention) {
		return fmt.Errorf("reasons %v do not mention %q", why, mustMention)
	}
	return nil
}

// internalChecks runs the sanity checks that are not conformance vectors:
// the RFC 8032 TEST 1 known answer and the RFC 8785 basics.
func internalChecks() error {
	seed, err := hex.DecodeString(
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		return err
	}
	secret, public := co.KeypairFromSeed(seed)
	expected := "ed25519:" +
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	if public != expected {
		return fmt.Errorf("RFC 8032 TEST 1 public key mismatch: %s", public)
	}
	signature := ed25519.Sign(secret, nil)
	publicKey := secret.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, nil, signature) {
		return errors.New("signature round-trip failed")
	}
	if ed25519.Verify(publicKey, []byte("x"), signature) {
		return errors.New("signature verified a different message")
	}
	jcsChecks := []struct {
		value    any
		expected string
	}{
		{map[string]any{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		{json.Number("1.0"), "1"},
		{json.Number("6.000"), "6"},
		{json.Number("0.7"), "0.7"},
		{1.0, "1"},
		{6.0, "6"},
		{0.7, "0.7"},
	}
	for _, tc := range jcsChecks {
		got, jcsErr := co.SerializeJCS(tc.value)
		if jcsErr != nil {
			return jcsErr
		}
		if got != tc.expected {
			return fmt.Errorf("JCS %v: got %s, want %s", tc.value, got, tc.expected)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// the 38 vectors
// ---------------------------------------------------------------------

func v01() error {
	if err := schemaOK(1); err != nil {
		return err
	}
	return semanticsOK(1)
}

func v02() error {
	v, err := vec(2)
	if err != nil {
		return err
	}
	input, ok := normalize(v["input"]).(map[string]any)
	if !ok {
		return errors.New("input is not a JSON object")
	}
	if err := schemaOK(2); err != nil {
		return err
	}
	if err := semanticsOK(2); err != nil {
		return err
	}
	partial, missing := co.IsPartial(input)
	if !partial {
		return errors.New("expected a partial object")
	}
	expect, _ := v["expect"].(map[string]any)
	expectedMissing, _ := expect["missing"].([]any)
	if len(missing) != len(expectedMissing) {
		return fmt.Errorf("missing fields %v != %v", missing, expectedMissing)
	}
	for i, fieldRaw := range expectedMissing {
		if fieldName, _ := fieldRaw.(string); fieldName != missing[i] {
			return fmt.Errorf("missing fields %v != %v", missing, expectedMissing)
		}
	}
	return nil
}

func v03() error { return schemaFails(3, "effects") }
func v04() error { return schemaFails(4, "causes") }
func v05() error { return schemaFails(5, "modality") }
func v06() error { return schemaFails(6, "colour") }
func v07() error { return schemaFails(7, "causes") }

func v08() error { return schemaOK(8) }

func v09() error { return schemaFails(9, "label") }
func v10() error { return schemaFails(10, "category") }

func v11() error { return schemaOK(11) }

func v12() error { return schemaFails(12, "confidence") }

func v13() error {
	if err := schemaOK(13); err != nil {
		return err
	}
	return semanticsOK(13)
}

func v14() error {
	if err := schemaOK(14); err != nil {
		return err
	}
	return semanticsFails(14, "dmin")
}

func v15() error { return semanticsFails(15, "acyclic") }
func v16() error { return semanticsFails(16, "acyclic") }

func v17() error {
	v, err := vec(17)
	if err != nil {
		return err
	}
	given, _ := v["given"].(map[string]any)
	parent, okParent := normalize(given["parent"]).(map[string]any)
	if !okParent {
		return errors.New("parent is not a JSON object")
	}
	child, okChild := normalize(v["input"]).(map[string]any)
	if !okChild {
		return errors.New("input is not a JSON object")
	}
	valid, reason := co.RefinementValid(child, parent)
	if valid {
		return errors.New("expected an invalid refinement")
	}
	if !strings.Contains(reason, "rival") {
		return fmt.Errorf("reason: %s", reason)
	}
	return nil
}

func v18() error { return semanticsFails(18, "not a legal field") }
func v19() error { return semanticsFails(19, "language-tagged") }

func v20() error {
	dog := sym("cnt:dog")
	mammal := sym("cnt:mammal")
	animal := sym("cnt:animal")
	enrich := func(about, entry string, i int) (map[string]any, error) {
		return signed("enrichment", map[string]any{
			"about": about, "field": "subsumes", "entry": entry,
		}, "taxo", i)
	}
	r1, err := enrich(dog, mammal, 1)
	if err != nil {
		return err
	}
	r2, err := enrich(mammal, animal, 2)
	if err != nil {
		return err
	}
	r3, err := enrich(animal, dog, 3)
	if err != nil {
		return err
	}
	// The enforcing tier rejects the cycle-completing write.
	s := co.NewStore(true)
	if _, err := s.PutRecord(r1, ""); err != nil {
		return err
	}
	if _, err := s.PutRecord(r2, ""); err != nil {
		return err
	}
	_, err = s.PutRecord(r3, "")
	if err == nil {
		return errors.New("enforcing store accepted a cycle")
	}
	var rejected *co.RejectedWrite
	if !errors.As(err, &rejected) {
		return fmt.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(rejected.Reason, "cycle") {
		return fmt.Errorf("wrong rejection reason: %s", rejected.Reason)
	}
	// Decentralized merge: the view breaks the cycle deterministically.
	s2 := co.NewStore(true)
	if _, err := s2.PutRecord(r1, ""); err != nil {
		return err
	}
	if _, err := s2.PutRecord(r2, ""); err != nil {
		return err
	}
	bad := r3
	if _, err := s2.ForceMergeRecord(bad, ""); err != nil {
		return err
	}
	_, excluded := s2.ActiveTaxonomyEdges("subsumes")
	if len(excluded) != 1 {
		return fmt.Errorf("excluded %d records", len(excluded))
	}
	badID, _ := bad["id"].(string)
	if excludedID, _ := excluded[0]["id"].(string); excludedID != badID {
		return errors.New("excluded the wrong record")
	}
	if !gapIDs(s2, "inconsistent_hierarchy")[badID] {
		return errors.New("no repair gap surfaced")
	}
	return nil
}

// admissibleFor evaluates vectors 21-23's admissibility question.
func admissibleFor(n int) (bool, error) {
	v, err := vec(n)
	if err != nil {
		return false, err
	}
	given, ok := v["given"].(map[string]any)
	if !ok {
		return false, errors.New("given is not a JSON object")
	}
	cro := map[string]any{
		"causes":   []any{sym("occ:c")},
		"effects":  []any{sym("occ:e")},
		"temporal": given["temporal"],
	}
	elapsed, ok := co.AsFloat(given["elapsed_seconds"])
	if !ok {
		return false, errors.New("elapsed_seconds is not a number")
	}
	return co.Admissible(cro, elapsed)
}

func v21() error {
	admissible, err := admissibleFor(21)
	if err != nil {
		return err
	}
	if !admissible {
		return errors.New("expected admissible")
	}
	return nil
}

func v22() error {
	admissible, err := admissibleFor(22)
	if err != nil {
		return err
	}
	if admissible {
		return errors.New("expected not admissible")
	}
	return nil
}

func v23() error {
	admissible, err := admissibleFor(23)
	if err != nil {
		return err
	}
	if !admissible {
		return errors.New("expected admissible")
	}
	return nil
}

// identityMatch evaluates vectors 24-25: inputA and inputB must identify
// identically.
func identityMatch(n int) error {
	v, err := vec(n)
	if err != nil {
		return err
	}
	inputA, okA := normalize(v["inputA"]).(map[string]any)
	inputB, okB := normalize(v["inputB"]).(map[string]any)
	if !okA || !okB {
		return errors.New("inputs are not JSON objects")
	}
	idA, err := co.Identify(inputA, "")
	if err != nil {
		return err
	}
	idB, err := co.Identify(inputB, "")
	if err != nil {
		return err
	}
	if idA != idB {
		return fmt.Errorf("identifiers differ: %s != %s", idA, idB)
	}
	return nil
}

func v24() error { return identityMatch(24) }
func v25() error { return identityMatch(25) }

func v26() error {
	s := co.NewStore(true)
	obj := map[string]any{
		"type": "occurrent", "label": "press_button", "category": "action",
	}
	first, err := s.Put(obj, "")
	if err != nil {
		return err
	}
	second, err := s.Put(obj, "")
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("second put returned a different identifier")
	}
	if s.ObjectCount() != 1 {
		return fmt.Errorf("store holds %d objects", s.ObjectCount())
	}
	return nil
}

// enrichmentEntries digs one materialized field's entry list out of a
// Get() view.
func enrichmentEntries(view map[string]any, field string) []any {
	if view == nil {
		return nil
	}
	enrichments, _ := view["enrichments"].(map[string]any)
	entries, _ := enrichments[field].([]any)
	return entries
}

func v27() error {
	s := co.NewStore(true)
	occ, err := s.Put(map[string]any{
		"type": "occurrent", "label": "press_button", "category": "action",
	}, "")
	if err != nil {
		return err
	}
	entry := map[string]any{"lang": "en", "text": "press the button"}
	r1, err := signed("enrichment", map[string]any{
		"about": occ, "field": "aliases", "entry": entry,
	}, "alice", 1)
	if err != nil {
		return err
	}
	r2, err := signed("enrichment", map[string]any{
		"about": occ, "field": "aliases", "entry": entry,
	}, "bob", 2)
	if err != nil {
		return err
	}
	id1, err := s.PutRecord(r1, "")
	if err != nil {
		return err
	}
	id2, err := s.PutRecord(r2, "")
	if err != nil {
		return err
	}
	if id1 == id2 {
		return errors.New("expected two distinct records")
	}
	aliases := enrichmentEntries(s.Get(occ, "default"), "aliases")
	if len(aliases) != 1 {
		return fmt.Errorf("materialized %d alias entries", len(aliases))
	}
	first, _ := aliases[0].(map[string]any)
	contributors, _ := first["contributors"].([]any)
	if len(contributors) != 2 {
		return fmt.Errorf("entry has %d contributors", len(contributors))
	}
	return nil
}

func v28() error {
	s := co.NewStore(true)
	claim := map[string]any{
		"type":     "cro",
		"causes":   []any{sym("occ:A")},
		"effects":  []any{sym("occ:B")},
		"modality": "sufficient",
	}
	i1, err := s.Put(claim, "")
	if err != nil {
		return err
	}
	i2, err := s.Put(claim, "")
	if err != nil {
		return err
	}
	if i1 != i2 {
		return errors.New("the same claim produced two identifiers")
	}
	if s.ObjectCount() != 1 {
		return fmt.Errorf("store holds %d objects", s.ObjectCount())
	}
	labs := []struct {
		who string
		ts  int
	}{{"lab1", 1}, {"lab2", 2}}
	for _, lab := range labs {
		rec, err := signed("assertion", map[string]any{
			"about": i1, "evidence_type": "observation",
			"strength": 0.8, "confidence": 0.8,
		}, lab.who, lab.ts)
		if err != nil {
			return err
		}
		if _, err := s.PutRecord(rec, ""); err != nil {
			return err
		}
	}
	if n := len(s.AssertionsAbout(i1, false)); n != 2 {
		return fmt.Errorf("expected two assertions, got %d", n)
	}
	return nil
}

// demoAssertion builds the signed assertion vectors 29-30 examine.
func demoAssertion() (map[string]any, error) {
	return signed("assertion", map[string]any{
		"about": sym("cro:demo"), "evidence_type": "intervention",
		"strength": 0.7, "confidence": 0.9,
	}, "signer", 0)
}

func v29() error {
	rec, err := demoAssertion()
	if err != nil {
		return err
	}
	if !co.VerifyRecord(rec, "") {
		return errors.New("valid signature did not verify")
	}
	return nil
}

func v30() error {
	rec, err := demoAssertion()
	if err != nil {
		return err
	}
	tampered := co.CopyMap(rec)
	tampered["confidence"] = 0.1
	if co.VerifyRecord(tampered, "") {
		return errors.New("tampered record verified")
	}
	return nil
}

func v31() error {
	s := co.NewStore(true)
	x, err := s.Put(map[string]any{
		"type": "cro", "causes": []any{sym("occ:A")}, "effects": []any{sym("occ:B")},
	}, "")
	if err != nil {
		return err
	}
	a, err := signed("assertion", map[string]any{
		"about": x, "evidence_type": "observation", "confidence": 0.8,
	}, "lab1", 1)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(a, ""); err != nil {
		return err
	}
	retraction, err := signed("retraction", map[string]any{"retracts": a["id"]}, "lab1", 2)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(retraction, ""); err != nil {
		return err
	}
	if n := len(s.AssertionsAbout(x, false)); n != 0 {
		return fmt.Errorf("default view still shows %d assertions", n)
	}
	history := s.AssertionsAbout(x, true)
	if len(history) != 1 {
		return fmt.Errorf("history view has %d assertions", len(history))
	}
	if flagged, _ := history[0]["retracted"].(bool); !flagged {
		return errors.New("history entry lacks the retracted mark")
	}
	foreign, err := signed("retraction", map[string]any{"retracts": a["id"]}, "mallory", 3)
	if err != nil {
		return err
	}
	_, err = s.PutRecord(foreign, "")
	var rejected *co.RejectedWrite
	if err == nil || !errors.As(err, &rejected) {
		return errors.New("foreign retraction accepted")
	}
	if n := len(s.AssertionsAbout(x, false)); n != 0 {
		return fmt.Errorf("default view shows %d assertions", n)
	}
	if n := len(s.AssertionsAbout(x, true)); n != 1 {
		return fmt.Errorf("history view has %d assertions", n)
	}
	return nil
}

func v32() error {
	s := co.NewStore(true)
	occ, err := s.Put(map[string]any{
		"type": "occurrent", "label": "press_button", "category": "action",
	}, "")
	if err != nil {
		return err
	}
	e, err := signed("enrichment", map[string]any{
		"about": occ, "field": "aliases",
		"entry": map[string]any{"lang": "ja", "text": "botan"},
	}, "bob", 1)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(e, ""); err != nil {
		return err
	}
	if n := len(enrichmentEntries(s.Get(occ, "default"), "aliases")); n != 1 {
		return fmt.Errorf("before retraction: %d entries", n)
	}
	retraction, err := signed("retraction", map[string]any{"retracts": e["id"]}, "bob", 2)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(retraction, ""); err != nil {
		return err
	}
	if n := len(enrichmentEntries(s.Get(occ, "default"), "aliases")); n != 0 {
		return fmt.Errorf("after retraction: %d entries", n)
	}
	if n := len(enrichmentEntries(s.Get(occ, "history"), "aliases")); n != 1 {
		return fmt.Errorf("history view has %d entries", n)
	}
	return nil
}

func v33() error {
	s := co.NewStore(true)
	k1 := key("K1").public
	k2 := key("K2").public
	claim := sym("cro:claim")
	a, err := signed("assertion", map[string]any{
		"about": claim, "evidence_type": "observation", "confidence": 0.9,
	}, "K1", 1)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(a, ""); err != nil {
		return err
	}
	succession, err := signed("succession", map[string]any{"successor": k2}, "K1", 2)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(succession, ""); err != nil {
		return err
	}
	if !s.Lineage(k2)[k1] {
		return errors.New("K1 not in lineage of K2")
	}
	if !s.Lineage(k1)[k2] {
		return errors.New("K2 not in lineage of K1")
	}
	// The successor may retract the predecessor's record.
	retraction, err := signed("retraction", map[string]any{"retracts": a["id"]}, "K2", 3)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(retraction, ""); err != nil {
		return err
	}
	if n := len(s.AssertionsAbout(claim, false)); n != 0 {
		return fmt.Errorf("successor retraction did not apply: %d assertions", n)
	}
	return nil
}

// conflictPair evaluates vectors 34-35's conflict question.
func conflictPair(n int) (bool, error) {
	v, err := vec(n)
	if err != nil {
		return false, err
	}
	given, ok := normalize(v["given"]).(map[string]any)
	if !ok {
		return false, errors.New("given is not a JSON object")
	}
	a, okA := given["A"].(map[string]any)
	b, okB := given["B"].(map[string]any)
	if !okA || !okB {
		return false, errors.New("A and B must be JSON objects")
	}
	return co.Conflicts(a, b), nil
}

func v34() error {
	conflicting, err := conflictPair(34)
	if err != nil {
		return err
	}
	if !conflicting {
		return errors.New("expected a conflict")
	}
	return nil
}

func v35() error {
	conflicting, err := conflictPair(35)
	if err != nil {
		return err
	}
	if conflicting {
		return errors.New("expected no conflict")
	}
	return nil
}

func v36() error {
	occA := sym("occ:A")
	occB := sym("occ:B")
	occC := sym("occ:C")
	occD := sym("occ:D")
	m1ID := sym("cro:m1")
	m2ID := sym("cro:m2")
	m3ID := sym("cro:m3")
	m1 := map[string]any{"id": m1ID, "causes": []any{occA}, "effects": []any{occB}}
	m2 := map[string]any{"id": m2ID, "causes": []any{occB}, "effects": []any{occC}}
	m3 := map[string]any{"id": m3ID, "causes": []any{occD}, "effects": []any{occC}}
	parent := map[string]any{
		"causes": []any{occA}, "effects": []any{occC},
		"mechanism": []any{m1ID, m2ID},
	}
	if got := co.HierarchyConsistent(parent, map[string]map[string]any{
		m1ID: m1, m2ID: m2,
	}); got != "consistent" {
		return fmt.Errorf("path A -> B -> C should be consistent, got %s", got)
	}
	parent2 := co.CopyMap(parent)
	parent2["mechanism"] = []any{m1ID, m3ID}
	if got := co.HierarchyConsistent(parent2, map[string]map[string]any{
		m1ID: m1, m3ID: m3,
	}); got != "inconsistent" {
		return fmt.Errorf("D -> C replacement should be inconsistent, got %s", got)
	}
	if got := co.HierarchyConsistent(parent, map[string]map[string]any{
		m1ID: m1,
	}); got != "indeterminate" {
		return fmt.Errorf("absent member should be indeterminate, got %s", got)
	}
	return nil
}

func v37() error {
	s := co.NewStore(true)
	occ, err := s.Put(map[string]any{
		"type": "occurrent", "label": "press_button", "category": "action",
	}, "")
	if err != nil {
		return err
	}
	rec, err := signed("enrichment", map[string]any{
		"about": occ, "field": "aliases",
		"entry": map[string]any{"lang": "en", "text": "Press the Button"},
	}, "alice", 1)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(rec, ""); err != nil {
		return err
	}
	byAlias := s.Resolve("Press  The   Button", "en")
	if len(byAlias) != 1 || byAlias[0] != occ {
		return fmt.Errorf("alias match failed: %v", byAlias)
	}
	byLabel := s.Resolve("press_button", "en")
	if len(byLabel) == 0 || byLabel[0] != occ {
		return fmt.Errorf("canonical-label match not ranked first: %v", byLabel)
	}
	return nil
}

// gapIDs collects the ids of one gap kind into a membership set.
func gapIDs(s *co.Store, kind string) map[string]bool {
	out := map[string]bool{}
	for _, gap := range s.Gaps(kind) {
		if gapID, ok := gap["id"].(string); ok {
			out[gapID] = true
		}
	}
	return out
}

func v38() error {
	s := co.NewStore(true)
	occA := sym("occ:A")
	occB := sym("occ:B")
	parent, err := s.Put(map[string]any{
		"type": "cro", "causes": []any{occA}, "effects": []any{occB},
	}, "")
	if err != nil {
		return err
	}
	if !gapIDs(s, "missing_field")[parent] {
		return errors.New("P is not in the missing_field gaps")
	}
	refinement, err := s.Put(map[string]any{
		"type": "cro", "causes": []any{occA}, "effects": []any{occB},
		"temporal": map[string]any{"dmin": 0, "dmax": 1, "unit": "seconds"},
		"modality": "sufficient", "refines": parent,
	}, "")
	if err != nil {
		return err
	}
	after := gapIDs(s, "missing_field")
	if after[parent] {
		return errors.New("the gap did not close")
	}
	if after[refinement] {
		return errors.New("the refinement itself must be complete")
	}
	return nil
}

// ---------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------

func main() {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Printf("cannot locate the repository root: %v\n", err)
		os.Exit(1)
	}
	vectorsDir = filepath.Join(root, "conformance", "vectors")
	co.SetSchemaDir(filepath.Join(root, "spec", "schema"))

	fmt.Println("causalontology-go conformance run")
	fmt.Print("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
	if err := internalChecks(); err != nil {
		fmt.Printf("FAILED :: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")

	vectors := []func() error{
		v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
		v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
		v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
		v31, v32, v33, v34, v35, v36, v37, v38,
	}
	failures := 0
	for i, run := range vectors {
		name := vectorName(i + 1)
		if vectorErr := run(); vectorErr != nil {
			failures++
			fmt.Printf("FAIL  %s :: %v\n", name, vectorErr)
		} else {
			fmt.Printf("PASS  %s\n", name)
		}
	}
	total := len(vectors)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%d/%d vectors passed\n", total-failures, total)
	if failures > 0 {
		os.Exit(1)
	}
	fmt.Println("causalontology-go is CONFORMANT to the suite " +
		"(vectors frozen at specification 1.0.0).")
}

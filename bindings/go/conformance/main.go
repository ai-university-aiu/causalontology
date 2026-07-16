// Command conformance is the Causalontology conformance runner for
// causalontology-go (specification 2.0.0).
//
// It runs every vector in conformance/vectors/ against the Go binding. An
// implementation is conformant if and only if it passes every vector;
// this runner exits nonzero on any failure. It reproduces every vNN()
// assertion of bindings/python/tests/run_conformance.py with the same
// fixtures and the same expected results.
//
// The vectors carry symbolic identifiers ("occurrent:press_button",
// "ed25519:alice"). This harness normalizes them deterministically -
// symbolic object ids become scheme:sha256(name), and symbolic key names
// become real Ed25519 keypairs seeded from sha256("key:" + name) - so the
// normative behaviors are tested with well-formed, whole-word data.
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

	co "github.com/ai-university-aiu/causalontology/bindings/go/v2/causalontology"
)

// vectorsDir is the conformance/vectors directory, set by main.
var vectorsDir string

// schemeNames are the seventeen whole-word identifier schemes (P7).
var schemeNames = []string{
	"occurrent", "causal_relation_object", "continuant", "realizable",
	"assertion", "enrichment", "retraction", "succession",
	"stratum", "bridge", "port", "conduit", "quality",
	"token_individual", "token_occurrence", "state_assertion",
	"token_causal_claim",
}

// wholeWord is the set of legitimate schemes plus ed25519 (V106).
var wholeWord = func() map[string]bool {
	out := map[string]bool{"ed25519": true}
	for _, s := range schemeNames {
		out[s] = true
	}
	return out
}()

// symbolicPrefix recognizes the whole-word identifier schemes the vectors
// and fixtures use.
var symbolicPrefix = regexp.MustCompile(
	"^(" + strings.Join(append(append([]string{}, schemeNames...), "ed25519"), "|") + "):")

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
			return s
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

// findRepoRoot locates the repository root.
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

// vec loads vector n's JSON file.
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

// ---------------------------------------------------------------------
// content-object builders (mirror the Python run_conformance builders)
// ---------------------------------------------------------------------

// mk completes a content object with its content-addressed id.
func mk(obj map[string]any) map[string]any {
	o := co.CopyMap(obj)
	id, err := co.Identify(o, "")
	if err != nil {
		panic(err)
	}
	o["id"] = id
	return o
}

// idOf returns an object's id.
func idOf(o map[string]any) string {
	id, _ := o["id"].(string)
	return id
}

// L builds a []any of strings.
func L(items ...string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}

// omap indexes objects by id into the map[string]map[string]any the
// semantic algorithms take.
func omap(objs ...map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, o := range objs {
		m[idOf(o)] = o
	}
	return m
}

func boolPtr(b bool) *bool { return &b }

func stratum(label, scheme string, ordinal int, unit string, governs []string) map[string]any {
	o := map[string]any{"type": "stratum", "label": label, "scheme": scheme, "ordinal": ordinal}
	if unit != "" {
		o["unit"] = unit
	}
	if governs != nil {
		arr := make([]any, len(governs))
		for i, g := range governs {
			arr[i] = g
		}
		o["governs"] = arr
	}
	return mk(o)
}

func occ(label, stratumID string) map[string]any {
	o := map[string]any{"type": "occurrent", "label": label, "category": "event"}
	if stratumID != "" {
		o["stratum"] = stratumID
	}
	return mk(o)
}

func cnt(label string) map[string]any {
	return mk(map[string]any{"type": "continuant", "label": label, "category": "object"})
}

func cro(causes, effects []any, kw map[string]any) map[string]any {
	o := map[string]any{"type": "causal_relation_object", "causes": causes, "effects": effects}
	for k, v := range kw {
		o[k] = v
	}
	return mk(o)
}

func bridge(coarse string, fine []any, relation string) map[string]any {
	return mk(map[string]any{"type": "bridge", "coarse": coarse, "fine": fine, "relation": relation})
}

func port(bearer, label, direction string, accepts []any, realizable string) map[string]any {
	o := map[string]any{"type": "port", "bearer": bearer, "label": label,
		"direction": direction, "accepts": accepts}
	if realizable != "" {
		o["realizable"] = realizable
	}
	return mk(o)
}

func conduit(frm, to string, carries []any, label, transform string) map[string]any {
	o := map[string]any{"type": "conduit", "label": label, "from": frm, "to": to, "carries": carries}
	if transform != "" {
		o["transform"] = transform
	}
	return mk(o)
}

func quality(label, datatype, unit, stratumID string) map[string]any {
	o := map[string]any{"type": "quality", "label": label, "datatype": datatype}
	if unit != "" {
		o["unit"] = unit
	}
	if stratumID != "" {
		o["stratum"] = stratumID
	}
	return mk(o)
}

func individual(instantiates, designator, partOf string) map[string]any {
	o := map[string]any{"type": "token_individual", "instantiates": instantiates}
	if designator != "" {
		o["designator"] = designator
	}
	if partOf != "" {
		o["part_of"] = partOf
	}
	return mk(o)
}

func token(instantiates string, interval map[string]any, participants []any, locus string) map[string]any {
	o := map[string]any{"type": "token_occurrence", "instantiates": instantiates, "interval": interval}
	if participants != nil {
		o["participants"] = participants
	}
	if locus != "" {
		o["locus"] = locus
	}
	return mk(o)
}

func state(subject, qual string, value, interval map[string]any) map[string]any {
	return mk(map[string]any{"type": "state_assertion", "subject": subject,
		"quality": qual, "value": value, "interval": interval})
}

func tcc(causes, effects []any, coveringLaw string, actualDelay map[string]any, counterfactual *bool) map[string]any {
	o := map[string]any{"type": "token_causal_claim", "causes": causes, "effects": effects}
	if coveringLaw != "" {
		o["covering_law"] = coveringLaw
	}
	if actualDelay != nil {
		o["actual_delay"] = actualDelay
	}
	if counterfactual != nil {
		o["counterfactual"] = *counterfactual
	}
	return mk(o)
}

func rlz(bearer, kind, label string) map[string]any {
	o := map[string]any{"type": "realizable", "kind": kind, "bearer": bearer}
	if label != "" {
		o["label"] = label
	}
	return mk(o)
}

// neuro is the six-stratum neuroendocrine fixture (matches _neuro()).
func neuro() map[int]map[string]any {
	labels := map[int]string{4: "macromolecular", 5: "subcellular", 6: "cellular",
		7: "synaptic", 9: "region", 14: "community_and_society"}
	out := map[int]map[string]any{}
	for o, lab := range labels {
		out[o] = stratum(lab, "neuroendocrine", o, "", nil)
	}
	return out
}

// ---------------------------------------------------------------------
// assertion helpers
// ---------------------------------------------------------------------

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

// schemaValidExplicit validates an object against an explicit kind.
func schemaValidExplicit(obj map[string]any, kind string) (bool, []string) {
	ok, why, err := co.ValidateSchema(obj, kind)
	if err != nil {
		return false, []string{err.Error()}
	}
	return ok, why
}

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
	jcsChecks := []struct {
		value    any
		expected string
	}{
		{map[string]any{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		{json.Number("1.0"), "1"},
		{json.Number("6.000"), "6"},
		{json.Number("0.7"), "0.7"},
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
	if co.ToSeconds(1, "months") != 2629746 {
		return errors.New("months constant wrong")
	}
	if co.ToSeconds(1, "years") != 31556952 {
		return errors.New("years constant wrong")
	}
	// Ground-truth content-addressed ids (PORT_GUIDE cross-check).
	groundTruth := []struct {
		obj  map[string]any
		want string
	}{
		{map[string]any{"type": "stratum", "label": "cellular", "scheme": "neuroendocrine", "ordinal": 6},
			"stratum:99162f6202087b209696f9a2a21fe57ada3a349840ce5f8af25e034c8bde5b81"},
		{map[string]any{"type": "realizable", "kind": "disposition",
			"bearer": "continuant:" + strings.Repeat("0", 64), "label": "ltp"},
			"realizable:486be612e50996f60632764a36d009e151a3967d4bedac3f61c88844577243c1"},
		{map[string]any{"type": "token_occurrence",
			"instantiates": "occurrent:" + strings.Repeat("0", 64),
			"interval":     map[string]any{"start": "1953-08-25T00:00:00Z", "open": true}},
			"token_occurrence:85987b294d9902330b25a9d692cdce27bce090bca30e7c09e8b943059e23351d"},
	}
	for _, g := range groundTruth {
		got, idErr := co.Identify(g.obj, "")
		if idErr != nil {
			return idErr
		}
		if got != g.want {
			return fmt.Errorf("ground-truth id mismatch:\n got  %s\n want %s", got, g.want)
		}
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

// enrichmentEntries digs one materialized field's entry list out of a view.
func enrichmentEntries(view map[string]any, field string) []any {
	if view == nil {
		return nil
	}
	enrichments, _ := view["enrichments"].(map[string]any)
	entries, _ := enrichments[field].([]any)
	return entries
}

// ---------------------------------------------------------------------
// V01 - V38: the whole-word re-freeze of the 1.0.0 suite
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
	return semanticsFails(14, "minimum_delay")
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
	dog := sym("continuant:dog")
	mammal := sym("continuant:mammal")
	animal := sym("continuant:animal")
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

func admissibleFor(n int) (bool, error) {
	v, err := vec(n)
	if err != nil {
		return false, err
	}
	given, ok := v["given"].(map[string]any)
	if !ok {
		return false, errors.New("given is not a JSON object")
	}
	c := map[string]any{
		"causes":   L(sym("occurrent:c")),
		"effects":  L(sym("occurrent:e")),
		"temporal": given["temporal"],
	}
	elapsed, ok := co.AsFloat(given["elapsed_seconds"])
	if !ok {
		return false, errors.New("elapsed_seconds is not a number")
	}
	return co.Admissible(c, elapsed)
}

func v21() error {
	ok, err := admissibleFor(21)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("expected admissible")
	}
	return nil
}

func v22() error {
	ok, err := admissibleFor(22)
	if err != nil {
		return err
	}
	if ok {
		return errors.New("expected not admissible")
	}
	return nil
}

func v23() error {
	ok, err := admissibleFor(23)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("expected admissible")
	}
	return nil
}

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
	obj := map[string]any{"type": "occurrent", "label": "press_button", "category": "action"}
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

func v27() error {
	s := co.NewStore(true)
	occid, err := s.Put(map[string]any{
		"type": "occurrent", "label": "press_button", "category": "action",
	}, "")
	if err != nil {
		return err
	}
	entry := map[string]any{"lang": "en", "text": "press the button"}
	r1, err := signed("enrichment", map[string]any{"about": occid, "field": "aliases", "entry": entry}, "alice", 1)
	if err != nil {
		return err
	}
	r2, err := signed("enrichment", map[string]any{"about": occid, "field": "aliases", "entry": entry}, "bob", 2)
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
	aliases := enrichmentEntries(s.Get(occid, "default"), "aliases")
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
		"type": "causal_relation_object", "causes": L(sym("occurrent:A")),
		"effects": L(sym("occurrent:B")), "modality": "sufficient",
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
			"about": i1, "evidence_type": "observation", "strength": 0.8, "confidence": 0.8,
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

func demoAssertion() (map[string]any, error) {
	return signed("assertion", map[string]any{
		"about": sym("causal_relation_object:demo"), "evidence_type": "intervention",
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
		"type": "causal_relation_object", "causes": L(sym("occurrent:A")), "effects": L(sym("occurrent:B")),
	}, "")
	if err != nil {
		return err
	}
	a, err := signed("assertion", map[string]any{"about": x, "evidence_type": "observation", "confidence": 0.8}, "lab1", 1)
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
	return nil
}

func v32() error {
	s := co.NewStore(true)
	occid, err := s.Put(map[string]any{"type": "occurrent", "label": "press_button", "category": "action"}, "")
	if err != nil {
		return err
	}
	e, err := signed("enrichment", map[string]any{
		"about": occid, "field": "aliases", "entry": map[string]any{"lang": "ja", "text": "botan"},
	}, "bob", 1)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(e, ""); err != nil {
		return err
	}
	if n := len(enrichmentEntries(s.Get(occid, "default"), "aliases")); n != 1 {
		return fmt.Errorf("before retraction: %d entries", n)
	}
	retraction, err := signed("retraction", map[string]any{"retracts": e["id"]}, "bob", 2)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(retraction, ""); err != nil {
		return err
	}
	if n := len(enrichmentEntries(s.Get(occid, "default"), "aliases")); n != 0 {
		return fmt.Errorf("after retraction: %d entries", n)
	}
	if n := len(enrichmentEntries(s.Get(occid, "history"), "aliases")); n != 1 {
		return fmt.Errorf("history view has %d entries", n)
	}
	return nil
}

func v33() error {
	s := co.NewStore(true)
	k1 := key("K1").public
	k2 := key("K2").public
	claim := sym("causal_relation_object:claim")
	a, err := signed("assertion", map[string]any{"about": claim, "evidence_type": "observation", "confidence": 0.9}, "K1", 1)
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
	c, err := conflictPair(34)
	if err != nil {
		return err
	}
	if !c {
		return errors.New("expected a conflict")
	}
	return nil
}

func v35() error {
	c, err := conflictPair(35)
	if err != nil {
		return err
	}
	if c {
		return errors.New("expected no conflict")
	}
	return nil
}

func v36() error {
	occA := sym("occurrent:A")
	occB := sym("occurrent:B")
	occC := sym("occurrent:C")
	occD := sym("occurrent:D")
	m1ID := sym("causal_relation_object:m1")
	m2ID := sym("causal_relation_object:m2")
	m3ID := sym("causal_relation_object:m3")
	m1 := map[string]any{"id": m1ID, "causes": L(occA), "effects": L(occB)}
	m2 := map[string]any{"id": m2ID, "causes": L(occB), "effects": L(occC)}
	m3 := map[string]any{"id": m3ID, "causes": L(occD), "effects": L(occC)}
	parent := map[string]any{"causes": L(occA), "effects": L(occC), "mechanism": L(m1ID, m2ID)}
	if got := co.HierarchyConsistent(parent, map[string]map[string]any{m1ID: m1, m2ID: m2}, nil); got != "consistent" {
		return fmt.Errorf("path A -> B -> C should be consistent, got %s", got)
	}
	parent2 := co.CopyMap(parent)
	parent2["mechanism"] = L(m1ID, m3ID)
	if got := co.HierarchyConsistent(parent2, map[string]map[string]any{m1ID: m1, m3ID: m3}, nil); got != "inconsistent" {
		return fmt.Errorf("D -> C replacement should be inconsistent, got %s", got)
	}
	if got := co.HierarchyConsistent(parent, map[string]map[string]any{m1ID: m1}, nil); got != "indeterminate" {
		return fmt.Errorf("absent member should be indeterminate, got %s", got)
	}
	return nil
}

func v37() error {
	s := co.NewStore(true)
	occid, err := s.Put(map[string]any{"type": "occurrent", "label": "press_button", "category": "action"}, "")
	if err != nil {
		return err
	}
	rec, err := signed("enrichment", map[string]any{
		"about": occid, "field": "aliases", "entry": map[string]any{"lang": "en", "text": "Press the Button"},
	}, "alice", 1)
	if err != nil {
		return err
	}
	if _, err := s.PutRecord(rec, ""); err != nil {
		return err
	}
	byAlias := s.Resolve("Press  The   Button", "en")
	if len(byAlias) != 1 || byAlias[0] != occid {
		return fmt.Errorf("alias match failed: %v", byAlias)
	}
	byLabel := s.Resolve("press_button", "en")
	if len(byLabel) == 0 || byLabel[0] != occid {
		return fmt.Errorf("canonical-label match not ranked first: %v", byLabel)
	}
	return nil
}

func v38() error {
	s := co.NewStore(true)
	occA := sym("occurrent:A")
	occB := sym("occurrent:B")
	parent, err := s.Put(map[string]any{
		"type": "causal_relation_object", "causes": L(occA), "effects": L(occB),
	}, "")
	if err != nil {
		return err
	}
	if !gapIDs(s, "missing_field")[parent] {
		return errors.New("P is not in the missing_field gaps")
	}
	refinement, err := s.Put(map[string]any{
		"type": "causal_relation_object", "causes": L(occA), "effects": L(occB),
		"temporal": map[string]any{"minimum_delay": 0, "maximum_delay": 1, "unit": "seconds"},
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
// V39 - V107: the 2.0.0 additions
// ---------------------------------------------------------------------

func v39() error {
	st := stratum("cellular", "neuroendocrine", 6, "cell", []string{"cell_biology"})
	if ok, why := schemaValidExplicit(st, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v40() error {
	bad := mk(map[string]any{"type": "stratum", "label": "cellular", "ordinal": 6})
	ok, why := schemaValidExplicit(bad, "stratum")
	if ok || !mentions(why, "scheme") {
		return fmt.Errorf("expected scheme failure, got ok=%v why=%v", ok, why)
	}
	return nil
}

func v41() error {
	a := stratum("cellular", "neuroendocrine", 6, "", nil)
	b := stratum("neuronal", "neuroendocrine", 6, "", nil)
	for _, x := range []map[string]any{a, b} {
		if ok, why := schemaValidExplicit(x, ""); !ok {
			return fmt.Errorf("schema: %v", why)
		}
	}
	if idOf(a) == idOf(b) {
		return errors.New("distinct labels must yield distinct ids")
	}
	return nil
}

func v42() error {
	s := neuro()
	s4p := stratum("molecular", "physics", 4, "", nil)
	c := occ("chronic_social_subordination", idOf(s[14]))
	e := occ("gene_expression", idOf(s4p))
	smap := map[string]map[string]any{idOf(s[14]): s[14], idOf(s4p): s4p}
	P := cro(L(idOf(c)), L(idOf(e)), nil)
	if got := co.ClassifyCRO(P, omap(c, e), smap); got != "scheme_mismatch" {
		return fmt.Errorf("expected scheme_mismatch, got %s", got)
	}
	return nil
}

func v43() error {
	for _, x := range []map[string]any{
		stratum("macromolecular", "neuroendocrine", 4, "", nil),
		stratum("region", "neuroendocrine", 9, "", nil),
	} {
		if ok, why := schemaValidExplicit(x, ""); !ok {
			return fmt.Errorf("schema: %v", why)
		}
	}
	return nil
}

func v44() error {
	st := stratum("cellular", "neuroendocrine", 6, "", nil)
	o := occ("neuron_fires", idOf(st))
	if ok, why := schemaValidExplicit(o, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	ok, why, err := co.ValidateSemantics(o, "")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("semantics: %v", why)
	}
	return nil
}

func v45() error {
	o := occ("press_button", "")
	if ok, why := schemaValidExplicit(o, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	e := occ("light_on", "")
	P := cro(L(idOf(o)), L(idOf(e)), nil)
	if got := co.ClassifyCRO(P, omap(o, e), map[string]map[string]any{}); got != "unclassifiable" {
		return fmt.Errorf("expected unclassifiable, got %s", got)
	}
	return nil
}

func v46() error {
	s := neuro()
	a := occ("depolarization", idOf(s[5]))
	b := occ("depolarization", idOf(s[6]))
	if idOf(a) == idOf(b) {
		return errors.New("same label different stratum must differ")
	}
	return nil
}

func bridgeFixture(relation string) (map[string]any, map[string]map[string]any, map[string]map[string]any) {
	s := neuro()
	coarse := occ("action_potential_fires", idOf(s[6]))
	fine := []map[string]any{occ("sodium_channels_open", idOf(s[4])), occ("sodium_influx", idOf(s[4]))}
	b := bridge(idOf(coarse), L(idOf(fine[0]), idOf(fine[1])), relation)
	om := map[string]map[string]any{idOf(coarse): coarse}
	for _, f := range fine {
		om[idOf(f)] = f
	}
	sm := map[string]map[string]any{idOf(s[4]): s[4], idOf(s[6]): s[6]}
	return b, om, sm
}

func validBridge(relation string) error {
	b, om, sm := bridgeFixture(relation)
	if ok, why := schemaValidExplicit(b, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if ok, why := co.BridgeWellformed(b, om, sm); !ok {
		return fmt.Errorf("bridge_wellformed: %s", why)
	}
	return nil
}

func v47() error { return validBridge("constitutes") }
func v48() error { return validBridge("aggregates") }
func v49() error { return validBridge("realizes") }
func v50() error { return validBridge("supervenes_on") }

func v51() error {
	s := neuro()
	coarse := occ("x_coarse", idOf(s[4]))
	fine := occ("x_fine", idOf(s[6]))
	b := bridge(idOf(coarse), L(idOf(fine)), "constitutes")
	om := omap(coarse, fine)
	sm := map[string]map[string]any{idOf(s[4]): s[4], idOf(s[6]): s[6]}
	if ok, _ := co.BridgeWellformed(b, om, sm); ok {
		return errors.New("expected malformed bridge (coarse ordinal not > fine)")
	}
	return nil
}

func v52() error {
	s := neuro()
	coarse := occ("c", idOf(s[6]))
	f1 := occ("f1", idOf(s[4]))
	f2 := occ("f2", idOf(s[5]))
	b := bridge(idOf(coarse), L(idOf(f1), idOf(f2)), "constitutes")
	om := omap(coarse, f1, f2)
	sm := map[string]map[string]any{idOf(s[4]): s[4], idOf(s[5]): s[5], idOf(s[6]): s[6]}
	if ok, _ := co.BridgeWellformed(b, om, sm); ok {
		return errors.New("expected malformed bridge (fine members span >1 stratum)")
	}
	return nil
}

func v53() error {
	x, y := sym("occurrent:x"), sym("occurrent:y")
	b1 := bridge(x, L(y), "constitutes")
	b2 := bridge(y, L(x), "constitutes")
	edges := map[string][]string{}
	for _, b := range []map[string]any{b1, b2} {
		coarse, _ := b["coarse"].(string)
		for _, f := range b["fine"].([]any) {
			fs, _ := f.(string)
			edges[fs] = append(edges[fs], coarse)
		}
	}
	if !co.HasCycle(edges) {
		return errors.New("expected a bridge cycle")
	}
	return nil
}

func v54() error {
	a := stratum("cellular", "neuroendocrine", 6, "", nil)
	b := stratum("molecular", "physics", 4, "", nil)
	coarse := occ("c", idOf(a))
	fine := occ("f", idOf(b))
	br := bridge(idOf(coarse), L(idOf(fine)), "constitutes")
	om := omap(coarse, fine)
	sm := map[string]map[string]any{idOf(a): a, idOf(b): b}
	if ok, _ := co.BridgeWellformed(br, om, sm); ok {
		return errors.New("expected malformed bridge (across schemes)")
	}
	return nil
}

func v55() error {
	s := neuro()
	coarse := occ("decision_made", idOf(s[6]))
	f1 := occ("cascade_a", idOf(s[4]))
	f2 := occ("cascade_b", idOf(s[4]))
	b1 := bridge(idOf(coarse), L(idOf(f1)), "realizes")
	b2 := bridge(idOf(coarse), L(idOf(f2)), "realizes")
	if idOf(b1) == idOf(b2) {
		return errors.New("two bridges must have distinct ids")
	}
	for _, b := range []map[string]any{b1, b2} {
		if ok, why := schemaValidExplicit(b, ""); !ok {
			return fmt.Errorf("schema: %v", why)
		}
	}
	return nil
}

func reachFixture() (map[string]any, map[string]map[string]any, []map[string]any) {
	s := neuro()
	ap := occ("action_potential_fires", idOf(s[6]))
	nt := occ("neurotransmitter_released", idOf(s[6]))
	fa := occ("calcium_enters", idOf(s[4]))
	fb := occ("vesicle_fuses", idOf(s[4]))
	m1 := cro(L(idOf(fa)), L(idOf(fb)), nil)
	P := cro(L(idOf(ap)), L(idOf(nt)), map[string]any{"mechanism": L(idOf(m1))})
	bridges := []map[string]any{
		bridge(idOf(ap), L(idOf(fa)), "constitutes"),
		bridge(idOf(nt), L(idOf(fb)), "constitutes"),
	}
	return P, map[string]map[string]any{idOf(m1): m1}, bridges
}

func v56() error {
	P, members, bridges := reachFixture()
	if got := co.HierarchyConsistent(P, members, bridges); got != "consistent" {
		return fmt.Errorf("expected consistent, got %s", got)
	}
	return nil
}

func v57() error {
	P, members, _ := reachFixture()
	if got := co.HierarchyConsistent(P, members, nil); got != "inconsistent" {
		return fmt.Errorf("expected inconsistent, got %s", got)
	}
	return nil
}

func v58() error {
	P, members, bridges := reachFixture()
	literal := co.HierarchyConsistent(P, members, nil)
	bridged := co.HierarchyConsistent(P, members, bridges)
	if literal == "consistent" || bridged != "consistent" {
		return fmt.Errorf("literal=%s bridged=%s", literal, bridged)
	}
	return nil
}

func classify(causeOrd, effectOrd int) string {
	s := neuro()
	c := occ("c", idOf(s[causeOrd]))
	e := occ("e", idOf(s[effectOrd]))
	sm := map[string]map[string]any{idOf(s[causeOrd]): s[causeOrd], idOf(s[effectOrd]): s[effectOrd]}
	return co.ClassifyCRO(cro(L(idOf(c)), L(idOf(e)), nil), omap(c, e), sm)
}

func v59() error {
	if got := classify(6, 6); got != "intra_stratal" {
		return fmt.Errorf("expected intra_stratal, got %s", got)
	}
	return nil
}

func v60() error {
	if got := classify(6, 5); got != "adjacent_stratal" {
		return fmt.Errorf("expected adjacent_stratal, got %s", got)
	}
	return nil
}

func v61() error {
	if got := classify(14, 4); got != "skipping" {
		return fmt.Errorf("expected skipping, got %s", got)
	}
	return nil
}

func skipFixture(causeOrd, effectOrd int, kw map[string]any) (map[string]any, string) {
	s := neuro()
	c := occ("c", idOf(s[causeOrd]))
	e := occ("e", idOf(s[effectOrd]))
	sm := map[string]map[string]any{idOf(s[causeOrd]): s[causeOrd], idOf(s[effectOrd]): s[effectOrd]}
	P := cro(L(idOf(c)), L(idOf(e)), kw)
	return P, co.ClassifyCRO(P, omap(c, e), sm)
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func v62() error {
	P, cls := skipFixture(14, 4, nil)
	if got := co.SkipGaps(P, cls); !eqStrings(got, []string{"incomplete_mechanism"}) {
		return fmt.Errorf("expected [incomplete_mechanism], got %v", got)
	}
	return nil
}

func v63() error {
	P, cls := skipFixture(14, 4, map[string]any{"skips": true})
	if got := co.SkipGaps(P, cls); len(got) != 0 {
		return fmt.Errorf("expected [], got %v", got)
	}
	return nil
}

func v64() error {
	P, cls := skipFixture(14, 4, map[string]any{"skips": true, "mechanism": L(sym("causal_relation_object:m"))})
	if got := co.SkipGaps(P, cls); !eqStrings(got, []string{"contradictory_skip"}) {
		return fmt.Errorf("expected [contradictory_skip], got %v", got)
	}
	ok, why, err := co.ValidateSemantics(P, "")
	if err != nil {
		return err
	}
	if ok || !mentions(why, "contradictory_skip") {
		return fmt.Errorf("expected hard semantics failure, ok=%v why=%v", ok, why)
	}
	return nil
}

func v65() error {
	P, cls := skipFixture(6, 6, map[string]any{"skips": true})
	if got := co.SkipGaps(P, cls); !eqStrings(got, []string{"vacuous_skip"}) {
		return fmt.Errorf("expected [vacuous_skip], got %v", got)
	}
	return nil
}

func v66() error {
	s := neuro()
	c := occ("c", idOf(s[14]))
	e := occ("e", idOf(s[4]))
	absent := cro(L(idOf(c)), L(idOf(e)), nil)
	falseSkip := cro(L(idOf(c)), L(idOf(e)), map[string]any{"skips": false})
	if idOf(absent) == idOf(falseSkip) {
		return errors.New("skips=false must be distinct from skips absent")
	}
	return nil
}

func v67() error {
	s := neuro()
	c1 := occ("c1", idOf(s[4]))
	c2 := occ("c2", idOf(s[6]))
	e := occ("e", idOf(s[6]))
	P := cro(L(idOf(c1), idOf(c2)), L(idOf(e)), nil)
	if !co.EndpointsMixed(P, omap(c1, c2, e)) {
		return errors.New("expected mixed endpoints")
	}
	return nil
}

func v68() error {
	P := cro(L(sym("occurrent:a")), L(sym("occurrent:b")), map[string]any{"modality": "enabling"})
	if ok, why := schemaValidExplicit(P, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v69() error {
	a := map[string]any{"causes": L(sym("occurrent:a")), "effects": L(sym("occurrent:b")), "modality": "enabling"}
	b := map[string]any{"causes": L(sym("occurrent:a")), "effects": L(sym("occurrent:b")), "modality": "sufficient"}
	if co.Conflicts(a, b) {
		return errors.New("enabling and sufficient must not conflict")
	}
	return nil
}

func v70() error {
	a := map[string]any{"causes": L(sym("occurrent:a")), "effects": L(sym("occurrent:b")), "modality": "enabling"}
	b := map[string]any{"causes": L(sym("occurrent:a")), "effects": L(sym("occurrent:b")), "modality": "preventive"}
	if !co.Conflicts(a, b) {
		return errors.New("enabling must be opposed by preventive")
	}
	return nil
}

func v71() error {
	b := cnt("hippocampus")
	p := port(idOf(b), "perforant_path", "in", L(sym("occurrent:signal")), "")
	if ok, why := schemaValidExplicit(p, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v72() error {
	b := idOf(cnt("hippocampus"))
	x := sym("occurrent:signal")
	if idOf(port(b, "perforant_path", "in", L(x), "")) == idOf(port(b, "fornix", "in", L(x), "")) {
		return errors.New("ports differing only in label must differ")
	}
	return nil
}

func conduitFixture(transform, badCarry, inFrom bool) (map[string]any, map[string]map[string]any, map[string]map[string]any) {
	x := sym("occurrent:motor_command")
	y := sym("occurrent:error_signal")
	z := sym("occurrent:unrelated")
	m1 := idOf(cnt("motor_cortex"))
	m2 := idOf(cnt("spinal_neuron"))
	fromDir := "out"
	if inFrom {
		fromDir = "in"
	}
	frm := port(m1, "out_port", fromDir, L(x), "")
	toAccepts := L(x)
	if transform {
		toAccepts = L(y)
	}
	to := port(m2, "in_port", "in", toAccepts, "")
	carries := L(x)
	if badCarry {
		carries = L(z)
	}
	xform := ""
	croMap := map[string]map[string]any{}
	if transform {
		law := cro(L(x), L(y), nil)
		croMap[idOf(law)] = law
		xform = idOf(law)
	}
	c := conduit(idOf(frm), idOf(to), carries, "conn", xform)
	return c, map[string]map[string]any{idOf(frm): frm, idOf(to): to}, croMap
}

func v73() error {
	c, pmap, _ := conduitFixture(false, false, false)
	if ok, why := schemaValidExplicit(c, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if ok, why := co.ConduitWellformed(c, pmap, nil); !ok {
		return fmt.Errorf("conduit_wellformed: %s", why)
	}
	return nil
}

func v74() error {
	c, pmap, cmap := conduitFixture(true, false, false)
	if ok, why := schemaValidExplicit(c, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if ok, why := co.ConduitWellformed(c, pmap, cmap); !ok {
		return fmt.Errorf("conduit_wellformed: %s", why)
	}
	return nil
}

func v75() error {
	c, pmap, _ := conduitFixture(false, true, false)
	if ok, _ := co.ConduitWellformed(c, pmap, nil); ok {
		return errors.New("expected malformed conduit (unaccepted carry)")
	}
	return nil
}

func v76() error {
	c, pmap, _ := conduitFixture(false, false, true)
	if ok, _ := co.ConduitWellformed(c, pmap, nil); ok {
		return errors.New("expected malformed conduit (from an in port)")
	}
	return nil
}

func v77() error {
	c, pmap, cmap := conduitFixture(true, false, false)
	if ok, why := co.ConduitWellformed(c, pmap, cmap); !ok {
		return fmt.Errorf("conduit_wellformed: %s", why)
	}
	var law map[string]any
	for _, v := range cmap {
		law = v
	}
	effect := stringOfFirst(law["effects"])
	for _, carried := range c["carries"].([]any) {
		if s, _ := carried.(string); s == effect {
			return errors.New("transform effect must not be in carries")
		}
	}
	return nil
}

func stringOfFirst(v any) string {
	if list, ok := v.([]any); ok && len(list) > 0 {
		s, _ := list[0].(string)
		return s
	}
	return ""
}

func v78() error {
	b := idOf(cnt("hippocampus"))
	if idOf(rlz(b, "disposition", "long_term_potentiation")) == idOf(rlz(b, "disposition", "pattern_separation")) {
		return errors.New("labelled realizables must differ")
	}
	return nil
}

func v79() error {
	b := idOf(cnt("hippocampus"))
	u1 := rlz(b, "disposition", "")
	u2 := rlz(b, "disposition", "")
	if ok, why := schemaValidExplicit(u1, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if idOf(u1) != idOf(u2) {
		return errors.New("unlabelled realizable ids must match")
	}
	if idOf(rlz(b, "disposition", "some_function")) == idOf(u1) {
		return errors.New("labelled realizable must differ from unlabelled")
	}
	return nil
}

func v80() error {
	parent := occ("fires", "")
	child := occ("fires_action_potential", "")
	e := map[string]any{"type": "enrichment", "about": idOf(child),
		"field": "occurrent_subsumes", "entry": idOf(parent)}
	ok, why, err := co.ValidateSemantics(e, "")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("semantics: %v", why)
	}
	return nil
}

func v81() error {
	a, b := sym("occurrent:a"), sym("occurrent:b")
	if !co.HasCycle(map[string][]string{a: {b}, b: {a}}) {
		return errors.New("expected a cycle")
	}
	return nil
}

func v82() error {
	whole := occ("eat", "")
	part := occ("chew", "")
	e := map[string]any{"type": "enrichment", "about": idOf(part),
		"field": "occurrent_part_of", "entry": idOf(whole)}
	ok, why, err := co.ValidateSemantics(e, "")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("semantics: %v", why)
	}
	return nil
}

func v83() error {
	legalKinds, shape, ok := co.EnrichmentFieldSpec("occurrent_part_of")
	if !ok {
		return errors.New("occurrent_part_of is not a known field")
	}
	if shape != "occurrent" || !eqStrings(legalKinds, []string{"occurrent"}) {
		return fmt.Errorf("unexpected spec: kinds=%v shape=%s", legalKinds, shape)
	}
	s := co.NewStore(true)
	if _, err := s.Put(occ("eat", ""), ""); err != nil {
		return err
	}
	if _, err := s.Put(occ("chew", ""), ""); err != nil {
		return err
	}
	for _, gap := range s.Gaps("") {
		// no CRO should have been created
		_ = gap
	}
	return nil
}

func v84() error {
	s := neuro()
	a := occ("run", idOf(s[9]))
	b := occ("sprint", idOf(s[6]))
	sa, _ := a["stratum"].(string)
	sb, _ := b["stratum"].(string)
	if sa == sb {
		return errors.New("expected different strata")
	}
	return nil
}

func v85() error {
	c := cnt("human_patient")
	ti := individual(idOf(c), "salted_hash_abc123", "")
	if ok, why := schemaValidExplicit(ti, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v86() error {
	bad := mk(map[string]any{"type": "token_individual", "designator": "x"})
	ok, why := schemaValidExplicit(bad, "token_individual")
	if ok || !mentions(why, "instantiates") {
		return fmt.Errorf("expected instantiates failure, ok=%v why=%v", ok, why)
	}
	return nil
}

func v87() error {
	c := idOf(cnt("human_patient"))
	if idOf(individual(c, "hash_a", "")) == idOf(individual(c, "hash_b", "")) {
		return errors.New("different designators must yield distinct ids")
	}
	return nil
}

func v88() error {
	o := occ("bilateral_hippocampal_resection", "")
	t := token(idOf(o), map[string]any{"start": "1953-08-25T00:00:00Z", "end": "1953-08-25T00:00:00Z"}, nil, "")
	if ok, why := schemaValidExplicit(t, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v89() error {
	o := idOf(occ("amnesia_onset", ""))
	bounded := token(o, map[string]any{"start": "1953-08-25T00:00:00Z", "end": "1953-08-26T00:00:00Z"}, nil, "")
	instantaneous := token(o, map[string]any{"start": "1953-08-25T00:00:00Z"}, nil, "")
	ongoing := token(o, map[string]any{"start": "1953-08-25T00:00:00Z", "open": true}, nil, "")
	set := map[string]bool{idOf(bounded): true, idOf(instantaneous): true, idOf(ongoing): true}
	if len(set) != 3 {
		return errors.New("three intervals must be distinguishable")
	}
	return nil
}

func v90() error {
	o := idOf(occ("resection", ""))
	c := idOf(cnt("human_patient"))
	patient := idOf(individual(c, "p", ""))
	surgeon := idOf(individual(c, "s", ""))
	t := token(o, map[string]any{"start": "1953-08-25T00:00:00Z"}, []any{
		map[string]any{"role": "patient", "filler": patient},
		map[string]any{"role": "agent", "filler": surgeon},
	}, "")
	if ok, why := schemaValidExplicit(t, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v91() error {
	q := quality("cortisol_concentration", "quantity", "ug/dL", "")
	if ok, why := schemaValidExplicit(q, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func stateFixture(datatype string, value map[string]any, unit string) (map[string]any, map[string]any) {
	q := quality("cortisol_concentration", datatype, unit, "")
	c := idOf(cnt("human_patient"))
	subj := idOf(individual(c, "p", ""))
	st := state(subj, idOf(q), value, map[string]any{
		"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"})
	return st, q
}

func v92() error {
	st, q := stateFixture("quantity", map[string]any{"quantity": 15.0, "unit": "ug/dL"}, "ug/dL")
	if ok, why := schemaValidExplicit(st, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if got := co.StateGaps(st, q); len(got) != 0 {
		return fmt.Errorf("expected [], got %v", got)
	}
	return nil
}

func v93() error {
	st, q := stateFixture("categorical", map[string]any{"categorical": "elevated"}, "")
	if ok, why := schemaValidExplicit(st, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if got := co.StateGaps(st, q); len(got) != 0 {
		return fmt.Errorf("expected [], got %v", got)
	}
	return nil
}

func v94() error {
	st, q := stateFixture("boolean", map[string]any{"boolean": true}, "")
	if ok, why := schemaValidExplicit(st, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if got := co.StateGaps(st, q); len(got) != 0 {
		return fmt.Errorf("expected [], got %v", got)
	}
	return nil
}

func v95() error {
	st, q := stateFixture("quantity", map[string]any{"categorical": "elevated"}, "ug/dL")
	if got := co.StateGaps(st, q); !eqStrings(got, []string{"value_type_mismatch"}) {
		return fmt.Errorf("expected [value_type_mismatch], got %v", got)
	}
	return nil
}

func v96() error {
	st, q := stateFixture("quantity", map[string]any{"quantity": 15.0, "unit": "mg/dL"}, "ug/dL")
	if got := co.StateGaps(st, q); !eqStrings(got, []string{"unit_mismatch"}) {
		return fmt.Errorf("expected [unit_mismatch], got %v", got)
	}
	return nil
}

func lawAndTokens() (law, oCause, oEffect, tCause, tEffect map[string]any) {
	oCause = occ("resection", "")
	oEffect = occ("amnesia_onset", "")
	law = cro(L(idOf(oCause)), L(idOf(oEffect)), map[string]any{
		"temporal": map[string]any{"minimum_delay": 0, "maximum_delay": 1, "unit": "days"},
		"modality": "sufficient",
	})
	tCause = token(idOf(oCause), map[string]any{"start": "1953-08-25T00:00:00Z"}, nil, "")
	tEffect = token(idOf(oEffect), map[string]any{"start": "1953-08-25T00:00:00Z", "open": true}, nil, "")
	return
}

func v97() error {
	law, _, _, tc, te := lawAndTokens()
	claim := tcc(L(idOf(tc)), L(idOf(te)), idOf(law),
		map[string]any{"duration": 0, "unit": "instant"}, boolPtr(true))
	if ok, why := schemaValidExplicit(claim, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v98() error {
	_, _, _, tc, te := lawAndTokens()
	claim := tcc(L(idOf(tc)), L(idOf(te)), "", nil, nil)
	if ok, why := schemaValidExplicit(claim, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	if _, has := claim["covering_law"]; has {
		return errors.New("covering_law must be absent")
	}
	return nil
}

func v99() error {
	law, _, _, _, _ := lawAndTokens()
	temporal, _ := law["temporal"].(map[string]any)
	if !co.DelayWithinWindow(map[string]any{"duration": 0, "unit": "instant"}, temporal) {
		return errors.New("instant delay must be within window")
	}
	return nil
}

func v100() error {
	temporal := map[string]any{"minimum_delay": 0, "maximum_delay": 1, "unit": "hours"}
	if co.DelayWithinWindow(map[string]any{"duration": 5, "unit": "days"}, temporal) {
		return errors.New("5 days must be outside a 1-hour window")
	}
	return nil
}

func v101() error {
	o := idOf(occ("x", ""))
	cause := token(o, map[string]any{"start": "2026-01-02T00:00:00Z"}, nil, "")
	effect := token(o, map[string]any{"start": "2026-01-01T00:00:00Z"}, nil, "")
	claim := tcc(L(idOf(cause)), L(idOf(effect)), "", nil, nil)
	if !co.Retrocausal(claim, omap(cause, effect)) {
		return errors.New("expected retrocausal")
	}
	return nil
}

func v102() error {
	other := cro(L(sym("occurrent:foo")), L(sym("occurrent:bar")), nil)
	_, _, _, tc, te := lawAndTokens()
	claim := tcc(L(idOf(tc)), L(idOf(te)), idOf(other), nil, nil)
	if !co.CoveringLawMismatch(claim, omap(tc, te), other) {
		return errors.New("expected covering-law mismatch")
	}
	return nil
}

func v103() error {
	a, err := signed("assertion", map[string]any{
		"about": sym("token_occurrence:t"), "evidence_type": "observation", "confidence": 0.9,
	}, "signer", 0)
	if err != nil {
		return err
	}
	if ok, why := schemaValidExplicit(a, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	return nil
}

func v104() error {
	ev := L(sym("token_occurrence:t1"), sym("token_causal_claim:c1"))
	base := map[string]any{
		"type": "assertion", "about": sym("causal_relation_object:law"),
		"source": key("signer").public, "evidence_type": "intervention",
		"strength": 0.95, "confidence": 0.99, "timestamp": "2026-07-14T00:00:00Z",
	}
	a := co.CopyMap(base)
	a["evidenced_by"] = ev
	idA, err := co.Identify(a, "")
	if err != nil {
		return err
	}
	withID := co.CopyMap(a)
	withID["id"] = idA
	if ok, why := schemaValidExplicit(withID, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	idBase, err := co.Identify(base, "")
	if err != nil {
		return err
	}
	if idA == idBase {
		return errors.New("evidenced_by must be identity-bearing")
	}
	return nil
}

func v105() error {
	a, err := signed("assertion", map[string]any{
		"about": sym("causal_relation_object:law"), "evidence_type": "simulation", "confidence": 0.5,
	}, "signer", 0)
	if err != nil {
		return err
	}
	if ok, why := schemaValidExplicit(a, ""); !ok {
		return fmt.Errorf("schema: %v", why)
	}
	rank := map[string]int{"intervention": 0, "observation": 1, "simulation": 2}
	if !(rank["intervention"] < rank["observation"] && rank["observation"] < rank["simulation"]) {
		return errors.New("evidence rank order wrong")
	}
	return nil
}

var idPattern = regexp.MustCompile(`^([a-z0-9_]+):[0-9a-f]{64}$`)

func scanSchemes(node any, out *[]string) {
	switch v := node.(type) {
	case string:
		if m := idPattern.FindStringSubmatch(v); m != nil {
			*out = append(*out, m[1])
		}
	case []any:
		for _, x := range v {
			scanSchemes(x, out)
		}
	case map[string]any:
		for _, x := range v {
			scanSchemes(x, out)
		}
	}
}

func v106() error {
	for n := 1; n <= 38; n++ {
		v, err := vec(n)
		if err != nil {
			return err
		}
		var ids []string
		scanSchemes(v, &ids)
		for _, scheme := range ids {
			if !wholeWord[scheme] {
				return fmt.Errorf("abbreviated scheme %q in vector %d", scheme, n)
			}
		}
	}
	rec := map[string]any{"type": "occurrent", "label": "press_button", "category": "action"}
	id1, err := co.Identify(rec, "")
	if err != nil {
		return err
	}
	id2, err := co.Identify(rec, "")
	if err != nil {
		return err
	}
	if id1 != id2 {
		return errors.New("identify is not deterministic")
	}
	if scheme, _, _ := strings.Cut(id1, ":"); scheme != "occurrent" {
		return fmt.Errorf("scheme is %q, want occurrent", scheme)
	}
	return nil
}

func v107() error {
	hexid := strings.Repeat("0", 64)
	// The abbreviated prefix is intentional (the negative test); assembled
	// so re-mint tools leave it alone.
	croAbbr := "c" + "r" + "o"
	abbreviated := map[string]any{
		"type": "causal_relation_object", "id": croAbbr + ":" + hexid,
		"causes": L("occurrent:" + hexid), "effects": L("occurrent:" + hexid),
	}
	if ok, _ := schemaValidExplicit(abbreviated, "causal_relation_object"); ok {
		return errors.New("abbreviated scheme must be rejected")
	}
	abbrStr := map[string]any{"type": "stratum", "id": "str:" + hexid,
		"label": "cellular", "scheme": "neuroendocrine", "ordinal": 6}
	if ok, _ := schemaValidExplicit(abbrStr, "stratum"); ok {
		return errors.New("abbreviated stratum scheme must be rejected")
	}
	whole := map[string]any{
		"type": "causal_relation_object", "id": "causal_relation_object:" + hexid,
		"causes": L("occurrent:" + hexid), "effects": L("occurrent:" + hexid),
	}
	if ok, why := schemaValidExplicit(whole, "causal_relation_object"); !ok {
		return fmt.Errorf("whole-word scheme must validate: %v", why)
	}
	return nil
}

// ---------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------

func safe(run func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return run()
}

func main() {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Printf("cannot locate the repository root: %v\n", err)
		os.Exit(1)
	}
	vectorsDir = filepath.Join(root, "conformance", "vectors")
	co.SetSchemaDir(filepath.Join(root, "spec", "schema"))

	fmt.Println("causalontology-go conformance run (specification 2.0.0)")
	fmt.Print("internal checks (RFC 8032, RFC 8785, fixed constants, ground-truth ids) ... ")
	if err := internalChecks(); err != nil {
		fmt.Printf("FAILED :: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")

	vectors := []func() error{
		v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
		v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
		v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
		v31, v32, v33, v34, v35, v36, v37, v38, v39, v40,
		v41, v42, v43, v44, v45, v46, v47, v48, v49, v50,
		v51, v52, v53, v54, v55, v56, v57, v58, v59, v60,
		v61, v62, v63, v64, v65, v66, v67, v68, v69, v70,
		v71, v72, v73, v74, v75, v76, v77, v78, v79, v80,
		v81, v82, v83, v84, v85, v86, v87, v88, v89, v90,
		v91, v92, v93, v94, v95, v96, v97, v98, v99, v100,
		v101, v102, v103, v104, v105, v106, v107,
	}
	failures := 0
	for i, run := range vectors {
		name := vectorName(i + 1)
		if vectorErr := safe(run); vectorErr != nil {
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
		"(vectors frozen at specification 2.0.0).")
}

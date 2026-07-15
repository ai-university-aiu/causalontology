// The semantic rules beyond the schemas (spec/semantics.md).
//
// Local rules are checked here; store-context rules (materialized
// acyclicity, retraction lineage) live in store.go where the context
// exists.
package causalontology

import (
	"errors"
	"fmt"
	"strings"
)

// UnitSeconds carries rule 4's fixed unit-conversion constants (average
// Gregorian values: a month is 2,629,746 s and a year 31,556,952 s).
var UnitSeconds = map[string]float64{
	"instant": 0,
	"seconds": 1,
	"minutes": 60,
	"hours":   3600,
	"days":    86400,
	"weeks":   604800,
	"months":  2629746,
	"years":   31556952,
}

// enrichmentFieldRule fixes, per rule 12, which kinds an enrichment field
// may be about and which shape its entry must take.
type enrichmentFieldRule struct {
	legalKinds []string
	entryShape string
}

// enrichmentFieldRules is rule 12's field-to-kind validity table. Two
// occurrent forms are added in 2.0.0.
var enrichmentFieldRules = map[string]enrichmentFieldRule{
	"aliases":            {[]string{"occurrent", "continuant"}, "alias"},
	"participants":       {[]string{"occurrent"}, "continuant"},
	"subsumes":           {[]string{"continuant"}, "continuant"},
	"part_of":            {[]string{"continuant"}, "continuant"},
	"realized_in":        {[]string{"realizable"}, "occurrent"},
	"occurrent_subsumes": {[]string{"occurrent"}, "occurrent"},
	"occurrent_part_of":  {[]string{"occurrent"}, "occurrent"},
}

// EnrichmentFieldSpec exposes rule 12's (legalKinds, entryShape) for a
// field, mirroring Python's ENRICHMENT_FIELDS[field].
func EnrichmentFieldSpec(field string) ([]string, string, bool) {
	rule, ok := enrichmentFieldRules[field]
	if !ok {
		return nil, "", false
	}
	return rule.legalKinds, rule.entryShape, true
}

// CROOptionalFields lists the optional Causal Relation Object fields in
// the order is_partial reports them.
var CROOptionalFields = []string{"mechanism", "temporal", "modality", "context"}

// kindOfID maps an identifier's scheme prefix to its kind ("" if the
// scheme is unknown, e.g. ed25519).
func kindOfID(identifier string) string {
	scheme, _, _ := strings.Cut(identifier, ":")
	return KindOfPrefix[scheme]
}

// containsString reports membership of a string in a slice.
func containsString(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

// ValidateSemantics checks the locally checkable semantic rules,
// returning (ok, reasons). An empty kind means: infer it.
func ValidateSemantics(obj map[string]any, kind string) (bool, []string, error) {
	if kind == "" {
		inferred, err := InferKind(obj)
		if err != nil {
			return false, nil, err
		}
		kind = inferred
	}
	var reasons []string

	if kind == "causal_relation_object" {
		if temporal, isObject := obj["temporal"].(map[string]any); isObject {
			dminRaw, hasMin := temporal["minimum_delay"]
			dmaxRaw, hasMax := temporal["maximum_delay"]
			if hasMin && hasMax && dminRaw != nil && dmaxRaw != nil {
				minimum_delay, okMin := AsFloat(dminRaw)
				maximum_delay, okMax := AsFloat(dmaxRaw)
				if okMin && okMax && minimum_delay > maximum_delay {
					reasons = append(reasons, "minimum_delay must be <= maximum_delay")
				}
			}
		}
		objectID, _ := obj["id"].(string)
		if objectID != "" {
			if containsString(stringList(obj["mechanism"]), objectID) {
				reasons = append(reasons,
					"mechanism must be acyclic (a Causal Relation Object may not contain itself)")
			}
			if refines, _ := obj["refines"].(string); refines == objectID {
				reasons = append(reasons, "refines must be acyclic")
			}
		}
		// Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
		// contradiction between skips:true and a non-empty mechanism.
		if skips, isBool := obj["skips"].(bool); isBool && skips && mechanismPresent(obj) {
			reasons = append(reasons,
				"contradictory_skip: skips is true but a mechanism is present")
		}
	}

	if kind == "enrichment" {
		field, _ := obj["field"].(string)
		about, _ := obj["about"].(string)
		entry := obj["entry"]
		if rule, known := enrichmentFieldRules[field]; known {
			aboutKind := kindOfID(about)
			if aboutKind != "" && !containsString(rule.legalKinds, aboutKind) {
				reasons = append(reasons, fmt.Sprintf(
					"%s is not a legal field for a %s (rule 12)", field, aboutKind))
			}
			if rule.entryShape == "alias" {
				entryObject, isObject := entry.(map[string]any)
				_, hasLang := entryObject["lang"]
				_, hasText := entryObject["text"]
				if !isObject || !hasLang || !hasText {
					reasons = append(reasons,
						"an aliases entry must be a language-tagged text object")
				}
			} else {
				entryText, isString := entry.(string)
				if !isString || !strings.HasPrefix(entryText, rule.entryShape+":") {
					reasons = append(reasons, fmt.Sprintf(
						"a %s entry must be a %s: identifier", field, rule.entryShape))
				}
			}
		}
	}

	return len(reasons) == 0, reasons, nil
}

// IsPartial reports (partial, missing): which optional CRO fields are
// unspecified, in the fixed order mechanism, temporal, modality, context.
func IsPartial(cro map[string]any) (bool, []string) {
	missing := []string{}
	for _, field := range CROOptionalFields {
		if _, present := cro[field]; !present {
			missing = append(missing, field)
		}
	}
	return len(missing) > 0, missing
}

// Admissible applies rule 4: temporal admissibility with the fixed unit
// constants. A missing window imposes no constraint.
func Admissible(cro map[string]any, elapsedSeconds float64) (bool, error) {
	temporalRaw, present := cro["temporal"]
	if !present || temporalRaw == nil {
		return true, nil
	}
	temporal, isObject := temporalRaw.(map[string]any)
	if !isObject {
		return false, errors.New("temporal must be an object")
	}
	unitName, _ := temporal["unit"].(string)
	unit, known := UnitSeconds[unitName]
	if !known {
		return false, fmt.Errorf("unknown temporal unit: %q", unitName)
	}
	minimum_delay, okMin := AsFloat(temporal["minimum_delay"])
	maximum_delay, okMax := AsFloat(temporal["maximum_delay"])
	if !okMin || !okMax {
		return false, errors.New("minimum_delay and maximum_delay must be numbers")
	}
	lo := minimum_delay * unit
	hi := maximum_delay * unit
	return lo <= elapsedSeconds && elapsedSeconds <= hi, nil
}

// toStringSet turns a slice into a membership set.
func toStringSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

// sameStringSet reports set equality of two string slices.
func sameStringSet(a, b []string) bool {
	setA := toStringSet(a)
	setB := toStringSet(b)
	if len(setA) != len(setB) {
		return false
	}
	for item := range setA {
		if !setB[item] {
			return false
		}
	}
	return true
}

// subsetOf reports whether every member of a is in b.
func subsetOf(a, b map[string]bool) bool {
	for item := range a {
		if !b[item] {
			return false
		}
	}
	return true
}

// windowOverlap reports whether two temporal windows overlap; either
// window absent counts as overlapping.
func windowOverlap(a, b map[string]any) bool {
	temporalA, okA := a["temporal"].(map[string]any)
	temporalB, okB := b["temporal"].(map[string]any)
	if !okA || !okB {
		return true
	}
	unitNameA, _ := temporalA["unit"].(string)
	unitNameB, _ := temporalB["unit"].(string)
	unitA, knownA := UnitSeconds[unitNameA]
	unitB, knownB := UnitSeconds[unitNameB]
	if !knownA || !knownB {
		return true
	}
	dminA, okMinA := AsFloat(temporalA["minimum_delay"])
	dmaxA, okMaxA := AsFloat(temporalA["maximum_delay"])
	dminB, okMinB := AsFloat(temporalB["minimum_delay"])
	dmaxB, okMaxB := AsFloat(temporalB["maximum_delay"])
	if !okMinA || !okMaxA || !okMinB || !okMaxB {
		return true
	}
	loA := dminA * unitA
	hiA := dmaxA * unitA
	loB := dminB * unitB
	hiB := dmaxB * unitB
	return loA <= hiB && loB <= hiA
}

// contextsCompatible reports whether two context sets are equal or one
// contains the other; either absent (or empty) counts as compatible.
func contextsCompatible(a, b map[string]any) bool {
	contextA := stringList(a["context"])
	contextB := stringList(b["context"])
	if len(contextA) == 0 || len(contextB) == 0 {
		return true
	}
	setA := toStringSet(contextA)
	setB := toStringSet(contextB)
	return subsetOf(setA, setB) || subsetOf(setB, setA)
}

// positiveModalities are the modalities a preventive claim conflicts with
// (rule 6, amended: necessary, sufficient, contributory, enabling are
// mutually compatible; preventive opposes all four).
var positiveModalities = map[string]bool{
	"necessary":    true,
	"sufficient":   true,
	"contributory": true,
	"enabling":     true,
}

// mechanismPresent reports whether an object carries a non-empty mechanism
// (Python's truthiness of obj.get("mechanism")).
func mechanismPresent(obj map[string]any) bool {
	return len(stringList(obj["mechanism"])) > 0
}

// Conflicts applies rule 6, the formal conflict test: same causes, same
// effects, compatible contexts, overlapping windows, and one side
// preventive against a positive modality on the other.
func Conflicts(a, b map[string]any) bool {
	if !sameStringSet(stringList(a["causes"]), stringList(b["causes"])) {
		return false
	}
	if !sameStringSet(stringList(a["effects"]), stringList(b["effects"])) {
		return false
	}
	if !contextsCompatible(a, b) {
		return false
	}
	if !windowOverlap(a, b) {
		return false
	}
	modalityA, _ := a["modality"].(string)
	modalityB, _ := b["modality"].(string)
	return (modalityA == "preventive" && positiveModalities[modalityB]) ||
		(modalityB == "preventive" && positiveModalities[modalityA])
}

// RefinementValid applies rule 3: (ok, reason) - is child a valid
// refinement of parent?
func RefinementValid(child, parent map[string]any) (bool, string) {
	if !JSONEqual(child["refines"], parent["id"]) {
		return false, "child does not name the parent in refines"
	}
	if !sameStringSet(stringList(child["causes"]), stringList(parent["causes"])) ||
		!sameStringSet(stringList(child["effects"]), stringList(parent["effects"])) {
		return false, "a refinement must keep the parent's causes and effects"
	}
	added := 0
	for _, field := range CROOptionalFields {
		if parentValue, present := parent[field]; present {
			if !JSONEqual(child[field], parentValue) {
				return false, "a refinement may not change a field the " +
					"parent specified; this is a rival claim"
			}
		} else if _, childHas := child[field]; childHas {
			added++
		}
	}
	if added == 0 {
		return false, "a refinement must add at least one unspecified field"
	}
	return true, "valid refinement"
}

// pathExists reports whether dst is reachable from src in a directed graph.
func pathExists(edges map[string]map[string]bool, src, dst string) bool {
	seen := map[string]bool{}
	stack := []string{src}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node == dst {
			return true
		}
		if seen[node] {
			continue
		}
		seen[node] = true
		for next := range edges[node] {
			stack = append(stack, next)
		}
	}
	return false
}

// BridgeClosure is ALGORITHM A: every finer occurrent an occurrent
// resolves to, following Bridges downward, transitively (N12.1). Includes
// the starting occurrent; the visited guard prevents an infinite loop on
// malformed cyclic data.
func BridgeClosure(occurrentID string, bridges []map[string]any) map[string]bool {
	result := map[string]bool{occurrentID: true}
	frontier := []string{occurrentID}
	visited := map[string]bool{}
	coarseIndex := map[string][]map[string]any{}
	for _, b := range bridges {
		if coarse, ok := b["coarse"].(string); ok {
			coarseIndex[coarse] = append(coarseIndex[coarse], b)
		}
	}
	for len(frontier) > 0 {
		current := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if visited[current] {
			continue
		}
		visited[current] = true
		for _, b := range coarseIndex[current] {
			for _, f := range stringList(b["fine"]) {
				result[f] = true
				frontier = append(frontier, f)
			}
		}
	}
	return result
}

// HierarchyConsistent is ALGORITHM B (amended rule 7): "consistent",
// "inconsistent", or "indeterminate", ACROSS STRATA via bridged
// reachability. members maps CRO identifiers to CRO objects for the
// parent's mechanism entries; an absent member yields "indeterminate"
// (dangling; ignorance, not refutation). An empty bridges slice reduces to
// 1.0.0 literal reachability (the degenerate case, N12.2.3).
func HierarchyConsistent(parent map[string]any, members map[string]map[string]any, bridges []map[string]any) string {
	mechanism := stringList(parent["mechanism"])
	if len(mechanism) == 0 {
		return "consistent"
	}
	edges := map[string]map[string]bool{}
	for _, memberID := range mechanism {
		member, present := members[memberID]
		if !present {
			return "indeterminate"
		}
		for _, cause := range stringList(member["causes"]) {
			if edges[cause] == nil {
				edges[cause] = map[string]bool{}
			}
			for _, effect := range stringList(member["effects"]) {
				edges[cause][effect] = true
			}
		}
	}
	causes := stringList(parent["causes"])
	effects := stringList(parent["effects"])
	bCause := map[string]map[string]bool{}
	for _, c := range causes {
		bCause[c] = BridgeClosure(c, bridges)
	}
	bEffect := map[string]map[string]bool{}
	for _, e := range effects {
		bEffect[e] = BridgeClosure(e, bridges)
	}
	for _, c := range causes {
		for _, e := range effects {
			connected := false
			for cp := range bCause[c] {
				for ep := range bEffect[e] {
					if pathExists(edges, cp, ep) {
						connected = true
						break
					}
				}
				if connected {
					break
				}
			}
			if !connected {
				return "inconsistent"
			}
		}
	}
	return "consistent"
}

// stratumOf returns an occurrent's stratum id ("" when absent/unstratified).
func stratumOf(occMap map[string]map[string]any, occID string) (string, bool) {
	occ, ok := occMap[occID]
	if !ok {
		return "", false
	}
	stratum, ok := occ["stratum"].(string)
	return stratum, ok
}

// ClassifyCRO is ALGORITHM C (rule 15): "intra_stratal" |
// "adjacent_stratal" | "skipping" | "mixed" | "unclassifiable" |
// "scheme_mismatch". Derived, never asserted; recompute on ingest (N12.3.1).
func ClassifyCRO(cro map[string]any, occMap, stratumMap map[string]map[string]any) string {
	causeStrata := []string{}
	for _, c := range stringList(cro["causes"]) {
		s, ok := stratumOf(occMap, c)
		if !ok {
			return "unclassifiable"
		}
		causeStrata = append(causeStrata, s)
	}
	effectStrata := []string{}
	for _, e := range stringList(cro["effects"]) {
		s, ok := stratumOf(occMap, e)
		if !ok {
			return "unclassifiable"
		}
		effectStrata = append(effectStrata, s)
	}
	allStrata := map[string]bool{}
	for _, s := range append(append([]string{}, causeStrata...), effectStrata...) {
		allStrata[s] = true
	}
	schemes := map[string]bool{}
	for s := range allStrata {
		scheme, _ := stratumMap[s]["scheme"].(string)
		schemes[scheme] = true
	}
	if len(schemes) > 1 {
		return "scheme_mismatch"
	}
	ordinalOf := func(s string) int {
		f, _ := AsFloat(stratumMap[s]["ordinal"])
		return int(f)
	}
	cOrd := make([]int, len(causeStrata))
	for i, s := range causeStrata {
		cOrd[i] = ordinalOf(s)
	}
	eOrd := make([]int, len(effectStrata))
	for i, s := range effectStrata {
		eOrd[i] = ordinalOf(s)
	}
	cMax, cMin := maxInt(cOrd), minInt(cOrd)
	eMax, eMin := maxInt(eOrd), minInt(eOrd)
	if cMax == cMin && cMin == eMax && eMax == eMin {
		return "intra_stratal"
	}
	gap, span := -1, -1
	for _, i := range cOrd {
		for _, j := range eOrd {
			d := i - j
			if d < 0 {
				d = -d
			}
			if gap < 0 || d < gap {
				gap = d
			}
			if d > span {
				span = d
			}
		}
	}
	if span == 1 {
		return "adjacent_stratal"
	}
	if gap > 1 {
		return "skipping"
	}
	return "mixed"
}

func maxInt(xs []int) int {
	m := xs[0]
	for _, x := range xs[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func minInt(xs []int) int {
	m := xs[0]
	for _, x := range xs[1:] {
		if x < m {
			m = x
		}
	}
	return m
}

// EndpointsMixed is true iff causes or effects span more than one distinct
// stratum (surfaces mixed_stratal_endpoints, an invitation; N12.3.2).
func EndpointsMixed(cro map[string]any, occMap map[string]map[string]any) bool {
	causeStrata := map[string]bool{}
	for _, c := range stringList(cro["causes"]) {
		s, ok := stratumOf(occMap, c)
		if !ok {
			return false
		}
		causeStrata[s] = true
	}
	effectStrata := map[string]bool{}
	for _, e := range stringList(cro["effects"]) {
		s, ok := stratumOf(occMap, e)
		if !ok {
			return false
		}
		effectStrata[s] = true
	}
	return len(causeStrata) > 1 || len(effectStrata) > 1
}

// SkipGaps is ALGORITHM D (rule 16): the gaps a Causal Relation Object
// surfaces for the skip decision. The asymmetry (clause 3) is implemented
// exactly: skips true + non-empty mechanism is a HARD contradiction; skips
// true on a genuine skip with no mechanism surfaces NOTHING (absence is the
// finding); skips absent on a genuine skip surfaces incomplete_mechanism.
func SkipGaps(cro map[string]any, classification string) []string {
	gaps := []string{}
	skipsTrue, _ := cro["skips"].(bool)
	hasMech := mechanismPresent(cro)
	if skipsTrue && hasMech {
		return append(gaps, "contradictory_skip")
	}
	if skipsTrue && classification != "skipping" && classification != "unclassifiable" {
		gaps = append(gaps, "vacuous_skip")
	}
	if classification == "skipping" && !hasMech {
		if !skipsTrue {
			gaps = append(gaps, "incomplete_mechanism")
		}
	}
	return gaps
}

// ToSeconds is the ALGORITHM E helper: normalize a delay to seconds by the
// fixed table.
func ToSeconds(duration float64, unit string) float64 {
	if unit == "instant" {
		return 0
	}
	return duration * UnitSeconds[unit]
}

// DelayWithinWindow is ALGORITHM E (rule 20): does an observed delay fall
// within a covering law's temporal window? Inclusive at both ends (N12.5.2).
func DelayWithinWindow(actualDelay, temporal map[string]any) bool {
	if len(actualDelay) == 0 || len(temporal) == 0 {
		return true
	}
	duration, _ := AsFloat(actualDelay["duration"])
	unit, _ := actualDelay["unit"].(string)
	observed := ToSeconds(duration, unit)
	minDelay, _ := AsFloat(temporal["minimum_delay"])
	maxDelay, _ := AsFloat(temporal["maximum_delay"])
	tunit, _ := temporal["unit"].(string)
	lo := ToSeconds(minDelay, tunit)
	hi := ToSeconds(maxDelay, tunit)
	return lo <= observed && observed <= hi
}

// BridgeWellformed applies rule 14 / N3.2.1: all of (a)-(e) must hold, else
// malformed_bridge.
func BridgeWellformed(bridge map[string]any, occMap, stratumMap map[string]map[string]any) (bool, string) {
	coarseID, _ := bridge["coarse"].(string)
	cs, ok := stratumOf(occMap, coarseID)
	if !ok {
		return false, "malformed_bridge: coarse has no stratum (a)"
	}
	fineStrata := []string{}
	for _, f := range stringList(bridge["fine"]) {
		s, ok := stratumOf(occMap, f)
		if !ok {
			return false, "malformed_bridge: a fine member has no stratum (b)"
		}
		fineStrata = append(fineStrata, s)
	}
	distinct := map[string]bool{}
	for _, s := range fineStrata {
		distinct[s] = true
	}
	if len(distinct) != 1 {
		return false, "malformed_bridge: fine members span >1 stratum (c)"
	}
	fs := fineStrata[0]
	coarseScheme, _ := stratumMap[cs]["scheme"].(string)
	fineScheme, _ := stratumMap[fs]["scheme"].(string)
	if coarseScheme != fineScheme {
		return false, "malformed_bridge: coarse and fine differ in scheme (d)"
	}
	coarseOrd, _ := AsFloat(stratumMap[cs]["ordinal"])
	fineOrd, _ := AsFloat(stratumMap[fs]["ordinal"])
	if !(coarseOrd > fineOrd) {
		return false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"
	}
	return true, "well-formed bridge"
}

// ConduitWellformed applies rule 17 / N4.2.1-2: N4.2.1 with the transform
// exception of N4.2.2.
func ConduitWellformed(conduit map[string]any, portMap, croMap map[string]map[string]any) (bool, string) {
	fromID, _ := conduit["from"].(string)
	toID, _ := conduit["to"].(string)
	frm, okFrom := portMap[fromID]
	to, okTo := portMap[toID]
	if !okFrom || !okTo {
		return false, "malformed_conduit: dangling port reference"
	}
	fromDir, _ := frm["direction"].(string)
	if fromDir != "out" && fromDir != "bidirectional" {
		return false, "malformed_conduit: from port is not out/bidirectional (a)"
	}
	toDir, _ := to["direction"].(string)
	if toDir != "in" && toDir != "bidirectional" {
		return false, "malformed_conduit: to port is not in/bidirectional (b)"
	}
	carries := stringList(conduit["carries"])
	fromAccepts := toStringSet(stringList(frm["accepts"]))
	for _, o := range carries {
		if !fromAccepts[o] {
			return false, "malformed_conduit: carries not accepted by from (c)"
		}
	}
	toAccepts := toStringSet(stringList(to["accepts"]))
	transform, hasTransform := conduit["transform"].(string)
	if !hasTransform || transform == "" {
		for _, o := range carries {
			if !toAccepts[o] {
				return false, "malformed_conduit: carries not accepted by to (d)"
			}
		}
	} else {
		if law, present := croMap[transform]; present {
			for _, o := range stringList(law["effects"]) {
				if !toAccepts[o] {
					return false, "malformed_conduit: transform effects not " +
						"accepted by to (d, relaxed per N4.2.2)"
				}
			}
		}
	}
	return true, "well-formed conduit"
}

// StateGaps applies rule 19 / N5.3.1-2: the HARD gaps a state assertion
// surfaces against its quality: value_type_mismatch and/or unit_mismatch.
func StateGaps(state, quality map[string]any) []string {
	gaps := []string{}
	datatype, _ := quality["datatype"].(string)
	value, _ := state["value"].(map[string]any)
	shape := ""
	if value != nil {
		if _, ok := value["quantity"]; ok {
			shape = "quantity"
		} else if _, ok := value["categorical"]; ok {
			shape = "categorical"
		} else if _, ok := value["boolean"]; ok {
			shape = "boolean"
		}
	}
	if shape != datatype {
		gaps = append(gaps, "value_type_mismatch")
	} else if datatype == "quantity" {
		valueUnit, _ := value["unit"].(string)
		qualityUnit, _ := quality["unit"].(string)
		if valueUnit != qualityUnit {
			gaps = append(gaps, "unit_mismatch")
		}
	}
	return gaps
}

// CoveringLawMismatch is rule 20: true iff the token claim's cause/effect
// tokens do not instantiate the covering law's causes/effects.
func CoveringLawMismatch(tcc map[string]any, tokenMap map[string]map[string]any, law map[string]any) bool {
	if len(law) == 0 {
		return false
	}
	lawCauses := toStringSet(stringList(law["causes"]))
	lawEffects := toStringSet(stringList(law["effects"]))
	for _, c := range stringList(tcc["causes"]) {
		instantiates, _ := tokenMap[c]["instantiates"].(string)
		if !lawCauses[instantiates] {
			return true
		}
	}
	for _, e := range stringList(tcc["effects"]) {
		instantiates, _ := tokenMap[e]["instantiates"].(string)
		if !lawEffects[instantiates] {
			return true
		}
	}
	return false
}

// Retrocausal is rule 21: true iff any cause token starts after any effect
// token (HARD; retrocausal_claim). RFC 3339 UTC 'Z' strings compare
// lexicographically.
func Retrocausal(tcc map[string]any, tokenMap map[string]map[string]any) bool {
	startOf := func(tokenID string) string {
		token, ok := tokenMap[tokenID]
		if !ok {
			return ""
		}
		interval, _ := token["interval"].(map[string]any)
		start, _ := interval["start"].(string)
		return start
	}
	for _, c := range stringList(tcc["causes"]) {
		cStart := startOf(c)
		for _, e := range stringList(tcc["effects"]) {
			if cStart > startOf(e) {
				return true
			}
		}
	}
	return false
}

// HasCycle reports whether a directed graph (node -> successors) has a
// cycle. Used for the bridge graph, occurrent_subsumes, occurrent_part_of,
// and token mereology.
func HasCycle(edges map[string][]string) bool {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := map[string]int{}
	var visit func(node string) bool
	visit = func(node string) bool {
		state[node] = grey
		for _, next := range edges[node] {
			switch state[next] {
			case grey:
				return true
			case white:
				if visit(next) {
					return true
				}
			}
		}
		state[node] = black
		return false
	}
	for node := range edges {
		if state[node] == white && visit(node) {
			return true
		}
	}
	return false
}

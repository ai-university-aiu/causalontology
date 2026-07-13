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

// enrichmentFieldRules is rule 12's field-to-kind validity table.
var enrichmentFieldRules = map[string]enrichmentFieldRule{
	"aliases":      {[]string{"occurrent", "continuant"}, "alias"},
	"participants": {[]string{"occurrent"}, "cnt"},
	"subsumes":     {[]string{"continuant"}, "cnt"},
	"part_of":      {[]string{"continuant"}, "cnt"},
	"realized_in":  {[]string{"realizable"}, "occ"},
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

	if kind == "cro" {
		if temporal, isObject := obj["temporal"].(map[string]any); isObject {
			dminRaw, hasMin := temporal["dmin"]
			dmaxRaw, hasMax := temporal["dmax"]
			if hasMin && hasMax && dminRaw != nil && dmaxRaw != nil {
				dmin, okMin := AsFloat(dminRaw)
				dmax, okMax := AsFloat(dmaxRaw)
				if okMin && okMax && dmin > dmax {
					reasons = append(reasons, "dmin must be <= dmax")
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
	dmin, okMin := AsFloat(temporal["dmin"])
	dmax, okMax := AsFloat(temporal["dmax"])
	if !okMin || !okMax {
		return false, errors.New("dmin and dmax must be numbers")
	}
	lo := dmin * unit
	hi := dmax * unit
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
	dminA, okMinA := AsFloat(temporalA["dmin"])
	dmaxA, okMaxA := AsFloat(temporalA["dmax"])
	dminB, okMinB := AsFloat(temporalB["dmin"])
	dmaxB, okMaxB := AsFloat(temporalB["dmax"])
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

// positiveModalities are the modalities a preventive claim conflicts with.
var positiveModalities = map[string]bool{
	"necessary":    true,
	"sufficient":   true,
	"contributory": true,
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

// HierarchyConsistent applies rule 7 and returns "consistent",
// "inconsistent", or "indeterminate". members maps CRO identifiers to CRO
// objects for the parent's mechanism entries (the store's view of them);
// an absent member is a dangling_reference gap, not a failure.
func HierarchyConsistent(parent map[string]any, members map[string]map[string]any) string {
	mechanism := stringList(parent["mechanism"])
	if len(mechanism) == 0 {
		return "consistent"
	}
	edges := map[string][]string{}
	for _, memberID := range mechanism {
		member, present := members[memberID]
		if !present {
			return "indeterminate"
		}
		effects := stringList(member["effects"])
		for _, cause := range stringList(member["causes"]) {
			edges[cause] = append(edges[cause], effects...)
		}
	}
	reachable := func(src, dst string) bool {
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
			stack = append(stack, edges[node]...)
		}
		return false
	}
	for _, cause := range stringList(parent["causes"]) {
		for _, effect := range stringList(parent["effects"]) {
			if !reachable(cause, effect) {
				return "inconsistent"
			}
		}
	}
	return "consistent"
}

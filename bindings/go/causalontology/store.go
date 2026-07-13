// An in-memory conformant store.
//
// Implements the store side of the abstract operation set (spec/store.md):
// immutable content objects with idempotent put; signed, add-only
// provenance records; materialized enrichment views with contributors;
// retraction handling in default views; succession lineage; the resolve
// minimum; the deterministic cycle-breaking view rule; and the stigmergy
// gap read. A faithful port of the Python binding's store.py; because Go
// maps iterate in random order, insertion order is kept explicitly in
// side slices, exactly where Python relies on dict insertion order.
package causalontology

import (
	"errors"
	"fmt"
	"strings"
)

// RejectedWrite is the error an enforcing store returns when it refuses a
// write; the reason is the message.
type RejectedWrite struct {
	Reason string
}

// Error returns the rejection reason.
func (e *RejectedWrite) Error() string {
	return e.Reason
}

// ContentKinds names the four immutable content object kinds.
var ContentKinds = map[string]bool{
	"occurrent":  true,
	"cro":        true,
	"continuant": true,
	"realizable": true,
}

// RecordKinds names the four signed provenance record kinds.
var RecordKinds = map[string]bool{
	"assertion":  true,
	"enrichment": true,
	"retraction": true,
	"succession": true,
}

// taxonomyEdge is one about -> entry edge with its carrying record.
type taxonomyEdge struct {
	target string
	record map[string]any
}

// Store is the in-memory conformant store.
type Store struct {
	// Enforcing stores reject cycle-completing taxonomy writes up front.
	Enforcing bool
	// objects maps id -> content object; objectOrder keeps insertion order.
	objects     map[string]map[string]any
	objectOrder []string
	// records maps id -> provenance record; recordOrder keeps insertion order.
	records     map[string]map[string]any
	recordOrder []string
	// Quarantine holds unsigned / unverifiable records by id.
	Quarantine map[string]map[string]any
}

// NewStore builds an empty store.
func NewStore(enforcing bool) *Store {
	return &Store{
		Enforcing:  enforcing,
		objects:    map[string]map[string]any{},
		records:    map[string]map[string]any{},
		Quarantine: map[string]map[string]any{},
	}
}

// ObjectCount reports how many content objects the store holds.
func (s *Store) ObjectCount() int {
	return len(s.objects)
}

// Put writes a content object; idempotent; returns the identifier. An
// empty kind means: infer it.
func (s *Store) Put(object map[string]any, kind string) (string, error) {
	if kind == "" {
		inferred, err := InferKind(object)
		if err != nil {
			return "", err
		}
		kind = inferred
	}
	if !ContentKinds[kind] {
		return "", errors.New("Put() takes content objects; use PutRecord()")
	}
	obj := CopyMap(object)
	if _, present := obj["type"]; !present {
		obj["type"] = kind
	}
	if _, present := obj["id"]; !present {
		id, err := Identify(obj, kind)
		if err != nil {
			return "", err
		}
		obj["id"] = id
	}
	objectID, isString := obj["id"].(string)
	if !isString {
		return "", errors.New("object id must be a string")
	}
	if _, exists := s.objects[objectID]; exists {
		// Immutable: identical identity is a no-op.
		return objectID, nil
	}
	schemaOK, schemaWhy, err := ValidateSchema(obj, kind)
	if err != nil {
		return "", err
	}
	if !schemaOK {
		return "", &RejectedWrite{strings.Join(schemaWhy, "; ")}
	}
	semanticsOK, semanticsWhy, err := ValidateSemantics(obj, kind)
	if err != nil {
		return "", err
	}
	if !semanticsOK {
		return "", &RejectedWrite{strings.Join(semanticsWhy, "; ")}
	}
	s.objects[objectID] = obj
	s.objectOrder = append(s.objectOrder, objectID)
	return objectID, nil
}

// PutRecord writes a signed provenance record; returns the identifier.
// An empty kind means: infer it.
func (s *Store) PutRecord(record map[string]any, kind string) (string, error) {
	return s.writeRecord(record, kind, false)
}

// ForceMergeRecord simulates a decentralized replica merge (no
// enforcement gate).
func (s *Store) ForceMergeRecord(record map[string]any, kind string) (string, error) {
	return s.writeRecord(record, kind, true)
}

// writeRecord is the shared body of PutRecord and ForceMergeRecord.
func (s *Store) writeRecord(record map[string]any, kind string, force bool) (string, error) {
	if kind == "" {
		inferred, err := InferKind(record)
		if err != nil {
			return "", err
		}
		kind = inferred
	}
	if !RecordKinds[kind] {
		return "", errors.New("PutRecord() takes provenance records")
	}
	rec := CopyMap(record)
	if _, present := rec["type"]; !present {
		rec["type"] = kind
	}
	recordID, _ := rec["id"].(string)
	if recordID == "" {
		id, err := Identify(rec, kind)
		if err != nil {
			return "", err
		}
		recordID = id
	}
	rec["id"] = recordID
	if _, exists := s.records[recordID]; exists {
		// Add-only and idempotent.
		return recordID, nil
	}
	if !VerifyRecord(rec, kind) {
		s.Quarantine[recordID] = rec
		return "", &RejectedWrite{"unsigned or unverifiable record: quarantined"}
	}
	semanticsOK, semanticsWhy, err := ValidateSemantics(rec, kind)
	if err != nil {
		return "", err
	}
	if !semanticsOK {
		return "", &RejectedWrite{strings.Join(semanticsWhy, "; ")}
	}
	if kind == "retraction" && !s.retractionSourceOk(rec) {
		return "", &RejectedWrite{"a retraction is valid only from the retracted " +
			"record's source or its succession lineage"}
	}
	if kind == "enrichment" && s.Enforcing && !force {
		field, _ := rec["field"].(string)
		if (field == "subsumes" || field == "part_of") && s.wouldCycle(rec) {
			return "", &RejectedWrite{fmt.Sprintf(
				"would create a cycle in the materialized %s graph", field)}
		}
	}
	s.records[recordID] = rec
	s.recordOrder = append(s.recordOrder, recordID)
	return recordID, nil
}

// recordsOf returns all stored records of one kind, in insertion order.
func (s *Store) recordsOf(kind string) []map[string]any {
	out := []map[string]any{}
	for _, recordID := range s.recordOrder {
		rec := s.records[recordID]
		if typeName, _ := rec["type"].(string); typeName == kind {
			out = append(out, rec)
		}
	}
	return out
}

// retractedIds collects the ids named by every stored retraction.
func (s *Store) retractedIds() map[string]bool {
	out := map[string]bool{}
	for _, rec := range s.recordsOf("retraction") {
		if target, isString := rec["retracts"].(string); isString {
			out[target] = true
		}
	}
	return out
}

// retractionSourceOk reports whether the retraction's source lies in the
// lineage of the retracted record's source; open world: an absent target
// may arrive later.
func (s *Store) retractionSourceOk(retraction map[string]any) bool {
	targetID, _ := retraction["retracts"].(string)
	target, present := s.records[targetID]
	if !present {
		return true
	}
	retractionSource, _ := retraction["source"].(string)
	targetSource, _ := target["source"].(string)
	return s.Lineage(targetSource)[retractionSource]
}

// Lineage returns the succession chain closure containing key (includes
// key itself).
func (s *Store) Lineage(key string) map[string]bool {
	successorOf := map[string]string{}
	predecessorOf := map[string]string{}
	for _, rec := range s.recordsOf("succession") {
		predecessor, okPredecessor := rec["predecessor"].(string)
		successor, okSuccessor := rec["successor"].(string)
		if okPredecessor && okSuccessor {
			successorOf[predecessor] = successor
			predecessorOf[successor] = predecessor
		}
	}
	chain := map[string]bool{key: true}
	cursor := key
	for {
		previous, present := predecessorOf[cursor]
		if !present || chain[previous] {
			break
		}
		chain[previous] = true
		cursor = previous
	}
	cursor = key
	for {
		next, present := successorOf[cursor]
		if !present || chain[next] {
			break
		}
		chain[next] = true
		cursor = next
	}
	return chain
}

// AssertionsAbout returns the assertions about an identifier; retracted
// ones are excluded by default, or included with a retracted flag when
// includeRetracted is set.
func (s *Store) AssertionsAbout(identifier string, includeRetracted bool) []map[string]any {
	retracted := s.retractedIds()
	out := []map[string]any{}
	for _, rec := range s.recordsOf("assertion") {
		if about, _ := rec["about"].(string); about != identifier {
			continue
		}
		recordID, _ := rec["id"].(string)
		if retracted[recordID] {
			if includeRetracted {
				marked := CopyMap(rec)
				marked["retracted"] = true
				out = append(out, marked)
			}
			continue
		}
		out = append(out, rec)
	}
	return out
}

// EnrichmentsAbout returns the enrichments about an identifier; retracted
// ones are excluded unless includeRetracted is set.
func (s *Store) EnrichmentsAbout(identifier string, includeRetracted bool) []map[string]any {
	retracted := s.retractedIds()
	out := []map[string]any{}
	for _, rec := range s.recordsOf("enrichment") {
		if about, _ := rec["about"].(string); about != identifier {
			continue
		}
		recordID, _ := rec["id"].(string)
		if retracted[recordID] && !includeRetracted {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// ActiveTaxonomyEdges returns (active, excluded) for subsumes/part_of
// after the rule 13 deterministic cycle-breaking: while a cycle exists,
// exclude the cycle record with the LATEST timestamp, ties broken by the
// lexicographically greatest record identifier (Python's max((ts, id))).
func (s *Store) ActiveTaxonomyEdges(field string) ([]map[string]any, []map[string]any) {
	retracted := s.retractedIds()
	active := []map[string]any{}
	for _, rec := range s.recordsOf("enrichment") {
		if fieldName, _ := rec["field"].(string); fieldName != field {
			continue
		}
		if recordID, _ := rec["id"].(string); retracted[recordID] {
			continue
		}
		active = append(active, rec)
	}
	excluded := []map[string]any{}
	for {
		cycle := findCycleRecords(active)
		if len(cycle) == 0 {
			break
		}
		loser := cycle[0]
		for _, candidate := range cycle[1:] {
			if taxonomyKeyLess(loser, candidate) {
				loser = candidate
			}
		}
		loserID, _ := loser["id"].(string)
		removed := false
		for i, rec := range active {
			if recordID, _ := rec["id"].(string); recordID == loserID {
				active = append(active[:i], active[i+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			// Defensive: the loser always comes from the active list.
			break
		}
		excluded = append(excluded, loser)
	}
	return active, excluded
}

// taxonomyKeyLess orders records by (timestamp, id), the cycle-breaking
// sort key.
func taxonomyKeyLess(a, b map[string]any) bool {
	timestampA, _ := a["timestamp"].(string)
	timestampB, _ := b["timestamp"].(string)
	if timestampA != timestampB {
		return timestampA < timestampB
	}
	idA, _ := a["id"].(string)
	idB, _ := b["id"].(string)
	return idA < idB
}

// findCycleRecords returns the records forming a cycle in the
// about -> entry graph, or nil when the graph is acyclic. As in the
// Python binding, the returned list is the DFS path up to and including
// the closing edge, discovered in record insertion order.
func findCycleRecords(recs []map[string]any) []map[string]any {
	edges := map[string][]taxonomyEdge{}
	nodeOrder := []string{}
	for _, rec := range recs {
		about, okAbout := rec["about"].(string)
		entry, okEntry := rec["entry"].(string)
		if !okAbout || !okEntry {
			continue
		}
		if _, present := edges[about]; !present {
			nodeOrder = append(nodeOrder, about)
		}
		edges[about] = append(edges[about], taxonomyEdge{entry, rec})
	}
	// state: 0 (absent) = unvisited, 1 = on the current path, 2 = finished.
	state := map[string]int{}
	var cycle []map[string]any
	var dfs func(node string, pathRecords []map[string]any) bool
	dfs = func(node string, pathRecords []map[string]any) bool {
		state[node] = 1
		for _, edge := range edges[node] {
			if state[edge.target] == 1 {
				cycle = append(append([]map[string]any{}, pathRecords...), edge.record)
				return true
			}
			if state[edge.target] == 0 {
				extended := append(append([]map[string]any{}, pathRecords...), edge.record)
				if dfs(edge.target, extended) {
					return true
				}
			}
		}
		state[node] = 2
		return false
	}
	for _, start := range nodeOrder {
		if state[start] == 0 && dfs(start, nil) {
			return cycle
		}
	}
	return nil
}

// wouldCycle reports whether adding the record would close a cycle among
// the active (unretracted) records of the same field.
func (s *Store) wouldCycle(record map[string]any) bool {
	retracted := s.retractedIds()
	targetField, _ := record["field"].(string)
	recs := []map[string]any{}
	for _, rec := range s.recordsOf("enrichment") {
		if fieldName, _ := rec["field"].(string); fieldName != targetField {
			continue
		}
		if recordID, _ := rec["id"].(string); retracted[recordID] {
			continue
		}
		recs = append(recs, rec)
	}
	recs = append(recs, record)
	return len(findCycleRecords(recs)) > 0
}

// enrichmentBucket accumulates one deduplicated (field, entry) view slot.
type enrichmentBucket struct {
	entry        any
	contributors []any
}

// Get returns the object with its materialized enrichment sets and
// contributors, or nil when the object is absent. Views: "default"
// (retractions and cycle-broken edges excluded), "history" (everything
// included), "raw" (the bare object).
func (s *Store) Get(identifier, view string) map[string]any {
	obj, exists := s.objects[identifier]
	if !exists {
		return nil
	}
	if view == "raw" {
		return map[string]any{"object": obj}
	}
	includeRetracted := view == "history"
	excludedIDs := map[string]bool{}
	for _, field := range []string{"subsumes", "part_of"} {
		_, excluded := s.ActiveTaxonomyEdges(field)
		for _, rec := range excluded {
			if recordID, isString := rec["id"].(string); isString {
				excludedIDs[recordID] = true
			}
		}
	}
	fieldOrder := []string{}
	bucketOrder := map[string][]string{}
	buckets := map[string]map[string]*enrichmentBucket{}
	for _, rec := range s.EnrichmentsAbout(identifier, includeRetracted) {
		recordID, _ := rec["id"].(string)
		if excludedIDs[recordID] && view != "history" {
			continue
		}
		field, _ := rec["field"].(string)
		entry := rec["entry"]
		// The (field, entry) dedup key: the canonical bytes of the entry.
		entryKey, err := SerializeJCS(entry)
		if err != nil {
			entryKey = fmt.Sprintf("!%v", entry)
		}
		if _, present := buckets[field]; !present {
			buckets[field] = map[string]*enrichmentBucket{}
			fieldOrder = append(fieldOrder, field)
		}
		slot, present := buckets[field][entryKey]
		if !present {
			slot = &enrichmentBucket{entry: entry}
			buckets[field][entryKey] = slot
			bucketOrder[field] = append(bucketOrder[field], entryKey)
		}
		slot.contributors = append(slot.contributors, map[string]any{
			"source":    rec["source"],
			"timestamp": rec["timestamp"],
		})
	}
	enrichments := map[string]any{}
	for _, field := range fieldOrder {
		entries := []any{}
		for _, entryKey := range bucketOrder[field] {
			slot := buckets[field][entryKey]
			entries = append(entries, map[string]any{
				"entry":        slot.entry,
				"contributors": slot.contributors,
			})
		}
		enrichments[field] = entries
	}
	return map[string]any{"object": obj, "enrichments": enrichments}
}

// canonLabel is the canonical-label form of free text: lowercase,
// whitespace runs collapsed to single underscores.
func canonLabel(text string) string {
	return strings.Join(strings.Fields(strings.ToLower(text)), "_")
}

// normAlias is the alias-normal form of free text: whitespace runs
// collapsed to single spaces, case-insensitive.
func normAlias(text string) string {
	return strings.ToLower(strings.Join(strings.Fields(text), " "))
}

// Resolve is the conformance minimum: exact label, then alias, then
// nothing; label hits rank before alias hits. An empty lang means: do
// not filter aliases by language.
func (s *Store) Resolve(text, lang string) []string {
	labelHits := []string{}
	aliasHits := []string{}
	wantedLabel := canonLabel(text)
	wantedAlias := normAlias(text)
	retracted := s.retractedIds()
	for _, objectID := range s.objectOrder {
		obj := s.objects[objectID]
		typeName, _ := obj["type"].(string)
		if typeName != "occurrent" && typeName != "continuant" {
			continue
		}
		if label, isString := obj["label"].(string); isString && label == wantedLabel {
			labelHits = append(labelHits, objectID)
			continue
		}
		for _, rec := range s.recordsOf("enrichment") {
			if about, _ := rec["about"].(string); about != objectID {
				continue
			}
			if field, _ := rec["field"].(string); field != "aliases" {
				continue
			}
			if recordID, _ := rec["id"].(string); retracted[recordID] {
				continue
			}
			entry, isObject := rec["entry"].(map[string]any)
			if !isObject {
				continue
			}
			if lang != "" {
				if entryLang, _ := entry["lang"].(string); entryLang != lang {
					continue
				}
			}
			aliasText, _ := entry["text"].(string)
			if normAlias(aliasText) == wantedAlias {
				aliasHits = append(aliasHits, objectID)
				break
			}
		}
	}
	return append(labelHits, aliasHits...)
}

// Gaps is the stigmergy read; gap kinds per spec/store.md. A non-empty
// kind filters the list.
func (s *Store) Gaps(kind string) []map[string]any {
	out := []map[string]any{}
	// The parents closed by a valid refinement in the store.
	refined := map[string]bool{}
	for _, objectID := range s.objectOrder {
		obj := s.objects[objectID]
		if typeName, _ := obj["type"].(string); typeName != "cro" {
			continue
		}
		refines, _ := obj["refines"].(string)
		if refines == "" {
			continue
		}
		parent, present := s.objects[refines]
		if !present {
			continue
		}
		if ok, _ := RefinementValid(obj, parent); ok {
			if parentID, isString := parent["id"].(string); isString {
				refined[parentID] = true
			}
		}
	}
	for _, objectID := range s.objectOrder {
		obj := s.objects[objectID]
		if typeName, _ := obj["type"].(string); typeName != "cro" {
			continue
		}
		// missing_field: lacking the temporal window or the modality -
		// mechanism and context may legitimately stay unspecified forever
		// (empty_mechanism is its own kind; absent context = context-free).
		_, hasTemporal := obj["temporal"]
		_, hasModality := obj["modality"]
		if (!hasTemporal || !hasModality) && !refined[objectID] {
			_, missing := IsPartial(obj)
			missingAny := make([]any, 0, len(missing))
			for _, field := range missing {
				missingAny = append(missingAny, field)
			}
			out = append(out, map[string]any{
				"id": objectID, "kind": "missing_field", "missing": missingAny,
			})
		}
		mechanismRaw, hasMechanism := obj["mechanism"]
		mechanismEmpty := !hasMechanism
		if hasMechanism {
			if list, isList := mechanismRaw.([]any); isList && len(list) == 0 {
				mechanismEmpty = true
			}
		}
		if mechanismEmpty && !refined[objectID] {
			out = append(out, map[string]any{"id": objectID, "kind": "empty_mechanism"})
		}
	}
	for _, field := range []string{"subsumes", "part_of"} {
		_, excluded := s.ActiveTaxonomyEdges(field)
		for _, rec := range excluded {
			out = append(out, map[string]any{
				"id":   rec["id"],
				"kind": "inconsistent_hierarchy",
				"note": "excluded by the deterministic cycle-breaking view rule",
			})
		}
	}
	// dangling_reference: a reference to an object absent from the store -
	// the red link that says "this page is wanted".
	for _, objectID := range s.objectOrder {
		obj := s.objects[objectID]
		typeName, _ := obj["type"].(string)
		refs := []string{}
		if typeName == "cro" {
			for _, fieldName := range []string{"causes", "effects", "context", "mechanism"} {
				refs = append(refs, stringList(obj[fieldName])...)
			}
			if refines, _ := obj["refines"].(string); refines != "" {
				refs = append(refs, refines)
			}
		} else if typeName == "realizable" {
			if bearer, _ := obj["bearer"].(string); bearer != "" {
				refs = append(refs, bearer)
			}
		}
		for _, ref := range refs {
			if _, present := s.objects[ref]; ref != "" && !present {
				out = append(out, map[string]any{
					"id": objectID, "kind": "dangling_reference", "ref": ref,
				})
			}
		}
	}
	// conflict: pairs of claims satisfying the formal test (rule 6).
	cros := []map[string]any{}
	for _, objectID := range s.objectOrder {
		obj := s.objects[objectID]
		if typeName, _ := obj["type"].(string); typeName == "cro" {
			cros = append(cros, obj)
		}
	}
	for i := 0; i < len(cros); i++ {
		for j := i + 1; j < len(cros); j++ {
			if Conflicts(cros[i], cros[j]) {
				out = append(out, map[string]any{
					"kind": "conflict", "a": cros[i]["id"], "b": cros[j]["id"],
				})
			}
		}
	}
	if kind != "" {
		filtered := []map[string]any{}
		for _, gap := range out {
			if gapKind, _ := gap["kind"].(string); gapKind == kind {
				filtered = append(filtered, gap)
			}
		}
		out = filtered
	}
	return out
}

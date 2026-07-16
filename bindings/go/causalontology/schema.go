// Schema validation against spec/schema/*.schema.json.
//
// A deliberately small interpreter for exactly the JSON Schema keywords
// the eight Causalontology schemas use: type, const, enum, pattern,
// required, properties, additionalProperties, items, minItems, minLength,
// minimum, maximum, oneOf, and local $ref (#/$defs/...). "format" is
// treated as an annotation, as the 2020-12 draft does by default. The
// schema patterns carry their own anchors, so the unanchored
// regexp.MatchString gives Python's re.search semantics.
package causalontology

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// schemaFiles maps each kind to its schema file name under spec/schema.
// Three token kinds keep their original 1.0.0-reserved file names
// (individual/token/state); the id scheme is the whole word.
var schemaFiles = map[string]string{
	"occurrent":              "occurrent.schema.json",
	"causal_relation_object": "causal_relation_object.schema.json",
	"continuant":             "continuant.schema.json",
	"realizable":             "realizable.schema.json",
	"stratum":                "stratum.schema.json",
	"bridge":                 "bridge.schema.json",
	"port":                   "port.schema.json",
	"conduit":                "conduit.schema.json",
	"quality":                "quality.schema.json",
	"token_individual":       "individual.schema.json",
	"token_occurrence":       "token.schema.json",
	"state_assertion":        "state.schema.json",
	"token_causal_claim":     "token_causal_claim.schema.json",
	"assertion":              "assertion.schema.json",
	"enrichment":             "enrichment.schema.json",
	"retraction":             "retraction.schema.json",
	"succession":             "succession.schema.json",
}

// schemaBaseURI is the cross-file $ref prefix the schemas use
// ("https://causalontology.org/schema/<file>.schema.json#/...").
const schemaBaseURI = "https://causalontology.org/schema/"

// schemaCache holds each parsed schema after its first load.
var schemaCache = map[string]map[string]any{}

// regexpCache holds each compiled pattern after its first use.
var regexpCache = map[string]*regexp.Regexp{}

// schemaDirOverride, when set, names the schema directory directly.
var schemaDirOverride string

// SetSchemaDir pins the directory the eight schema files are read from
// (and clears the cache); the conformance runner points it at the
// repository's spec/schema.
func SetSchemaDir(dir string) {
	schemaDirOverride = dir
	schemaCache = map[string]map[string]any{}
}

// resolveSchemaDir finds spec/schema: the explicit override first, then
// the CAUSALONTOLOGY_ROOT environment variable, then a walk up from the
// working directory.
func resolveSchemaDir() (string, error) {
	if schemaDirOverride != "" {
		return schemaDirOverride, nil
	}
	if root := os.Getenv("CAUSALONTOLOGY_ROOT"); root != "" {
		return filepath.Join(root, "spec", "schema"), nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, "spec", "schema")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf(
		"cannot locate spec/schema: set CAUSALONTOLOGY_ROOT or run inside the repository")
}

// loadSchema reads and caches the root schema for one kind.
func loadSchema(kind string) (map[string]any, error) {
	fileName, known := schemaFiles[kind]
	if !known {
		return nil, fmt.Errorf("unknown kind: %q", kind)
	}
	return loadSchemaFile(fileName)
}

// loadSchemaFile reads and caches one schema file by name (used both for
// a kind's root schema and for cross-file $ref resolution).
func loadSchemaFile(fileName string) (map[string]any, error) {
	if cached, ok := schemaCache[fileName]; ok {
		return cached, nil
	}
	dir, err := resolveSchemaDir()
	if err != nil {
		return nil, err
	}
	value, err := DecodeJSONFile(filepath.Join(dir, fileName))
	if err != nil {
		return nil, err
	}
	schema, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema %s is not a JSON object", fileName)
	}
	schemaCache[fileName] = schema
	return schema, nil
}

// compiledPattern compiles and caches one schema regular expression.
func compiledPattern(pattern string) (*regexp.Regexp, error) {
	if re, ok := regexpCache[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexpCache[pattern] = re
	return re, nil
}

// navigate follows a JSON Pointer (slash-separated, leading empty parts
// skipped) from a document to a nested schema node.
func navigate(doc map[string]any, pointer string) (map[string]any, error) {
	var node any = doc
	for _, part := range strings.Split(pointer, "/") {
		if part == "" {
			continue
		}
		container, isObject := node.(map[string]any)
		if !isObject {
			return nil, fmt.Errorf("bad $ref path at %q", part)
		}
		next, found := container[part]
		if !found {
			return nil, fmt.Errorf("unresolved $ref part: %q", part)
		}
		node = next
	}
	target, isObject := node.(map[string]any)
	if !isObject {
		return nil, fmt.Errorf("$ref target is not a schema object")
	}
	return target, nil
}

// resolveRef follows local ("#/$defs/...") and cross-file
// ("https://causalontology.org/schema/<file>#/...") $ref chains, returning
// the concrete schema node and the root document it lives in (which
// changes across a cross-file hop, so nested local refs resolve correctly).
func resolveRef(schema, root map[string]any) (map[string]any, map[string]any, error) {
	for {
		refRaw, present := schema["$ref"]
		if !present {
			return schema, root, nil
		}
		ref, ok := refRaw.(string)
		if !ok {
			return nil, nil, fmt.Errorf("$ref must be a string: %v", refRaw)
		}
		switch {
		case strings.HasPrefix(ref, "#/"):
			target, err := navigate(root, ref[2:])
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", ref, err)
			}
			schema = target
		case strings.HasPrefix(ref, schemaBaseURI):
			rest := ref[len(schemaBaseURI):]
			fileName, pointer, _ := strings.Cut(rest, "#/")
			loaded, err := loadSchemaFile(fileName)
			if err != nil {
				return nil, nil, err
			}
			root = loaded
			if pointer == "" {
				schema = loaded
			} else {
				target, err := navigate(root, pointer)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: %w", ref, err)
				}
				schema = target
			}
		default:
			return nil, nil, fmt.Errorf("unsupported $ref: %q", ref)
		}
	}
}

// isNumberValue reports whether a value is a JSON number in this
// binding's value model (never a bool, which is its own type in Go).
func isNumberValue(value any) bool {
	if _, isBool := value.(bool); isBool {
		return false
	}
	_, ok := AsFloat(value)
	return ok
}

// isIntegerValue reports whether a value is a JSON integer in this
// binding's value model: an integer-literal json.Number, or a Go int; a
// bool (its own type) and a decimal are not integers, matching Python's
// isinstance(value, int) and not isinstance(value, bool).
func isIntegerValue(value any) bool {
	switch n := value.(type) {
	case int, int64:
		return true
	case json.Number:
		return IsIntegerNumber(n)
	}
	return false
}

// checkSchema validates one value against one (sub)schema, appending
// human-readable reasons; the returned error is reserved for structural
// schema problems (bad $ref, uncompilable pattern), not validation
// failures.
func checkSchema(value any, schema, root map[string]any, path string, reasons *[]string) error {
	resolved, resolvedRoot, err := resolveRef(schema, root)
	if err != nil {
		return err
	}
	schema = resolved
	root = resolvedRoot

	if oneOfRaw, present := schema["oneOf"]; present {
		branches, _ := oneOfRaw.([]any)
		passing := 0
		for _, branchRaw := range branches {
			branch, isObject := branchRaw.(map[string]any)
			if !isObject {
				continue
			}
			var branchReasons []string
			if err := checkSchema(value, branch, root, path, &branchReasons); err != nil {
				return err
			}
			if len(branchReasons) == 0 {
				passing++
			}
		}
		if passing != 1 {
			*reasons = append(*reasons, fmt.Sprintf(
				"%s: matches %d of the oneOf branches (need exactly 1)", path, passing))
		}
		return nil
	}

	if typeRaw, present := schema["type"]; present {
		typeName, _ := typeRaw.(string)
		ok := false
		switch typeName {
		case "object":
			_, ok = value.(map[string]any)
		case "array":
			_, ok = value.([]any)
		case "string":
			_, ok = value.(string)
		case "boolean":
			_, ok = value.(bool)
		case "number":
			ok = isNumberValue(value)
		case "integer":
			ok = isIntegerValue(value)
		}
		if !ok {
			*reasons = append(*reasons, fmt.Sprintf("%s: expected %s", path, typeName))
			return nil
		}
	}

	if constValue, present := schema["const"]; present && !JSONEqual(value, constValue) {
		*reasons = append(*reasons, fmt.Sprintf("%s: must equal %v", path, constValue))
	}
	if enumRaw, present := schema["enum"]; present {
		options, _ := enumRaw.([]any)
		found := false
		for _, option := range options {
			if JSONEqual(value, option) {
				found = true
				break
			}
		}
		if !found {
			*reasons = append(*reasons, fmt.Sprintf("%s: %v not in enumeration", path, value))
		}
	}
	if patternRaw, present := schema["pattern"]; present {
		if text, isString := value.(string); isString {
			pattern, _ := patternRaw.(string)
			re, err := compiledPattern(pattern)
			if err != nil {
				return err
			}
			if !re.MatchString(text) {
				*reasons = append(*reasons, fmt.Sprintf(
					"%s: %q does not match %s", path, text, pattern))
			}
		}
	}
	if minLengthRaw, present := schema["minLength"]; present {
		if text, isString := value.(string); isString {
			if minLength, ok := AsFloat(minLengthRaw); ok &&
				float64(utf8.RuneCountInString(text)) < minLength {
				*reasons = append(*reasons, fmt.Sprintf("%s: shorter than minLength", path))
			}
		}
	}
	if minimumRaw, present := schema["minimum"]; present {
		if number, isNumber := AsFloat(value); isNumber {
			if minimum, ok := AsFloat(minimumRaw); ok && number < minimum {
				*reasons = append(*reasons, fmt.Sprintf(
					"%s: below minimum %v", path, minimumRaw))
			}
		}
	}
	if maximumRaw, present := schema["maximum"]; present {
		if number, isNumber := AsFloat(value); isNumber {
			if maximum, ok := AsFloat(maximumRaw); ok && number > maximum {
				*reasons = append(*reasons, fmt.Sprintf(
					"%s: above maximum %v", path, maximumRaw))
			}
		}
	}

	if list, isList := value.([]any); isList {
		if minItemsRaw, present := schema["minItems"]; present {
			if minItems, ok := AsFloat(minItemsRaw); ok && float64(len(list)) < minItems {
				*reasons = append(*reasons, fmt.Sprintf(
					"%s: fewer than %d items", path, int(minItems)))
			}
		}
		if itemsRaw, present := schema["items"]; present {
			if itemSchema, isObject := itemsRaw.(map[string]any); isObject {
				for i, item := range list {
					itemPath := fmt.Sprintf("%s[%d]", path, i)
					if err := checkSchema(item, itemSchema, root, itemPath, reasons); err != nil {
						return err
					}
				}
			}
		}
	}

	if object, isObject := value.(map[string]any); isObject {
		properties, _ := schema["properties"].(map[string]any)
		if requiredRaw, present := schema["required"]; present {
			requiredList, _ := requiredRaw.([]any)
			for _, nameRaw := range requiredList {
				name, _ := nameRaw.(string)
				if _, has := object[name]; !has {
					*reasons = append(*reasons, fmt.Sprintf(
						"%s: required property '%s' missing", path, name))
				}
			}
		}
		if additional, isBool := schema["additionalProperties"].(bool); isBool && !additional {
			keys := make([]string, 0, len(object))
			for key := range object {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if _, defined := properties[key]; !defined {
					*reasons = append(*reasons, fmt.Sprintf(
						"%s: additional property '%s'", path, key))
				}
			}
		}
		propertyNames := make([]string, 0, len(properties))
		for name := range properties {
			propertyNames = append(propertyNames, name)
		}
		sort.Strings(propertyNames)
		for _, name := range propertyNames {
			propertyValue, has := object[name]
			if !has {
				continue
			}
			propertySchema, isSchema := properties[name].(map[string]any)
			if !isSchema {
				continue
			}
			if err := checkSchema(propertyValue, propertySchema, root, path+"."+name, reasons); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateSchema checks structural validity against the kind's JSON
// Schema, returning (ok, reasons). An empty kind means: infer it.
func ValidateSchema(obj map[string]any, kind string) (bool, []string, error) {
	if kind == "" {
		inferred, err := InferKind(obj)
		if err != nil {
			return false, nil, err
		}
		kind = inferred
	}
	root, err := loadSchema(kind)
	if err != nil {
		return false, nil, err
	}
	var reasons []string
	if err := checkSchema(obj, root, root, "$", &reasons); err != nil {
		return false, nil, err
	}
	return len(reasons) == 0, reasons, nil
}

package causalontology

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedSchemasAreComplete is the check that does not need a checkout:
// the module must carry all twenty-one schemas and every one of them must
// parse. It fails inside the artifact as readily as inside the repository,
// which is the point - the defect being guarded against was a published
// artifact that carried none of them.
func TestEmbeddedSchemasAreComplete(t *testing.T) {
	names := EmbeddedSchemaNames()
	if len(names) != 21 {
		t.Fatalf("embedded schema count = %d, want 21: %v", len(names), names)
	}
	for _, name := range names {
		data, err := embeddedSchemas.ReadFile("spec_schema/" + name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		var parsed any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("embedded %s is not valid JSON: %v", name, err)
		}
	}
	// Every kind the validator knows must have its file compiled in.
	present := map[string]bool{}
	for _, name := range names {
		present[name] = true
	}
	for kind, file := range schemaFiles {
		if !present[file] {
			t.Fatalf("kind %q maps to %s, which is not embedded", kind, file)
		}
	}
}

// TestValidateSchemaUsesEmbeddedCopy proves the compiled-in copy is reachable
// with no override and no CAUSALONTOLOGY_SPEC - the exact configuration a
// consumer outside a checkout has.
func TestValidateSchemaUsesEmbeddedCopy(t *testing.T) {
	t.Setenv("CAUSALONTOLOGY_SPEC", "")
	previous := schemaDirOverride
	SetSchemaDir("")
	defer SetSchemaDir(previous)

	object := map[string]any{
		"id": "continuant:" +
			"0000000000000000000000000000000000000000000000000000000000000000",
		"label":    "a continuant",
		"category": "object",
	}
	if _, _, err := ValidateSchema(object, "continuant"); err != nil {
		t.Fatalf("ValidateSchema with no on-disk schemas: %v", err)
	}
}

// TestNoDriftFromSpecSchema runs the byte-for-byte guard when a checkout is
// reachable, and skips when it is not (a consumer running `go test` on the
// downloaded module has no spec/schema).
func TestNoDriftFromSpecSchema(t *testing.T) {
	dir := BindingPath()
	for i := 0; i < 12 && dir != ""; i++ {
		candidate := filepath.Join(dir, "spec", "schema")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			if err := CheckEmbeddedSchemaDrift(candidate); err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("compared against %s", candidate)
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("no spec/schema above the binding; nothing to compare against")
}

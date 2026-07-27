// Compile-time copy of the twenty-one whole-word schemas.
//
// A Go module ships only its own subdirectory, so spec/schema is not
// delivered by `go get`. Embedding keeps the module self-contained, the
// same choice the Rust binding makes with include_str!. Refresh the copy
// from spec/schema at each conformance freeze; the conformance runner
// fails on any byte of drift.
package causalontology

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

//go:embed spec_schema/*.schema.json
var embeddedSchemas embed.FS

// EmbeddedSchemaNames lists the file names compiled into the module, in
// sorted order. A caller (or the conformance runner) can assert the count
// without reaching for the filesystem.
func EmbeddedSchemaNames() []string {
	entries, err := fs.ReadDir(embeddedSchemas, "spec_schema")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// BindingPath reports the directory this package was compiled from. Go
// records each source file's path in the binary (unless it is built with
// -trimpath), so inside a checkout this is bindings/go/v4/causalontology and
// after `go get` it is the module cache entry. The conformance runner prints
// it and, in installed mode, refuses to continue if it is inside the
// repository - that is how a "fresh install" test is stopped from quietly
// exercising repository source.
func BindingPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok || file == "" {
		return ""
	}
	dir := filepath.Dir(file)
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return dir
}

// CheckEmbeddedSchemaDrift compares every compiled-in schema against a
// spec/schema directory and reports the first byte-level difference. The
// check runs in both directions - every on-disk schema must be embedded and
// every embedded schema must still exist on disk - so neither a stale
// vendored copy nor a silently dropped file can pass.
func CheckEmbeddedSchemaDrift(specSchemaDir string) error {
	entries, err := os.ReadDir(specSchemaDir)
	if err != nil {
		return err
	}
	onDiskNames := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".schema.json") {
			continue
		}
		onDiskNames[name] = true
		onDisk, err := os.ReadFile(filepath.Join(specSchemaDir, name))
		if err != nil {
			return err
		}
		embedded, err := embeddedSchemas.ReadFile("spec_schema/" + name)
		if err != nil {
			return fmt.Errorf("embedded schema drift: %s is not embedded", name)
		}
		if !bytes.Equal(onDisk, embedded) {
			return fmt.Errorf(
				"embedded schema drift: %s differs from spec/schema - "+
					"re-copy into causalontology/spec_schema", name)
		}
	}
	for _, name := range EmbeddedSchemaNames() {
		if !onDiskNames[name] {
			return fmt.Errorf(
				"embedded schema drift: %s is embedded but absent from spec/schema", name)
		}
	}
	if len(onDiskNames) != len(EmbeddedSchemaNames()) {
		return fmt.Errorf("embedded schema drift: %d on disk, %d embedded",
			len(onDiskNames), len(EmbeddedSchemaNames()))
	}
	return nil
}

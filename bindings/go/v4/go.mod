module github.com/ai-university-aiu/causalontology/bindings/go/v4

go 1.22

// v4.0.0 shipped without the twenty-one JSON Schemas: the module carried no
// copy of spec/schema and resolved it from the filesystem, so ValidateSchema
// failed for every consumer outside a repository checkout. Fixed in v4.0.1,
// which compiles the schemas in with embed.FS.
retract v4.0.0

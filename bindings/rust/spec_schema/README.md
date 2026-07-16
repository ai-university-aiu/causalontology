Vendored copy of ../../spec/schema/*.schema.json so the crate is
self-contained for crates.io packaging. spec/schema/ remains normative;
this copy is refreshed at each conformance freeze (last: 2.0.0,
whole-word re-mint). The conformance runner will catch any drift.

Vendored copy of ../../spec/schema/*.schema.json so the crate is
self-contained for crates.io packaging. spec/schema/ remains normative;
this copy is refreshed at each conformance freeze (last: 4.0.0, the
twenty-one schemas). The conformance runner will catch any drift.

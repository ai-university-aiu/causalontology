Vendored copy of ../../spec/schema/*.schema.json so the package is
self-contained for Hackage packaging. spec/schema/ remains normative;
this copy is refreshed at each conformance freeze (last: 4.0.0, the
twenty-one schemas). These files are listed in `data-files` in
causalontology.cabal and are resolved at run time through
`Paths_causalontology.getDataFileName`. The conformance runner will
catch any drift.

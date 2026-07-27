Vendored copy of ../../spec/schema/*.schema.json so the NuGet package is
self-contained. spec/schema/ remains normative; this copy is refreshed at
each conformance freeze (last: 4.0.0, the twenty-one schemas). The files
are compiled into Causalontology.dll as embedded resources and are also
packed into the .nupkg (and copied next to the assembly) so a consumer can
read them from disk. The conformance runner will catch any drift.

Vendored copy of ../../../../spec/schema/*.schema.json so the Composer
package is self-contained. spec/schema/ remains normative; this copy is
refreshed at each conformance freeze (last: 4.0.0, the twenty-one schemas).

src/SchemaValidator.php prefers this directory over any repository-relative
path, so an installed copy validates with no repository present. Do not
exclude it from the package archive: it is data, not PSR-4 source, so nothing
in the autoloader would notice its absence until the first validate call
fails. bindings/php/conformance.php fails the run if this copy is absent,
incomplete, or byte-different from spec/schema.

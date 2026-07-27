# The twenty-one specification JSON Schemas must travel INSIDE the built
# artifact, under inst/schema. When they do not, every consumer outside a
# repository checkout fails on the first co_validate_schema() call -- which
# is precisely the packaging defect this test exists to catch. R CMD check
# runs this against the *installed* package, so a manifest change that stops
# shipping inst/schema turns the check red instead of shipping quietly.
library(causalontology)

# An explicit specification tree would mask a missing bundle, so take it out
# of the picture for the duration of this test.
old_spec <- Sys.getenv("CAUSALONTOLOGY_SPEC", unset = NA_character_)
Sys.unsetenv("CAUSALONTOLOGY_SPEC")
if (!is.na(old_spec)) {
  on.exit(Sys.setenv(CAUSALONTOLOGY_SPEC = old_spec), add = TRUE)
}

# (1) the bundled directory exists inside the installed package.
schema_dir <- system.file("schema", package = "causalontology")
stopifnot(is.character(schema_dir), length(schema_dir) == 1L,
          nzchar(schema_dir), dir.exists(schema_dir))

# (2) it holds exactly the twenty-one schemas of specification 4.0.0.
expected <- sort(c(
  "assertion.schema.json", "attitude.schema.json", "bridge.schema.json",
  "causal_relation_object.schema.json", "conduit.schema.json",
  "continuant.schema.json", "cross_stratal_seam.schema.json",
  "enrichment.schema.json", "individual.schema.json",
  "occurrent.schema.json", "port.schema.json",
  "predicted_occurrence.schema.json", "prediction_error.schema.json",
  "quality.schema.json", "realizable.schema.json", "retraction.schema.json",
  "state.schema.json", "stratum.schema.json", "succession.schema.json",
  "token.schema.json", "token_causal_claim.schema.json"))
found <- sort(basename(Sys.glob(file.path(schema_dir, "*.schema.json"))))
stopifnot(length(found) == 21L, identical(found, expected))

# (3) every kind's schema actually loads and validates through the public
# API, with no specification tree present. An empty object is structurally
# invalid for all of them; what matters is that validation *runs* rather
# than dying on a missing file.
kinds <- c("occurrent", "causal_relation_object", "continuant", "realizable",
           "stratum", "bridge", "cross_stratal_seam", "port", "conduit",
           "quality", "token_individual", "token_occurrence",
           "state_assertion", "token_causal_claim", "attitude",
           "predicted_occurrence", "prediction_error", "assertion",
           "enrichment", "retraction", "succession")
empty <- co_parse_json("{}")
for (kind in kinds) {
  res <- co_validate_schema(empty, kind)
  stopifnot(is.list(res), isFALSE(res$ok), length(res$errors) > 0L)
}

# (4) and a well-formed record still passes, so the bundled copies are the
# real schemas and not empty placeholders.
ok_occurrent <- co_parse_json(paste0(
  "{\"id\":\"occurrent:", strrep("a", 64L),
  "\",\"label\":\"press_button\",\"category\":\"action\"}"))
stopifnot(isTRUE(co_validate_schema(ok_occurrent, "occurrent")$ok))

cat("causalontology R bundled-schema test: OK (21 schemas in ",
    schema_dir, ")\n", sep = "")

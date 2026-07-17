# causalontology-r -- schema.R
#
# Schema validation against spec/schema/*.schema.json, ported from the
# reference bindings/python/causalontology/schema.py.
#
# A deliberately small interpreter for exactly the JSON Schema keywords the
# seventeen Causalontology schemas use: type, const, enum, pattern,
# required, properties, additionalProperties, items, minItems, minLength,
# minimum, maximum, oneOf, local $ref (#/$defs/...), and cross-file $ref to
# a sibling schema (https://causalontology.org/schema/<file>.schema.json#/
# ...). "format" is treated as an annotation, as the 2020-12 draft does by
# default.

# kind -> schema file. Three token kinds keep their original 1.0.0-reserved
# file names (individual/token/state); the id scheme is the whole word.
co_schema_files <- c(
  occurrent  = "occurrent.schema.json",
  causal_relation_object = "causal_relation_object.schema.json",
  continuant = "continuant.schema.json",
  realizable = "realizable.schema.json",
  stratum    = "stratum.schema.json",
  bridge     = "bridge.schema.json",
  port       = "port.schema.json",
  conduit    = "conduit.schema.json",
  quality    = "quality.schema.json",
  token_individual   = "individual.schema.json",
  token_occurrence   = "token.schema.json",
  state_assertion    = "state.schema.json",
  token_causal_claim = "token_causal_claim.schema.json",
  assertion  = "assertion.schema.json",
  enrichment = "enrichment.schema.json",
  retraction = "retraction.schema.json",
  succession = "succession.schema.json"
)

co_schema_base <- "https://causalontology.org/schema/"

co_schema_dir <- function() {
  env <- Sys.getenv("CAUSALONTOLOGY_SPEC", unset = "")
  if (nzchar(env)) return(file.path(env, "schema"))
  # In-repo / sourced: the standard's spec/schema is the source of truth.
  root <- tryCatch(co_repo_root(), error = function(e) NULL)
  if (!is.null(root) && dir.exists(file.path(root, "spec", "schema"))) {
    return(file.path(root, "spec", "schema"))
  }
  # Installed package: the schemas bundled under inst/schema.
  p <- system.file("schema", package = "causalontology")
  if (nzchar(p) && dir.exists(p)) return(p)
  stop("cannot locate the specification schemas")
}

# Load and cache one schema file by its filename.
co_load_schema_file <- function(filename) {
  if (!exists("schemas", envir = co_state, inherits = FALSE)) {
    assign("schemas", list(), envir = co_state)
  }
  cache <- get("schemas", envir = co_state, inherits = FALSE)
  if (!co_has_key(cache, filename)) {
    path <- file.path(co_schema_dir(), filename)
    text <- paste(readLines(path, warn = FALSE, encoding = "UTF-8"),
                  collapse = "\n")
    cache[[filename]] <- co_parse_json(text)
    assign("schemas", cache, envir = co_state)
  }
  cache[[filename]]
}

co_load_schema <- function(kind) {
  if (!(kind %in% names(co_schema_files))) stop("unknown kind: ", kind)
  co_load_schema_file(co_schema_files[[kind]])
}

# Navigate a JSON pointer body (already stripped of a leading "#/" or "").
co_schema_navigate <- function(doc, pointer) {
  node <- doc
  for (part in strsplit(pointer, "/", fixed = TRUE)[[1]]) {
    if (!nzchar(part)) next
    node <- node[[part]]
  }
  node
}

# Follow local and cross-file $ref chains to a concrete node + its root.
# Returns list(schema = <node>, root = <root doc>).
co_schema_resolve <- function(schema, root) {
  while (co_is_obj(schema) && co_has(schema, "$ref")) {
    ref <- schema[["$ref"]]
    if (startsWith(ref, "#/")) {
      schema <- co_schema_navigate(root, substring(ref, 3L))
    } else if (startsWith(ref, co_schema_base)) {
      rest <- substring(ref, nchar(co_schema_base) + 1L)
      idx <- regexpr("#/", rest, fixed = TRUE)
      if (idx > 0L) {
        filename <- substr(rest, 1L, idx - 1L)
        pointer <- substring(rest, idx + 2L)
      } else {
        filename <- rest
        pointer <- ""
      }
      root <- co_load_schema_file(filename)
      schema <- if (nzchar(pointer)) co_schema_navigate(root, pointer) else root
    } else {
      stop("unsupported $ref: ", ref)
    }
  }
  list(schema = schema, root = root)
}

# Does this value have the given JSON Schema type?
co_schema_type_ok <- function(value, t) {
  if (identical(t, "object"))  return(co_is_obj(value))
  if (identical(t, "array"))   return(co_is_arr(value))
  if (identical(t, "string"))  return(co_is_str(value))
  if (identical(t, "boolean")) return(co_is_bool(value))
  if (identical(t, "integer")) return(co_is_num(value) &&
                                        isTRUE(as.numeric(value) ==
                                               floor(as.numeric(value))))
  if (identical(t, "number"))  return(co_is_num(value))  # excludes logicals
  stop("unsupported schema type: ", t)
}

# One recursive check; errors accumulate in the collector environment.
co_schema_check <- function(value, schema, root, path, errs) {
  rr <- co_schema_resolve(schema, root)
  schema <- rr$schema
  root <- rr$root

  if (co_has(schema, "oneOf")) {
    passing <- 0L
    branches <- schema[["oneOf"]]
    for (i in seq_along(branches)) {
      sub_errs <- new.env(parent = emptyenv())
      sub_errs$msgs <- character(0)
      co_schema_check(value, branches[[i]], root, path, sub_errs)
      if (length(sub_errs$msgs) == 0L) passing <- passing + 1L
    }
    if (passing != 1L) {
      errs$msgs <- c(errs$msgs, sprintf(
        "%s: matches %d of the oneOf branches (need exactly 1)",
        path, passing))
    }
    return(invisible(NULL))
  }

  t <- co_get(schema, "type")
  if (!is.null(t)) {
    if (!co_schema_type_ok(value, t)) {
      errs$msgs <- c(errs$msgs, sprintf("%s: expected %s", path, t))
      return(invisible(NULL))
    }
  }

  if (co_has(schema, "const") && !co_equal(value, schema[["const"]])) {
    errs$msgs <- c(errs$msgs, sprintf("%s: must equal '%s'",
                                      path, as.character(schema[["const"]])[[1]]))
  }
  if (co_has(schema, "enum")) {
    enum <- schema[["enum"]]
    hit <- FALSE
    for (i in seq_along(enum)) {
      if (co_equal(value, enum[[i]])) { hit <- TRUE; break }
    }
    if (!hit) {
      shown <- if (co_is_str(value)) value else co_jcs(value)
      errs$msgs <- c(errs$msgs, sprintf("%s: '%s' not in enumeration",
                                        path, shown))
    }
  }
  if (co_has(schema, "pattern") && co_is_str(value)) {
    if (!grepl(schema[["pattern"]], value, perl = TRUE)) {
      errs$msgs <- c(errs$msgs, sprintf("%s: '%s' does not match %s",
                                        path, value, schema[["pattern"]]))
    }
  }
  if (co_has(schema, "minLength") && co_is_str(value)) {
    if (nchar(value, type = "chars") < as.numeric(schema[["minLength"]])) {
      errs$msgs <- c(errs$msgs, sprintf("%s: shorter than minLength", path))
    }
  }
  if (co_has(schema, "minimum") && co_is_num(value)) {
    if (as.numeric(value) < as.numeric(schema[["minimum"]])) {
      errs$msgs <- c(errs$msgs, sprintf("%s: below minimum %s", path,
                                        co_jcs_number(schema[["minimum"]])))
    }
  }
  if (co_has(schema, "maximum") && co_is_num(value)) {
    if (as.numeric(value) > as.numeric(schema[["maximum"]])) {
      errs$msgs <- c(errs$msgs, sprintf("%s: above maximum %s", path,
                                        co_jcs_number(schema[["maximum"]])))
    }
  }

  if (co_is_arr(value)) {
    if (co_has(schema, "minItems") &&
        length(value) < as.numeric(schema[["minItems"]])) {
      errs$msgs <- c(errs$msgs, sprintf("%s: fewer than %.0f items", path,
                                        as.numeric(schema[["minItems"]])))
    }
    if (co_has(schema, "items")) {
      for (i in seq_along(value)) {
        co_schema_check(value[[i]], schema[["items"]], root,
                        sprintf("%s[%d]", path, i - 1L), errs)
      }
    }
  }

  if (co_is_obj(value)) {
    props <- co_get(schema, "properties", co_obj())
    prop_names <- names(props)
    if (is.null(prop_names)) prop_names <- character(0)
    for (req in co_strings(co_get(schema, "required"))) {
      if (!co_has(value, req)) {
        errs$msgs <- c(errs$msgs, sprintf(
          "%s: required property '%s' missing", path, req))
      }
    }
    if (identical(co_get(schema, "additionalProperties"), FALSE)) {
      value_names <- names(value)
      if (is.null(value_names)) value_names <- character(0)
      for (key in value_names) {
        if (!(key %in% prop_names)) {
          errs$msgs <- c(errs$msgs, sprintf(
            "%s: additional property '%s'", path, key))
        }
      }
    }
    for (key in prop_names) {
      if (co_has(value, key)) {
        co_schema_check(value[[key]], props[[key]], root,
                        sprintf("%s.%s", path, key), errs)
      }
    }
  }

  invisible(NULL)
}

# list(ok, errors) -- structural validity against the kind's JSON Schema.
co_validate_schema <- function(obj, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(obj)
  root <- co_load_schema(kind)
  errs <- new.env(parent = emptyenv())
  errs$msgs <- character(0)
  co_schema_check(obj, root, root, "$", errs)
  list(ok = length(errs$msgs) == 0L, errors = errs$msgs)
}

# causalontology-r -- schema.R
#
# Schema validation against spec/schema/*.schema.json, ported from the
# reference bindings/python/causalontology/schema.py.
#
# A deliberately small interpreter for exactly the JSON Schema keywords
# the eight Causalontology schemas use: type, const, enum, pattern,
# required, properties, additionalProperties, items, minItems, minLength,
# minimum, maximum, oneOf, and local $ref (#/$defs/...). "format" is
# treated as an annotation, as the 2020-12 draft does by default.

co_schema_files <- c(
  cro        = "cro.schema.json",
  occurrent  = "occurrent.schema.json",
  continuant = "continuant.schema.json",
  realizable = "realizable.schema.json",
  assertion  = "assertion.schema.json",
  enrichment = "enrichment.schema.json",
  retraction = "retraction.schema.json",
  succession = "succession.schema.json"
)

co_schema_dir <- function() {
  env <- Sys.getenv("CAUSALONTOLOGY_SPEC", unset = "")
  if (nzchar(env)) return(file.path(env, "schema"))
  file.path(co_repo_root(), "spec", "schema")
}

co_load_schema <- function(kind) {
  if (!(kind %in% names(co_schema_files))) stop("unknown kind: ", kind)
  if (!exists("schemas", envir = co_state, inherits = FALSE)) {
    assign("schemas", list(), envir = co_state)
  }
  cache <- get("schemas", envir = co_state, inherits = FALSE)
  if (!co_has_key(cache, kind)) {
    path <- file.path(co_schema_dir(), co_schema_files[[kind]])
    text <- paste(readLines(path, warn = FALSE, encoding = "UTF-8"),
                  collapse = "\n")
    cache[[kind]] <- co_parse_json(text)
    assign("schemas", cache, envir = co_state)
  }
  cache[[kind]]
}

# Follow local $ref chains (#/$defs/...) to the referenced subschema.
co_schema_resolve <- function(schema, root) {
  while (co_has(schema, "$ref")) {
    ref <- schema[["$ref"]]
    if (!startsWith(ref, "#/")) stop("only local $ref supported: ", ref)
    node <- root
    for (part in strsplit(substring(ref, 3L), "/", fixed = TRUE)[[1]]) {
      node <- node[[part]]
    }
    schema <- node
  }
  schema
}

# Does this value have the given JSON Schema type?
co_schema_type_ok <- function(value, t) {
  if (identical(t, "object"))  return(co_is_obj(value))
  if (identical(t, "array"))   return(co_is_arr(value))
  if (identical(t, "string"))  return(co_is_str(value))
  if (identical(t, "boolean")) return(co_is_bool(value))
  if (identical(t, "number"))  return(co_is_num(value))  # excludes logicals
  stop("unsupported schema type: ", t)
}

# One recursive check; errors accumulate in the collector environment.
co_schema_check <- function(value, schema, root, path, errs) {
  schema <- co_schema_resolve(schema, root)

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
    # length in characters (code points), not bytes, as Python len() counts
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
        # 0-based item paths, matching the reference messages
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

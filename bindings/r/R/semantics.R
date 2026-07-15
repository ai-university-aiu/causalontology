# causalontology-r -- semantics.R
#
# The semantic rules beyond the schemas (spec/semantics.md), ported from
# the reference bindings/python/causalontology/semantics.py.
#
# Local rules are checked here; store-context rules (materialized
# acyclicity, retraction lineage) live in store.R where the context exists.

# Rule 4: the fixed unit-conversion constants (average Gregorian values).
co_unit_seconds <- c(
  instant = 0,
  seconds = 1,
  minutes = 60,
  hours   = 3600,
  days    = 86400,
  weeks   = 604800,
  months  = 2629746,
  years   = 31556952
)

# Rule 12: enrichment field-to-kind validity and entry shapes.
co_enrichment_fields <- list(
  aliases      = list(kinds = c("occurrent", "continuant"), shape = "alias"),
  participants = list(kinds = c("occurrent"),               shape = "continuant"),
  subsumes     = list(kinds = c("continuant"),              shape = "continuant"),
  part_of      = list(kinds = c("continuant"),              shape = "continuant"),
  realized_in  = list(kinds = c("realizable"),              shape = "occurrent")
)

# The optional CRO fields, in the reference order (V02 checks this order).
co_cro_optional_fields <- c("mechanism", "temporal", "modality", "context")

# The kind named by an identifier's scheme prefix, or NULL.
co_kind_of_id <- function(identifier) {
  if (!co_is_str(identifier) || !nzchar(identifier)) return(NULL)
  pre <- strsplit(identifier, ":", fixed = TRUE)[[1]][[1]]
  if (pre %in% names(co_kind_of_prefix)) co_kind_of_prefix[[pre]] else NULL
}

# list(ok, errors) -- the locally checkable semantic rules.
co_validate_semantics <- function(obj, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(obj)
  errors <- character(0)

  if (identical(kind, "causal_relation_object")) {
    t <- co_get(obj, "temporal")
    if (!is.null(t) && !co_is_null(t) &&
        co_has(t, "minimum_delay") && !co_is_null(t[["minimum_delay"]]) &&
        co_has(t, "maximum_delay") && !co_is_null(t[["maximum_delay"]]) &&
        as.numeric(t[["minimum_delay"]]) > as.numeric(t[["maximum_delay"]])) {
      errors <- c(errors, "minimum_delay must be <= maximum_delay")
    }
    oid <- co_get(obj, "id")
    if (co_is_str(oid) && nzchar(oid) &&
        oid %in% co_strings(co_get(obj, "mechanism"))) {
      errors <- c(errors, paste0(
        "mechanism must be acyclic ",
        "(a Causal Relation Object may not contain itself)"))
    }
    if (co_is_str(oid) && nzchar(oid) &&
        identical(co_get(obj, "refines"), oid)) {
      errors <- c(errors, "refines must be acyclic")
    }
  }

  if (identical(kind, "enrichment")) {
    field <- co_get(obj, "field")
    about <- co_get(obj, "about", "")
    entry <- co_get(obj, "entry")
    spec <- if (co_is_str(field) && co_has_key(co_enrichment_fields, field)) {
      co_enrichment_fields[[field]]
    } else {
      NULL
    }
    if (!is.null(spec)) {
      about_kind <- co_kind_of_id(about)
      if (!is.null(about_kind) && !(about_kind %in% spec$kinds)) {
        errors <- c(errors, sprintf(
          "%s is not a legal field for a %s (rule 12)", field, about_kind))
      }
      if (identical(spec$shape, "alias")) {
        if (!(co_is_obj(entry) && co_has(entry, "lang") &&
              co_has(entry, "text"))) {
          errors <- c(errors,
                      "an aliases entry must be a language-tagged text object")
        }
      } else {
        if (!(co_is_str(entry) &&
              startsWith(entry, paste0(spec$shape, ":")))) {
          errors <- c(errors, sprintf(
            "a %s entry must be a %s: identifier", field, spec$shape))
        }
      }
    }
  }

  list(ok = length(errors) == 0L, errors = errors)
}

# list(partial, missing) -- which optional CRO fields are unspecified.
co_is_partial <- function(cro) {
  missing <- character(0)
  for (f in co_cro_optional_fields) {
    if (!co_has(cro, f)) missing <- c(missing, f)
  }
  list(partial = length(missing) > 0L, missing = missing)
}

# Rule 4: temporal admissibility with the fixed constants.
co_admissible <- function(cro, elapsed_seconds) {
  t <- co_get(cro, "temporal")
  if (is.null(t) || co_is_null(t)) return(TRUE)  # no window, no constraint
  unit <- co_unit_seconds[[t[["unit"]]]]
  lo <- as.numeric(t[["minimum_delay"]]) * unit
  hi <- as.numeric(t[["maximum_delay"]]) * unit
  elapsed <- as.numeric(elapsed_seconds)
  isTRUE(lo <= elapsed) && isTRUE(elapsed <= hi)
}

# Do the temporal windows of two CROs overlap (absent = overlapping)?
co_window_overlap <- function(a, b) {
  ta <- co_get(a, "temporal")
  tb <- co_get(b, "temporal")
  if (is.null(ta) || co_is_null(ta) || is.null(tb) || co_is_null(tb)) {
    return(TRUE)
  }
  ua <- co_unit_seconds[[ta[["unit"]]]]
  ub <- co_unit_seconds[[tb[["unit"]]]]
  lo_a <- as.numeric(ta[["minimum_delay"]]) * ua
  hi_a <- as.numeric(ta[["maximum_delay"]]) * ua
  lo_b <- as.numeric(tb[["minimum_delay"]]) * ub
  hi_b <- as.numeric(tb[["maximum_delay"]]) * ub
  isTRUE(lo_a <= hi_b) && isTRUE(lo_b <= hi_a)
}

# Are the context sets compatible (either absent/empty, or nested/equal)?
co_contexts_compatible <- function(a, b) {
  sa <- unique(co_strings(co_get(a, "context")))
  sb <- unique(co_strings(co_get(b, "context")))
  if (length(sa) == 0L || length(sb) == 0L) return(TRUE)
  all(sa %in% sb) || all(sb %in% sa)   # subset either way covers equality
}

co_positive_modalities <- c("necessary", "sufficient", "contributory")

# Rule 6: the formal conflict test.
co_conflicts <- function(a, b) {
  if (!setequal(co_strings(a[["causes"]]), co_strings(b[["causes"]]))) {
    return(FALSE)
  }
  if (!setequal(co_strings(a[["effects"]]), co_strings(b[["effects"]]))) {
    return(FALSE)
  }
  if (!co_contexts_compatible(a, b)) return(FALSE)
  if (!co_window_overlap(a, b)) return(FALSE)
  ma <- co_get(a, "modality", "")
  mb <- co_get(b, "modality", "")
  if (!co_is_str(ma)) ma <- ""
  if (!co_is_str(mb)) mb <- ""
  (identical(ma, "preventive") && mb %in% co_positive_modalities) ||
    (identical(mb, "preventive") && ma %in% co_positive_modalities)
}

# Rule 3: list(ok, reason) -- is child a valid refinement of parent?
co_refinement_valid <- function(child, parent) {
  if (!co_equal_or_both_absent(co_get(child, "refines"),
                               co_get(parent, "id"))) {
    return(list(ok = FALSE,
                reason = "child does not name the parent in refines"))
  }
  if (!setequal(co_strings(child[["causes"]]), co_strings(parent[["causes"]])) ||
      !setequal(co_strings(child[["effects"]]), co_strings(parent[["effects"]]))) {
    return(list(ok = FALSE,
                reason = "a refinement must keep the parent's causes and effects"))
  }
  added <- 0L
  for (field in co_cro_optional_fields) {
    if (co_has(parent, field)) {
      if (!co_equal(co_get(child, field), co_get(parent, field))) {
        return(list(ok = FALSE, reason = paste0(
          "a refinement may not change a field the parent specified; ",
          "this is a rival claim")))
      }
    } else if (co_has(child, field)) {
      added <- added + 1L
    }
  }
  if (added == 0L) {
    return(list(ok = FALSE,
                reason = "a refinement must add at least one unspecified field"))
  }
  list(ok = TRUE, reason = "valid refinement")
}

# Equality that also treats two absences (NULLs) as equal, mirroring
# Python's child.get("refines") != parent.get("id") on possibly-missing
# fields.
co_equal_or_both_absent <- function(a, b) {
  if (is.null(a) && is.null(b)) return(TRUE)
  if (is.null(a) || is.null(b)) return(FALSE)
  co_equal(a, b)
}

# Rule 7: "consistent" | "inconsistent" | "indeterminate".
# members: a NAMED list from CRO identifier to CRO object for the parent's
# mechanism entries (the store's view of them).
co_hierarchy_consistent <- function(parent, members) {
  mechanism <- co_strings(co_get(parent, "mechanism"))
  if (length(mechanism) == 0L) return("consistent")  # nothing claimed
  edges <- new.env(parent = emptyenv())
  for (mid in mechanism) {
    m <- if (co_has_key(members, mid)) members[[mid]] else NULL
    if (is.null(m)) return("indeterminate")  # a dangling_reference gap
    effects <- co_strings(m[["effects"]])
    for (c_id in co_strings(m[["causes"]])) {
      old <- if (exists(c_id, envir = edges, inherits = FALSE)) {
        get(c_id, envir = edges, inherits = FALSE)
      } else {
        character(0)
      }
      assign(c_id, unique(c(old, effects)), envir = edges)
    }
  }
  reachable <- function(src, dst) {
    seen <- character(0)
    stack <- src
    while (length(stack) > 0L) {
      node <- stack[[length(stack)]]
      stack <- stack[-length(stack)]
      if (identical(node, dst)) return(TRUE)
      if (node %in% seen) next
      seen <- c(seen, node)
      nxt <- if (exists(node, envir = edges, inherits = FALSE)) {
        get(node, envir = edges, inherits = FALSE)
      } else {
        character(0)
      }
      stack <- c(stack, nxt)
    }
    FALSE
  }
  for (c_id in co_strings(parent[["causes"]])) {
    for (e_id in co_strings(parent[["effects"]])) {
      if (!reachable(c_id, e_id)) return("inconsistent")
    }
  }
  "consistent"
}

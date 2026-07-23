# causalontology-r -- semantics.R
#
# The semantic rules beyond the schemas (spec/semantics.md), ported from
# the reference bindings/python/causalontology/semantics.py.
#
# Local rules are checked here; store-context rules (materialized
# acyclicity, retraction lineage) live in store.R where the context exists.
# The 2.0.0 normative algorithms (Section 12: bridge closure, bridged
# reachability, stratal classification, the skip decision procedure, and
# unit normalization) are implemented here exactly as written.

# Rule 4 / Algorithm E: the fixed unit-conversion constants (mean Gregorian).
co_unit_seconds <- c(
  instant = 0,
  seconds = 1,
  minutes = 60,
  hours   = 3600,
  days    = 86400,
  weeks   = 604800,
  months  = 2629746,     # NORMATIVE: mean Gregorian month
  years   = 31556952     # NORMATIVE: mean Gregorian year (365.2425 days)
)

# 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete step
# with NO wall-clock mapping; a tick window is ordered by integer comparison,
# and an ordinal window and a wall-clock window are DIFFERENT DIMENSIONS that do
# not compare (mixing them is never within-window and never overlapping).
co_ordinal_units <- c(ticks = 1)

# "ordinal" for a tick-like unit, else "wallclock".
co_dimension <- function(unit) {
  if (unit %in% names(co_ordinal_units)) "ordinal" else "wallclock"
}

# A comparable magnitude within ONE dimension: raw tick count for an ordinal
# unit, seconds for a wall-clock unit. Never mix dimensions.
co_magnitude <- function(value, unit) {
  if (unit %in% names(co_ordinal_units)) return(as.numeric(value))  # tick count
  if (identical(unit, "instant")) return(0)
  as.numeric(value) * co_unit_seconds[[unit]]
}

# Rule 12: enrichment field-to-kind validity and entry shapes. Two occurrent
# forms added in 2.0.0.
co_enrichment_fields <- list(
  aliases            = list(kinds = c("occurrent", "continuant"), shape = "alias"),
  participants       = list(kinds = c("occurrent"),  shape = "continuant"),
  subsumes           = list(kinds = c("continuant"), shape = "continuant"),
  part_of            = list(kinds = c("continuant"), shape = "continuant"),
  realized_in        = list(kinds = c("realizable"), shape = "occurrent"),
  occurrent_subsumes = list(kinds = c("occurrent"),  shape = "occurrent"),
  occurrent_part_of  = list(kinds = c("occurrent"),  shape = "occurrent")
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
    # Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
    # contradiction between skips:true and a non-empty mechanism.
    if (isTRUE(co_get(obj, "skips")) && length(co_strings(co_get(obj, "mechanism"))) > 0L) {
      errors <- c(errors, paste0(
        "contradictory_skip: skips is true but a mechanism is present"))
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

  # 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain has,
  # by drawing it, a modelled intervening mechanism - so mechanism_status
  # 'absent' contradicts a present chain (the honest-ignorance distinction must
  # stay honest). The stratal well-formedness (non-adjacency, adjacency of
  # chain steps, scheme, the home rule) needs the strata map and lives in
  # co_seam_wellformed, exactly as bridge well-formedness does.
  if (identical(kind, "cross_stratal_seam")) {
    chain <- co_get(obj, "chain")
    if (!is.null(chain) && !co_is_null(chain) &&
        identical(co_get(obj, "mechanism_status"), "absent")) {
      errors <- c(errors, paste0(
        "contradictory_seam: a drawn chain cannot carry mechanism_status ",
        "'absent' (a drawn mechanism is not absent)"))
    }
  }

  # 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
  # exactly ONE temporal dimension - a wall-clock start (optional end) or an
  # ordinal start_tick (optional end_tick), never both and never neither. Per
  # Rule 23 the two dimensions never compare. The pairing check of a
  # prediction_error against its predicted_occurrence and its observed
  # token_occurrence needs those objects and lives in
  # co_prediction_pairing_mismatch, exactly as covering_law_mismatch does.
  if (identical(kind, "predicted_occurrence")) {
    iv <- co_get(obj, "interval")
    wall <- co_is_obj(iv) && co_has(iv, "start")
    tick <- co_is_obj(iv) && co_has(iv, "start_tick")
    if (isTRUE(wall) && isTRUE(tick)) {
      errors <- c(errors, paste0(
        "dimension_conflict: a predicted interval must carry exactly one ",
        "temporal dimension, not a wall-clock start AND an ordinal start_tick"))
    }
    if (!isTRUE(wall) && !isTRUE(tick)) {
      errors <- c(errors, paste0(
        "missing_dimension: a predicted interval must carry a wall-clock ",
        "start or an ordinal start_tick"))
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

# Rule 4: temporal admissibility. For a wall-clock window `elapsed` is in
# seconds; for an ordinal ('ticks') window `elapsed` is a tick count. Ordering
# is by magnitude WITHIN the window's own dimension (3.0.0).
co_admissible <- function(cro, elapsed) {
  t <- co_get(cro, "temporal")
  if (is.null(t) || co_is_null(t)) return(TRUE)  # no window, no constraint
  unit <- as.character(t[["unit"]])
  lo <- co_magnitude(t[["minimum_delay"]], unit)
  hi <- co_magnitude(t[["maximum_delay"]], unit)
  elapsed <- as.numeric(elapsed)
  isTRUE(lo <= elapsed) && isTRUE(elapsed <= hi)
}

# Do the temporal windows of two CROs overlap (absent = overlapping)?
# 3.0.0: an ordinal window and a wall-clock window are different dimensions and
# never overlap.
co_window_overlap <- function(a, b) {
  ta <- co_get(a, "temporal")
  tb <- co_get(b, "temporal")
  if (is.null(ta) || co_is_null(ta) || is.null(tb) || co_is_null(tb)) {
    return(TRUE)
  }
  ua <- as.character(ta[["unit"]])
  ub <- as.character(tb[["unit"]])
  if (!identical(co_dimension(ua), co_dimension(ub))) return(FALSE)
  lo_a <- co_magnitude(ta[["minimum_delay"]], ua)
  hi_a <- co_magnitude(ta[["maximum_delay"]], ua)
  lo_b <- co_magnitude(tb[["minimum_delay"]], ub)
  hi_b <- co_magnitude(tb[["maximum_delay"]], ub)
  isTRUE(lo_a <= hi_b) && isTRUE(lo_b <= hi_a)
}

# Are the context sets compatible (either absent/empty, or nested/equal)?
co_contexts_compatible <- function(a, b) {
  sa <- unique(co_strings(co_get(a, "context")))
  sb <- unique(co_strings(co_get(b, "context")))
  if (length(sa) == 0L || length(sb) == 0L) return(TRUE)
  all(sa %in% sb) || all(sb %in% sa)   # subset either way covers equality
}

# Rule 6 (amended): necessary, sufficient, contributory, enabling are
# mutually compatible; preventive opposes all four.
co_positive_modalities <- c("necessary", "sufficient", "contributory", "enabling")

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

# Equality that also treats two absences (NULLs) as equal.
co_equal_or_both_absent <- function(a, b) {
  if (is.null(a) && is.null(b)) return(TRUE)
  if (is.null(a) || is.null(b)) return(FALSE)
  co_equal(a, b)
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

# ==========================================================================
# 2.0.0 NORMATIVE ALGORITHMS (Section 12)
# ==========================================================================

# ALGORITHM A. Every finer occurrent an occurrent resolves to, following
# Bridges downward, transitively. Includes the starting occurrent (N12.1.1).
# `bridges` is a list of bridge objects. Returns a character vector.
co_bridge_closure <- function(occurrent_id, bridges) {
  result <- occurrent_id
  frontier <- occurrent_id
  visited <- character(0)
  coarse_index <- list()
  for (b in bridges) {
    ck <- b[["coarse"]]
    cur <- if (co_has_key(coarse_index, ck)) coarse_index[[ck]] else list()
    cur[[length(cur) + 1L]] <- b
    coarse_index[[ck]] <- cur
  }
  while (length(frontier) > 0L) {
    current <- frontier[[length(frontier)]]
    frontier <- frontier[-length(frontier)]
    if (current %in% visited) next
    visited <- c(visited, current)
    if (co_has_key(coarse_index, current)) {
      for (b in coarse_index[[current]]) {
        for (f in co_strings(b[["fine"]])) {
          result <- c(result, f)
          frontier <- c(frontier, f)
        }
      }
    }
  }
  unique(result)
}

# Does a path exist from src to dst in an edge map (named list node -> chars)?
co_path_exists <- function(edges, src, dst) {
  seen <- character(0)
  stack <- src
  while (length(stack) > 0L) {
    node <- stack[[length(stack)]]
    stack <- stack[-length(stack)]
    if (identical(node, dst)) return(TRUE)
    if (node %in% seen) next
    seen <- c(seen, node)
    if (co_has_key(edges, node)) stack <- c(stack, edges[[node]])
  }
  FALSE
}

# ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
# "indeterminate", ACROSS STRATA via bridged reachability.
# members: named list from CRO identifier to CRO object for the mechanism
# entries. bridges: list of bridge objects (empty -> literal reachability).
co_hierarchy_consistent <- function(parent, members, bridges = list()) {
  mechanism <- co_strings(co_get(parent, "mechanism"))
  if (length(mechanism) == 0L) return("consistent")
  edges <- list()
  for (mid in mechanism) {
    m <- if (co_has_key(members, mid)) members[[mid]] else NULL
    if (is.null(m)) return("indeterminate")
    effects <- co_strings(m[["effects"]])
    for (c_id in co_strings(m[["causes"]])) {
      old <- if (co_has_key(edges, c_id)) edges[[c_id]] else character(0)
      edges[[c_id]] <- unique(c(old, effects))
    }
  }
  b_cause <- list()
  for (c_id in co_strings(parent[["causes"]])) {
    b_cause[[c_id]] <- co_bridge_closure(c_id, bridges)
  }
  b_effect <- list()
  for (e_id in co_strings(parent[["effects"]])) {
    b_effect[[e_id]] <- co_bridge_closure(e_id, bridges)
  }
  for (c_id in co_strings(parent[["causes"]])) {
    for (e_id in co_strings(parent[["effects"]])) {
      connected <- FALSE
      for (cp in b_cause[[c_id]]) {
        for (ep in b_effect[[e_id]]) {
          if (co_path_exists(edges, cp, ep)) { connected <- TRUE; break }
        }
        if (connected) break
      }
      if (!connected) return("inconsistent")
    }
  }
  "consistent"
}

# The stratum id of an occurrent id, or NULL.
.co_stratum_of <- function(occ_map, occ_id) {
  o <- if (co_has_key(occ_map, occ_id)) occ_map[[occ_id]] else NULL
  if (is.null(o)) return(NULL)
  s <- co_get(o, "stratum")
  if (is.null(s) || co_is_null(s)) NULL else s
}

# ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping" |
# "mixed" | "unclassifiable" | "scheme_mismatch".
co_classify_cro <- function(cro, occ_map, stratum_map) {
  cause_strata <- lapply(co_strings(cro[["causes"]]),
                         function(c) .co_stratum_of(occ_map, c))
  effect_strata <- lapply(co_strings(cro[["effects"]]),
                          function(e) .co_stratum_of(occ_map, e))
  all_pairs <- c(cause_strata, effect_strata)
  if (any(vapply(all_pairs, is.null, logical(1)))) return("unclassifiable")
  cs <- unlist(cause_strata); es <- unlist(effect_strata)
  all_strata <- unique(c(cs, es))
  schemes <- unique(vapply(all_strata,
                           function(s) stratum_map[[s]][["scheme"]], character(1)))
  if (length(schemes) > 1L) return("scheme_mismatch")
  c_ord <- vapply(cs, function(s) as.numeric(stratum_map[[s]][["ordinal"]]), numeric(1))
  e_ord <- vapply(es, function(s) as.numeric(stratum_map[[s]][["ordinal"]]), numeric(1))
  if (max(c_ord) == min(c_ord) && min(c_ord) == max(e_ord) &&
      max(e_ord) == min(e_ord)) {
    return("intra_stratal")
  }
  diffs <- outer(c_ord, e_ord, function(i, j) abs(i - j))
  gap <- min(diffs)
  span <- max(diffs)
  if (span == 1) return("adjacent_stratal")
  if (gap > 1) return("skipping")
  "mixed"
}

# TRUE iff causes or effects span more than one distinct stratum (N12.3.2).
co_endpoints_mixed <- function(cro, occ_map) {
  cs <- lapply(co_strings(cro[["causes"]]), function(c) .co_stratum_of(occ_map, c))
  es <- lapply(co_strings(cro[["effects"]]), function(e) .co_stratum_of(occ_map, e))
  if (any(vapply(cs, is.null, logical(1))) ||
      any(vapply(es, is.null, logical(1)))) {
    return(FALSE)
  }
  length(unique(unlist(cs))) > 1L || length(unique(unlist(es))) > 1L
}

# ALGORITHM D (Rule 16): the gaps a CRO surfaces for the skip decision.
co_skip_gaps <- function(cro, classification) {
  gaps <- character(0)
  has_mech <- length(co_strings(co_get(cro, "mechanism"))) > 0L
  if (isTRUE(co_get(cro, "skips")) && has_mech) {
    return("contradictory_skip")   # HARD
  }
  if (isTRUE(co_get(cro, "skips")) &&
      !(classification %in% c("skipping", "unclassifiable"))) {
    gaps <- c(gaps, "vacuous_skip")  # invitation
  }
  if (identical(classification, "skipping") && !has_mech) {
    if (isTRUE(co_get(cro, "skips"))) {
      # NOTHING: absence is a finding
    } else {
      gaps <- c(gaps, "incomplete_mechanism")  # invitation
    }
  }
  gaps
}

# ALGORITHM E helper: normalize a delay to seconds by the fixed table.
# 3.0.0: an ordinal ('ticks') unit is dimensionless and has NO wall-clock
# mapping - converting one to seconds is a category error and is refused.
co_to_seconds <- function(duration, unit) {
  if (unit %in% names(co_ordinal_units)) {
    stop(sprintf(paste0("'%s' is an ordinal (dimensionless) unit and has no ",
                        "wall-clock seconds mapping"), unit), call. = FALSE)
  }
  if (identical(unit, "instant")) return(0)
  as.numeric(duration) * co_unit_seconds[[unit]]
}

# ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
# temporal window? Inclusive at both ends (N12.5.2). 3.0.0: an ordinal delay
# compares to an ordinal window by integer tick count; an ordinal delay and a
# wall-clock window (or vice versa) are different dimensions and never fall
# within one another.
co_delay_within_window <- function(actual_delay, temporal) {
  if (is.null(actual_delay) || co_is_null(actual_delay) ||
      is.null(temporal) || co_is_null(temporal)) {
    return(TRUE)
  }
  du <- as.character(actual_delay[["unit"]])
  tu <- as.character(temporal[["unit"]])
  if (!identical(co_dimension(du), co_dimension(tu))) return(FALSE)
  observed <- co_magnitude(actual_delay[["duration"]], du)
  lo <- co_magnitude(temporal[["minimum_delay"]], tu)
  hi <- co_magnitude(temporal[["maximum_delay"]], tu)
  isTRUE(lo <= observed) && isTRUE(observed <= hi)
}

# Rule 14 / N3.2.1: Bridge well-formedness. list(ok, reason).
co_bridge_wellformed <- function(bridge, occ_map, stratum_map) {
  coarse <- if (co_has_key(occ_map, bridge[["coarse"]])) {
    occ_map[[bridge[["coarse"]]]]
  } else co_obj()
  cs <- co_get(coarse, "stratum")
  if (is.null(cs) || co_is_null(cs)) {
    return(list(ok = FALSE, reason = "malformed_bridge: coarse has no stratum (a)"))
  }
  fine_ids <- co_strings(bridge[["fine"]])
  fine_strata <- lapply(fine_ids, function(f) .co_stratum_of(occ_map, f))
  if (any(vapply(fine_strata, is.null, logical(1)))) {
    return(list(ok = FALSE,
                reason = "malformed_bridge: a fine member has no stratum (b)"))
  }
  fine_strata <- unlist(fine_strata)
  if (length(unique(fine_strata)) != 1L) {
    return(list(ok = FALSE,
                reason = "malformed_bridge: fine members span >1 stratum (c)"))
  }
  fs <- fine_strata[[1]]
  if (!identical(stratum_map[[cs]][["scheme"]], stratum_map[[fs]][["scheme"]])) {
    return(list(ok = FALSE,
                reason = "malformed_bridge: coarse and fine differ in scheme (d)"))
  }
  if (!(as.numeric(stratum_map[[cs]][["ordinal"]]) >
        as.numeric(stratum_map[[fs]][["ordinal"]]))) {
    return(list(ok = FALSE,
                reason = "malformed_bridge: coarse ordinal not > fine ordinal (e)"))
  }
  list(ok = TRUE, reason = "well-formed bridge")
}

# 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness. list(ok,
# reason). All of (a)-(g) must hold, else malformed_seam. A seam is a MANAGED
# jump across NON-ADJACENT strata; when it DRAWS a chain, the chain must be an
# adjacent-stratum path spanning the two endpoints' strata.
co_seam_wellformed <- function(seam, occ_map, stratum_map) {
  src_s <- .co_stratum_of(occ_map, as.character(seam[["source"]]))
  tgt_s <- .co_stratum_of(occ_map, as.character(seam[["target"]]))
  if (is.null(src_s) || is.null(tgt_s)) {
    return(list(ok = FALSE,
                reason = "malformed_seam: an endpoint has no stratum (a)"))
  }
  if (!identical(stratum_map[[src_s]][["scheme"]],
                 stratum_map[[tgt_s]][["scheme"]])) {
    return(list(ok = FALSE,
                reason = "malformed_seam: endpoints differ in scheme (b)"))
  }
  so <- as.numeric(stratum_map[[src_s]][["ordinal"]])
  to_ <- as.numeric(stratum_map[[tgt_s]][["ordinal"]])
  if (abs(so - to_) <= 1) {
    return(list(ok = FALSE, reason = paste0(
      "malformed_seam: endpoints are adjacent or co-stratal; ",
      "a seam is for NON-adjacent strata (c)")))
  }
  chain <- co_get(seam, "chain")
  if (!is.null(chain) && !co_is_null(chain)) {
    if (identical(co_get(seam, "mechanism_status"), "absent")) {
      return(list(ok = FALSE, reason = paste0(
        "malformed_seam: a drawn chain contradicts mechanism_status ",
        "'absent' (d)")))
    }
    lo <- min(so, to_); hi <- max(so, to_)
    ords <- numeric(0)
    for (oid in co_strings(chain)) {
      st <- .co_stratum_of(occ_map, oid)
      if (is.null(st)) {
        return(list(ok = FALSE,
                    reason = "malformed_seam: a chain member has no stratum (e)"))
      }
      if (!identical(stratum_map[[st]][["scheme"]],
                     stratum_map[[src_s]][["scheme"]])) {
        return(list(ok = FALSE,
                    reason = "malformed_seam: a chain member differs in scheme (e)"))
      }
      ords <- c(ords, as.numeric(stratum_map[[st]][["ordinal"]]))
    }
    if (!all(lo < ords & ords < hi)) {
      return(list(ok = FALSE, reason = paste0(
        "malformed_seam: a chain member is not at an INTERVENING stratum, ",
        "strictly between the endpoints (f)")))
    }
    if (length(ords) >= 2L) {
      diffs <- diff(ords)
      if (!(all(diffs > 0) || all(diffs < 0))) {
        return(list(ok = FALSE, reason = paste0(
          "malformed_seam: chain is not strictly monotone from one endpoint ",
          "toward the other (g)")))
      }
    }
  }
  list(ok = TRUE, reason = "well-formed cross_stratal_seam")
}

# THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST stratum it
# touches - the endpoint of the greater ordinal. Returns that stratum's
# identifier (NULL if an endpoint is unstratified).
co_seam_home <- function(seam, occ_map, stratum_map) {
  src_s <- .co_stratum_of(occ_map, as.character(seam[["source"]]))
  tgt_s <- .co_stratum_of(occ_map, as.character(seam[["target"]]))
  if (is.null(src_s) || is.null(tgt_s)) return(NULL)
  if (as.numeric(stratum_map[[src_s]][["ordinal"]]) >=
      as.numeric(stratum_map[[tgt_s]][["ordinal"]])) {
    src_s
  } else {
    tgt_s
  }
}

# Rule 17 / N4.2.1-2: Conduit well-formedness. list(ok, reason).
co_conduit_wellformed <- function(conduit, port_map, cro_map = list()) {
  frm <- if (co_has_key(port_map, conduit[["from"]])) port_map[[conduit[["from"]]]] else NULL
  to  <- if (co_has_key(port_map, conduit[["to"]])) port_map[[conduit[["to"]]]] else NULL
  if (is.null(frm) || is.null(to)) {
    return(list(ok = FALSE, reason = "malformed_conduit: dangling port reference"))
  }
  if (!(co_get(frm, "direction") %in% c("out", "bidirectional"))) {
    return(list(ok = FALSE,
                reason = "malformed_conduit: from port is not out/bidirectional (a)"))
  }
  if (!(co_get(to, "direction") %in% c("in", "bidirectional"))) {
    return(list(ok = FALSE,
                reason = "malformed_conduit: to port is not in/bidirectional (b)"))
  }
  carries <- co_strings(conduit[["carries"]])
  frm_accepts <- co_strings(frm[["accepts"]])
  if (!all(carries %in% frm_accepts)) {
    return(list(ok = FALSE,
                reason = "malformed_conduit: carries not accepted by from (c)"))
  }
  transform <- co_get(conduit, "transform")
  to_accepts <- co_strings(to[["accepts"]])
  if (is.null(transform) || co_is_null(transform)) {
    if (!all(carries %in% to_accepts)) {
      return(list(ok = FALSE,
                  reason = "malformed_conduit: carries not accepted by to (d)"))
    }
  } else {
    law <- if (co_has_key(cro_map, transform)) cro_map[[transform]] else NULL
    if (!is.null(law)) {
      if (!all(co_strings(law[["effects"]]) %in% to_accepts)) {
        return(list(ok = FALSE, reason = paste0(
          "malformed_conduit: transform effects not accepted by to ",
          "(d, relaxed per N4.2.2)")))
      }
    }
  }
  list(ok = TRUE, reason = "well-formed conduit")
}

# Rule 19 / N5.3.1-2: State value type and unit coherence. Returns the HARD
# gaps a state assertion surfaces against its quality.
co_state_gaps <- function(state, quality) {
  gaps <- character(0)
  dt <- co_get(quality, "datatype")
  v <- co_get(state, "value", co_obj())
  shape <- if (co_has(v, "quantity")) "quantity"
    else if (co_has(v, "categorical")) "categorical"
    else if (co_has(v, "boolean")) "boolean"
    else NULL
  if (!identical(shape, dt)) {
    gaps <- c(gaps, "value_type_mismatch")
  } else if (identical(dt, "quantity") &&
             !identical(co_get(v, "unit"), co_get(quality, "unit"))) {
    gaps <- c(gaps, "unit_mismatch")
  }
  gaps
}

# Rule 20: covering-law coherence. TRUE iff mismatched.
co_covering_law_mismatch <- function(tcc, token_map, law) {
  if (is.null(law) || co_is_null(law)) return(FALSE)
  law_causes <- co_strings(law[["causes"]])
  law_effects <- co_strings(law[["effects"]])
  for (c_id in co_strings(tcc[["causes"]])) {
    if (!(token_map[[c_id]][["instantiates"]] %in% law_causes)) return(TRUE)
  }
  for (e_id in co_strings(tcc[["effects"]])) {
    if (!(token_map[[e_id]][["instantiates"]] %in% law_effects)) return(TRUE)
  }
  FALSE
}

# 4.0.0 Rule 24: prediction-to-observation pairing. TRUE iff the prediction
# error's observed token does not instantiate the occurrent its
# predicted_occurrence instantiates. An ABSENT observed is never a mismatch - it
# means the predicted occurrence was not fulfilled by any recorded occurrence.
co_prediction_pairing_mismatch <- function(error, predicted, observed) {
  if (!co_has(error, "observed") || is.null(observed) || co_is_null(observed)) {
    return(FALSE)
  }
  !identical(as.character(observed[["instantiates"]]),
             as.character(predicted[["instantiates"]]))
}

# Rule 21: temporal coherence of token causation. TRUE iff retrocausal.
co_retrocausal <- function(tcc, token_map) {
  for (c_id in co_strings(tcc[["causes"]])) {
    cstart <- token_map[[c_id]][["interval"]][["start"]]
    for (e_id in co_strings(tcc[["effects"]])) {
      estart <- token_map[[e_id]][["interval"]][["start"]]
      if (co_str_gt(cstart, estart)) return(TRUE)
    }
  }
  FALSE
}

# Rules 4 / 6.1: generic acyclicity for the new graph relations. `edges` is
# a named list node -> character vector of successors.
co_has_cycle <- function(edges) {
  state <- new.env(parent = emptyenv())  # node -> 1 grey | 2 black
  node_state <- function(n) if (exists(n, envir = state, inherits = FALSE)) {
    get(n, envir = state, inherits = FALSE)
  } else 0L
  visit <- function(node) {
    assign(node, 1L, envir = state)
    succs <- if (co_has_key(edges, node)) edges[[node]] else character(0)
    for (nxt in succs) {
      s <- node_state(nxt)
      if (s == 1L) return(TRUE)
      if (s == 0L && visit(nxt)) return(TRUE)
    }
    assign(node, 2L, envir = state)
    FALSE
  }
  for (n in names(edges)) {
    if (node_state(n) == 0L && visit(n)) return(TRUE)
  }
  FALSE
}

# causalontology-r -- store.R
#
# An in-memory conformant store, ported from the CURRENT reference
# bindings/python/causalontology/store.py.
#
# Implements the store side of the abstract operation set (spec/store.md):
# immutable content objects with idempotent put; signed, add-only
# provenance records; materialized enrichment views with contributors;
# retraction handling in default views; succession lineage; the resolve
# minimum; the deterministic cycle-breaking view rule; and the stigmergy
# gap read.
#
# The store is an R environment (mutable state, idiomatic in base R). Its
# objects / records / quarantine members are NAMED LISTS keyed by
# identifier: named lists preserve insertion order, so every iteration
# below (names(s$objects), names(s$records)) deliberately mirrors the
# Python dict iteration order of the reference.

co_content_kinds <- c("occurrent", "causal_relation_object", "continuant",
                      "realizable", "stratum", "bridge", "port", "conduit",
                      "quality", "token_individual", "token_occurrence",
                      "state_assertion", "token_causal_claim")
co_record_kinds  <- c("assertion", "enrichment", "retraction", "succession")

# Raise the RejectedWrite condition (catch with
# tryCatch(..., co_rejected_write = function(e) ...)).
co_rejected <- function(msg) {
  stop(structure(class = c("co_rejected_write", "error", "condition"),
                 list(message = msg, call = NULL)))
}

# A new store; enforcing = TRUE applies the write-time cycle gate.
co_store_new <- function(enforcing = TRUE) {
  s <- new.env(parent = emptyenv())
  s$enforcing <- isTRUE(enforcing)
  s$objects <- list()      # id -> content object (insertion ordered)
  s$records <- list()      # id -> provenance record (insertion ordered)
  s$quarantine <- list()   # id -> record (unsigned / unverifiable)
  class(s) <- "co_store"
  s
}

# ----------------------------------------------------------------- put
# Write a content object; idempotent; returns the identifier.
co_store_put <- function(s, obj, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(obj)
  if (!(kind %in% co_content_kinds)) {
    stop("co_store_put() takes content objects; use co_store_put_record()")
  }
  if (!co_has(obj, "type")) obj[["type"]] <- kind
  if (!co_has(obj, "id")) obj[["id"]] <- co_identify(obj, kind)
  oid <- obj[["id"]]
  if (co_has_key(s$objects, oid)) {
    return(oid)   # immutable: identical identity is a no-op
  }
  r <- co_validate_schema(obj, kind)
  if (!r$ok) co_rejected(paste(r$errors, collapse = "; "))
  r <- co_validate_semantics(obj, kind)
  if (!r$ok) co_rejected(paste(r$errors, collapse = "; "))
  s$objects[[oid]] <- obj
  oid
}

# Write a signed provenance record; returns the identifier.
co_store_put_record <- function(s, record, kind = NULL, force = FALSE) {
  if (is.null(kind)) kind <- co_infer_kind(record)
  if (!(kind %in% co_record_kinds)) {
    stop("co_store_put_record() takes provenance records")
  }
  if (!co_has(record, "type")) record[["type"]] <- kind
  rid <- co_get(record, "id")
  if (is.null(rid) || co_is_null(rid) || !nzchar(as.character(rid)[[1]])) {
    rid <- co_identify(record, kind)
  }
  record[["id"]] <- rid
  if (co_has_key(s$records, rid)) {
    return(rid)   # add-only and idempotent
  }
  if (!co_verify_record(record, kind)) {
    s$quarantine[[rid]] <- record
    co_rejected("unsigned or unverifiable record: quarantined")
  }
  r <- co_validate_semantics(record, kind)
  if (!r$ok) co_rejected(paste(r$errors, collapse = "; "))
  if (identical(kind, "retraction") && !co_retraction_source_ok(s, record)) {
    co_rejected(paste0(
      "a retraction is valid only from the retracted record's ",
      "source or its succession lineage"))
  }
  if (identical(kind, "enrichment") && s$enforcing && !isTRUE(force)) {
    if (record[["field"]] %in% c("subsumes", "part_of") &&
        co_store_would_cycle(s, record)) {
      co_rejected(sprintf(
        "would create a cycle in the materialized %s graph",
        record[["field"]]))
    }
  }
  s$records[[rid]] <- record
  rid
}

# Simulate a decentralized replica merge (no enforcement gate).
co_store_force_merge_record <- function(s, record, kind = NULL) {
  co_store_put_record(s, record, kind, force = TRUE)
}

# ------------------------------------------------------ record queries
# All records of one kind, in insertion order.
co_records_of <- function(s, kind) {
  out <- list()
  for (rid in names(s$records)) {
    r <- s$records[[rid]]
    if (identical(co_get(r, "type"), kind)) out[[length(out) + 1L]] <- r
  }
  out
}

# The identifiers of every retracted record.
co_retracted_ids <- function(s) {
  out <- character(0)
  for (r in co_records_of(s, "retraction")) out <- c(out, r[["retracts"]])
  unique(out)
}

# May this retraction's source retract its target?
co_retraction_source_ok <- function(s, retraction) {
  target_id <- retraction[["retracts"]]
  target <- if (co_has_key(s$records, target_id)) {
    s$records[[target_id]]
  } else {
    NULL
  }
  if (is.null(target)) return(TRUE)  # open world: target may arrive later
  retraction[["source"]] %in% co_store_lineage(s, target[["source"]])
}

# The succession chain closure containing key (includes key).
co_store_lineage <- function(s, key) {
  succ <- list()
  pred <- list()
  for (rec in co_records_of(s, "succession")) {
    succ[[rec[["predecessor"]]]] <- rec[["successor"]]
    pred[[rec[["successor"]]]] <- rec[["predecessor"]]
  }
  chain <- key
  cursor <- key
  while (co_has_key(pred, cursor)) {
    cursor <- pred[[cursor]]
    chain <- c(chain, cursor)
  }
  cursor <- key
  while (co_has_key(succ, cursor)) {
    cursor <- succ[[cursor]]
    chain <- c(chain, cursor)
  }
  unique(chain)
}

# The assertions about one identifier (default views exclude retracted).
co_store_assertions_about <- function(s, identifier,
                                      include_retracted = FALSE) {
  retracted <- co_retracted_ids(s)
  out <- list()
  for (r in co_records_of(s, "assertion")) {
    if (!identical(r[["about"]], identifier)) next
    if (r[["id"]] %in% retracted) {
      if (include_retracted) {
        r[["retracted"]] <- TRUE      # a copy: flags the history view only
        out[[length(out) + 1L]] <- r
      }
      next
    }
    out[[length(out) + 1L]] <- r
  }
  out
}

# The enrichments about one identifier.
co_store_enrichments_about <- function(s, identifier,
                                       include_retracted = FALSE) {
  retracted <- co_retracted_ids(s)
  out <- list()
  for (r in co_records_of(s, "enrichment")) {
    if (!identical(r[["about"]], identifier)) next
    if (r[["id"]] %in% retracted && !include_retracted) next
    out[[length(out) + 1L]] <- r
  }
  out
}

# ------------------------------------------------ materialized views
# a strictly follows b in (timestamp, id) order? Compared timestamp
# first, then id, each by Unicode code points (never locale collation).
co_ts_id_gt <- function(a, b) {
  ta <- a[["timestamp"]]
  tb <- b[["timestamp"]]
  if (!identical(ta, tb)) return(co_str_gt(ta, tb))
  co_str_gt(a[["id"]], b[["id"]])
}

# list(active, excluded) for subsumes/part_of after rule 13 cycle-breaking.
co_active_taxonomy_edges <- function(s, field) {
  retracted <- co_retracted_ids(s)
  active <- list()
  for (r in co_records_of(s, "enrichment")) {
    if (identical(r[["field"]], field) && !(r[["id"]] %in% retracted)) {
      active[[length(active) + 1L]] <- r
    }
  }
  excluded <- list()
  repeat {
    cyc <- co_find_cycle_records(active)
    if (length(cyc) == 0L) break
    # exclude the cycle-completing record with the LATEST timestamp,
    # ties broken by lexicographic record identifier (deterministic)
    li <- 1L
    for (i in seq_along(cyc)) {
      if (co_ts_id_gt(cyc[[i]], cyc[[li]])) li <- i
    }
    loser <- cyc[[li]]
    keep <- list()
    for (r in active) {   # remove exactly the loser (records are id-unique)
      if (!identical(r[["id"]], loser[["id"]])) keep[[length(keep) + 1L]] <- r
    }
    active <- keep
    excluded[[length(excluded) + 1L]] <- loser
  }
  list(active = active, excluded = excluded)
}

# The records forming one directed cycle in about -> entry edges, or an
# empty list (a depth-first search with the white/grey/black coloring).
co_find_cycle_records <- function(recs) {
  edges <- list()   # about -> list of list(entry, rec), insertion ordered
  for (r in recs) {
    ab <- r[["about"]]
    cur <- if (co_has_key(edges, ab)) edges[[ab]] else list()
    cur[[length(cur) + 1L]] <- list(entry = r[["entry"]], rec = r)
    edges[[ab]] <- cur
  }
  state <- new.env(parent = emptyenv())   # node -> 1 (grey) | 2 (black)
  cycle <- list()
  node_state <- function(node) {
    if (exists(node, envir = state, inherits = FALSE)) {
      get(node, envir = state, inherits = FALSE)
    } else {
      0L
    }
  }
  dfs <- function(node, path_records) {
    assign(node, 1L, envir = state)
    outs <- if (co_has_key(edges, node)) edges[[node]] else list()
    for (pair in outs) {
      nxt <- pair[["entry"]]
      rec <- pair[["rec"]]
      st <- node_state(nxt)
      if (st == 1L) {
        cycle <<- c(path_records, list(rec))
        return(TRUE)
      }
      if (st == 0L) {
        if (dfs(nxt, c(path_records, list(rec)))) return(TRUE)
      }
    }
    assign(node, 2L, envir = state)
    FALSE
  }
  for (start in names(edges)) {
    if (node_state(start) == 0L && dfs(start, list())) return(cycle)
  }
  list()
}

# Would accepting this record close a cycle in its field's active graph?
co_store_would_cycle <- function(s, record) {
  retracted <- co_retracted_ids(s)
  recs <- list()
  for (r in co_records_of(s, "enrichment")) {
    if (identical(r[["field"]], record[["field"]]) &&
        !(r[["id"]] %in% retracted)) {
      recs[[length(recs) + 1L]] <- r
    }
  }
  recs[[length(recs) + 1L]] <- record
  length(co_find_cycle_records(recs)) > 0L
}

# The object with its materialized enrichment sets and contributors.
# view: "default" | "history" | "raw". Returns NULL for an unknown id.
co_store_get <- function(s, identifier, view = "default") {
  obj <- if (co_has_key(s$objects, identifier)) {
    s$objects[[identifier]]
  } else {
    NULL
  }
  if (is.null(obj)) return(NULL)
  include_retracted <- identical(view, "history")
  excluded_ids <- character(0)
  for (field in c("subsumes", "part_of")) {
    ate <- co_active_taxonomy_edges(s, field)
    for (r in ate$excluded) excluded_ids <- c(excluded_ids, r[["id"]])
  }
  field_slots <- list()   # field -> (named list: entry key -> bucket)
  for (rec in co_store_enrichments_about(s, identifier, include_retracted)) {
    if (rec[["id"]] %in% excluded_ids && !identical(view, "history")) next
    # canonical entry key: JCS text of the entry (sorted keys), so the
    # same entry from two sources lands in one bucket -- the reference's
    # tuple(sorted(entry.items())) dedup, in canonical-string form
    entry_key <- co_jcs(rec[["entry"]])
    fld <- rec[["field"]]
    slot <- if (co_has_key(field_slots, fld)) field_slots[[fld]] else list()
    bucket <- if (co_has_key(slot, entry_key)) {
      slot[[entry_key]]
    } else {
      list(entry = rec[["entry"]], contributors = list())
    }
    bucket$contributors[[length(bucket$contributors) + 1L]] <-
      list(source = rec[["source"]], timestamp = rec[["timestamp"]])
    slot[[entry_key]] <- bucket
    field_slots[[fld]] <- slot
  }
  enrichments <- list()
  for (fld in names(field_slots)) {
    buckets <- list()
    for (k in names(field_slots[[fld]])) {
      buckets[[length(buckets) + 1L]] <- field_slots[[fld]][[k]]
    }
    enrichments[[fld]] <- buckets
  }
  if (identical(view, "raw")) return(list(object = obj))
  list(object = obj, enrichments = enrichments)
}

# -------------------------------------------------------------- resolve
# canonical-label form: lowercase, whitespace runs to single underscores
co_canon_label <- function(text) {
  parts <- strsplit(trimws(tolower(text)), "[[:space:]]+")[[1]]
  parts <- parts[nzchar(parts)]
  paste(parts, collapse = "_")
}

# normalized alias form: whitespace runs to single spaces, case folded
co_norm_alias <- function(text) {
  parts <- strsplit(text, "[[:space:]]+")[[1]]
  parts <- parts[nzchar(parts)]
  tolower(paste(parts, collapse = " "))
}

# The conformance minimum: exact label, then alias, then nothing.
# Returns a character vector of identifiers, label hits ranked first.
co_store_resolve <- function(s, text, lang = NULL) {
  label_hits <- character(0)
  alias_hits <- character(0)
  wanted_label <- co_canon_label(text)
  wanted_alias <- co_norm_alias(text)
  retracted <- co_retracted_ids(s)
  enrichment_records <- co_records_of(s, "enrichment")
  for (oid in names(s$objects)) {
    obj <- s$objects[[oid]]
    ty <- co_get(obj, "type")
    if (!(identical(ty, "occurrent") || identical(ty, "continuant"))) next
    if (identical(co_get(obj, "label"), wanted_label)) {
      label_hits <- c(label_hits, oid)
      next
    }
    for (rec in enrichment_records) {
      if (!identical(rec[["about"]], oid) ||
          !identical(rec[["field"]], "aliases")) next
      if (rec[["id"]] %in% retracted) next
      entry <- rec[["entry"]]
      if (!is.null(lang) && !identical(co_get(entry, "lang"), lang)) next
      if (identical(co_norm_alias(co_get(entry, "text", "")), wanted_alias)) {
        alias_hits <- c(alias_hits, oid)
        break
      }
    }
  }
  c(label_hits, alias_hits)
}

# ---------------------------------------------------------------- gaps
# The stigmergy read. Gap kinds per spec/store.md. Returns a list of
# gap records (plain named lists).
co_store_gaps <- function(s, kind = NULL) {
  out <- list()
  # which parents are closed by a valid refinement already in the store
  refined <- character(0)
  for (oid in names(s$objects)) {
    obj <- s$objects[[oid]]
    if (!identical(co_get(obj, "type"), "causal_relation_object")) next
    ref <- co_get(obj, "refines")
    if (!co_is_str(ref) || !nzchar(ref)) next
    parent <- if (co_has_key(s$objects, ref)) s$objects[[ref]] else NULL
    if (is.null(parent)) next
    rv <- co_refinement_valid(obj, parent)
    if (rv$ok) refined <- c(refined, parent[["id"]])
  }
  for (oid in names(s$objects)) {
    obj <- s$objects[[oid]]
    if (!identical(co_get(obj, "type"), "causal_relation_object")) next
    # missing_field: lacking the temporal window or the modality --
    # mechanism and context may legitimately stay unspecified forever
    # (empty_mechanism is its own kind; absent context = context-free).
    if ((!co_has(obj, "temporal") || !co_has(obj, "modality")) &&
        !(oid %in% refined)) {
      out[[length(out) + 1L]] <- list(id = oid, kind = "missing_field",
                                      missing = co_is_partial(obj)$missing)
    }
    mech <- co_get(obj, "mechanism")
    if (!co_has(obj, "mechanism") ||
        (co_is_arr(mech) && length(mech) == 0L)) {
      if (!(oid %in% refined)) {
        out[[length(out) + 1L]] <- list(id = oid, kind = "empty_mechanism")
      }
    }
  }
  for (field in c("subsumes", "part_of")) {
    ate <- co_active_taxonomy_edges(s, field)
    for (rec in ate$excluded) {
      out[[length(out) + 1L]] <- list(
        id = rec[["id"]], kind = "inconsistent_hierarchy",
        note = paste0("excluded by the deterministic ",
                      "cycle-breaking view rule"))
    }
  }
  # dangling_reference: a reference to an object absent from the store --
  # the red link that says "this page is wanted".
  for (oid in names(s$objects)) {
    obj <- s$objects[[oid]]
    ty <- co_get(obj, "type")
    refs <- character(0)
    if (identical(ty, "causal_relation_object")) {
      refs <- c(co_strings(co_get(obj, "causes")),
                co_strings(co_get(obj, "effects")),
                co_strings(co_get(obj, "context")),
                co_strings(co_get(obj, "mechanism")))
      ref <- co_get(obj, "refines")
      if (co_is_str(ref) && nzchar(ref)) refs <- c(refs, ref)
    } else if (identical(ty, "realizable")) {
      bearer <- co_get(obj, "bearer")
      if (co_is_str(bearer)) refs <- c(refs, bearer)
    }
    for (ref in refs) {
      if (nzchar(ref) && !co_has_key(s$objects, ref)) {
        out[[length(out) + 1L]] <- list(id = oid,
                                        kind = "dangling_reference",
                                        ref = ref)
      }
    }
  }
  # conflict: pairs of claims satisfying the formal test (rule 6).
  cros <- list()
  for (oid in names(s$objects)) {
    obj <- s$objects[[oid]]
    if (identical(co_get(obj, "type"), "causal_relation_object")) {
      cros[[length(cros) + 1L]] <- obj
    }
  }
  n <- length(cros)
  if (n >= 2L) {                       # seq_len / seq.int: no 1:0 trap
    for (i in seq_len(n - 1L)) {
      for (j in seq.int(i + 1L, n)) {
        if (co_conflicts(cros[[i]], cros[[j]])) {
          out[[length(out) + 1L]] <- list(kind = "conflict",
                                          a = cros[[i]][["id"]],
                                          b = cros[[j]][["id"]])
        }
      }
    }
  }
  if (!is.null(kind)) {
    filtered <- list()
    for (g in out) {
      if (identical(g[["kind"]], kind)) filtered[[length(filtered) + 1L]] <- g
    }
    out <- filtered
  }
  out
}

#!/usr/bin/env Rscript
# The Causalontology conformance runner for causalontology-r (spec 2.0.0).
#
# Runs every vector in conformance/vectors/ against the R binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure. It mirrors the reference harness
# bindings/python/tests/run_conformance.py vector for vector (V01-V107).
#
# The vectors are the whole-word 2.0.0 baseline (Principle P7): V01-V38 are
# the 1.0.0 suite re-frozen unaltered in meaning, V39-V107 are new.
#
# Run from anywhere:   Rscript bindings/r/conformance.R
# Crypto: SHA-256 is pure base R; Ed25519 (RFC 8032) is delegated to the
# system `openssl` command-line tool. No CRAN package is required.

# --------------------------------------------------------------------------
# locate the binding directory and the repository root, then load the code
# --------------------------------------------------------------------------

co_main_args <- commandArgs(trailingOnly = FALSE)
co_file_arg <- grep("^--file=", co_main_args, value = TRUE)
if (length(co_file_arg) >= 1L) {
  co_script_path <- normalizePath(sub("^--file=", "", co_file_arg[[1]]))
  co_binding_dir <- dirname(co_script_path)
} else {
  co_binding_dir <- file.path(normalizePath(getwd()), "bindings", "r")
}

for (co_src in c("json.R", "jcs.R", "canonical.R", "signing.R",
                 "schema.R", "semantics.R", "store.R")) {
  source(file.path(co_binding_dir, "R", co_src))
}

co_root_candidate <- dirname(dirname(co_binding_dir))   # bindings/r -> root
if (dir.exists(file.path(co_root_candidate, "conformance", "vectors"))) {
  co_set_root(co_root_candidate)
} else {
  co_set_root(co_repo_root())
}
co_vecdir <- file.path(co_repo_root(), "conformance", "vectors")

# --------------------------------------------------------------------------
# small assertion helper
# --------------------------------------------------------------------------

check <- function(cond, msg = "assertion failed") {
  if (!isTRUE(cond)) stop(msg, call. = FALSE)
  invisible(TRUE)
}

# --------------------------------------------------------------------------
# whole-word scheme normalization (Principle P7)
# --------------------------------------------------------------------------

co_schemes <- c("occurrent", "causal_relation_object", "continuant",
                "realizable", "assertion", "enrichment", "retraction",
                "succession", "stratum", "bridge", "port", "conduit",
                "quality", "token_individual", "token_occurrence",
                "state_assertion", "token_causal_claim")
co_whole_word <- c(co_schemes, "ed25519")
co_schemes_pattern <- paste0("^(", paste(co_whole_word, collapse = "|"), "):")

key_cache <- new.env(parent = emptyenv())

# A real, deterministic Ed25519 keypair for a symbolic key name.
key <- function(name) {
  if (!exists(name, envir = key_cache, inherits = FALSE)) {
    seed <- co_sha256_raw(co_utf8(paste0("key:", name)))
    assign(name, co_keypair_from_seed(seed), envir = key_cache)
  }
  get(name, envir = key_cache, inherits = FALSE)
}

# Normalize one symbolic identifier to a well-formed one.
sym <- function(s) {
  idx <- regexpr(":", s, fixed = TRUE)
  scheme <- substr(s, 1L, idx - 1L)
  name <- substring(s, idx + 1L)
  if (identical(scheme, "ed25519")) {
    if (grepl("^[0-9a-f]{64}$", name)) return(s)  # frozen: a real key
    return(key(name)$public)
  }
  if (grepl("^[0-9a-f]{64}$", name)) return(s)    # frozen: a real id
  paste0(scheme, ":", co_sha256_hex(co_utf8(name)))
}

# Recursively normalize symbolic identifiers and placeholders.
normalize <- function(x) {
  if (co_is_str(x)) {
    if (identical(x, "<128 hex>")) return(strrep("ab", 64L))
    if (grepl(co_schemes_pattern, x)) return(sym(x))
    return(x)
  }
  if (co_is_arr(x)) {
    for (i in seq_along(x)) x[[i]] <- normalize(x[[i]])
    return(x)
  }
  if (co_is_obj(x)) {
    for (k in names(x)) x[[k]] <- normalize(x[[k]])
    return(x)
  }
  x
}

# Vector n's file path (exactly one match required).
vecfile <- function(n) {
  hits <- Sys.glob(file.path(co_vecdir, sprintf("v%02d_*.json", n)))
  if (length(hits) != 1L) stop("vector ", n, " not found")
  hits[[1]]
}

vec <- function(n) {
  text <- paste(readLines(vecfile(n), warn = FALSE, encoding = "UTF-8"),
                collapse = "\n")
  co_parse_json(text)
}

co_ts <- function(i) sprintf("2026-07-13T0%d:00:00Z", i)

# Build, timestamp, and sign a provenance record.
signed <- function(kind, body, who, ts_i = 0L) {
  kp <- key(who)
  rec <- body
  rec[["type"]] <- kind
  if (!co_has(rec, "timestamp")) rec[["timestamp"]] <- co_ts(ts_i)
  if (identical(kind, "succession")) {
    if (!co_has(rec, "predecessor")) rec[["predecessor"]] <- kp$public
  } else {
    rec[["source"]] <- kp$public
  }
  co_sign_record(rec, kp$secret, kind)
}

# A content object completed with its real content-addressed id.
mk <- function(o) { o[["id"]] <- co_identify(o); o }

# Run an expression expecting a RejectedWrite; returns its message or NULL.
rejected_message <- function(expr) {
  tryCatch({ force(expr); NULL },
           co_rejected_write = function(e) conditionMessage(e))
}

# The ids carried by a list of gap records.
gap_ids <- function(gaps) {
  if (length(gaps) == 0L) return(character(0))
  out <- character(0)
  for (g in gaps) if (co_has_key(g, "id")) out <- c(out, g[["id"]])
  out
}

# --------------------------------------------------------------------------
# builders (mirror the reference harness)
# --------------------------------------------------------------------------

b_stratum <- function(label, scheme, ordinal, unit = NULL, governs = NULL) {
  o <- co_obj(type = "stratum", label = label, scheme = scheme, ordinal = ordinal)
  if (!is.null(unit)) o[["unit"]] <- unit
  if (!is.null(governs)) o[["governs"]] <- co_arr_from(governs)
  mk(o)
}

b_occ <- function(label, stratum_id = NULL, category = "event") {
  o <- co_obj(type = "occurrent", label = label, category = category)
  if (!is.null(stratum_id)) o[["stratum"]] <- stratum_id
  mk(o)
}

b_cnt <- function(label, category = "object") {
  mk(co_obj(type = "continuant", label = label, category = category))
}

b_cro <- function(causes, effects, ...) {
  o <- co_obj(type = "causal_relation_object",
              causes = co_arr_from(causes), effects = co_arr_from(effects))
  extra <- list(...)
  for (nm in names(extra)) o[[nm]] <- co_wrap(extra[[nm]])
  mk(o)
}

b_bridge <- function(coarse, fine, relation) {
  mk(co_obj(type = "bridge", coarse = coarse, fine = co_arr_from(fine),
            relation = relation))
}

b_port <- function(bearer, label, direction, accepts, realizable = NULL) {
  o <- co_obj(type = "port", bearer = bearer, label = label,
              direction = direction, accepts = co_arr_from(accepts))
  if (!is.null(realizable)) o[["realizable"]] <- realizable
  mk(o)
}

b_conduit <- function(frm, to, carries, label = "conn", transform = NULL) {
  o <- co_obj(type = "conduit", label = label, from = frm, to = to,
              carries = co_arr_from(carries))
  if (!is.null(transform)) o[["transform"]] <- transform
  mk(o)
}

b_quality <- function(label, datatype, unit = NULL, stratum_id = NULL) {
  o <- co_obj(type = "quality", label = label, datatype = datatype)
  if (!is.null(unit)) o[["unit"]] <- unit
  if (!is.null(stratum_id)) o[["stratum"]] <- stratum_id
  mk(o)
}

b_individual <- function(instantiates, designator = NULL, part_of = NULL) {
  o <- co_obj(type = "token_individual", instantiates = instantiates)
  if (!is.null(designator)) o[["designator"]] <- designator
  if (!is.null(part_of)) o[["part_of"]] <- part_of
  mk(o)
}

b_token <- function(instantiates, interval, participants = NULL, locus = NULL) {
  o <- co_obj(type = "token_occurrence", instantiates = instantiates,
              interval = interval)
  if (!is.null(participants)) o[["participants"]] <- participants
  if (!is.null(locus)) o[["locus"]] <- locus
  mk(o)
}

b_state <- function(subject, qual, value, interval) {
  mk(co_obj(type = "state_assertion", subject = subject, quality = qual,
            value = value, interval = interval))
}

b_tcc <- function(causes, effects, covering_law = NULL, actual_delay = NULL,
                  counterfactual = NULL) {
  o <- co_obj(type = "token_causal_claim",
              causes = co_arr_from(causes), effects = co_arr_from(effects))
  if (!is.null(covering_law)) o[["covering_law"]] <- covering_law
  if (!is.null(actual_delay)) o[["actual_delay"]] <- actual_delay
  if (!is.null(counterfactual)) o[["counterfactual"]] <- counterfactual
  mk(o)
}

b_rlz <- function(bearer, kind, label = NULL) {
  o <- co_obj(type = "realizable", kind = kind, bearer = bearer)
  if (!is.null(label)) o[["label"]] <- label
  mk(o)
}

neuro <- function() {
  labels <- list("4" = "macromolecular", "5" = "subcellular",
                 "6" = "cellular", "7" = "synaptic", "9" = "region",
                 "14" = "community_and_society")
  s <- list()
  for (o in names(labels)) {
    s[[o]] <- b_stratum(labels[[o]], "neuroendocrine", as.numeric(o))
  }
  s
}

# --------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# --------------------------------------------------------------------------

internal_checks <- function() {
  # RFC 8032 TEST 1 known-answer: the seed must derive the vector's public
  # key. (The empty-message signature of TEST 1 is not exercised: openssl's
  # CLI rejects an empty one-shot buffer; real records are never empty.)
  seed <- co_hex2bin(paste0("9d61b19deffd5a60ba844af492ec2cc4",
                            "4449c5697b326919703bac031cae7f60"))
  kp <- co_keypair_from_seed(seed)
  expected <- paste0("ed25519:d75a980182b10ab7d54bfed3c964073a",
                     "0ee172f3daa62325af021a68f707511a")
  check(identical(kp$public, expected),
        paste("RFC 8032 TEST 1 public key mismatch:", kp$public))
  pub_raw <- co_hex2bin(substring(kp$public, nchar("ed25519:") + 1L))
  msg <- co_utf8("causalontology")
  sig <- .co_ed_sign(seed, msg)
  check(co_ed25519_verify(msg, sig, pub_raw), "Ed25519 roundtrip must verify")
  check(!co_ed25519_verify(co_utf8("causalontologX"), sig, pub_raw),
        "a signature over the wrong message must not verify")
  # JCS basics
  check(identical(co_jcs(co_obj(b = 2, a = 1)), "{\"a\":1,\"b\":2}"),
        "JCS key sorting failed")
  check(identical(co_jcs(1.0), "1"), "JCS 1.0 must print as 1")
  check(identical(co_jcs(6.000), "6"), "JCS 6.000 must print as 6")
  check(identical(co_jcs(0.7), "0.7"), "JCS 0.7 must print as 0.7")
  check(co_to_seconds(1, "months") == 2629746, "months constant")
  check(co_to_seconds(1, "years") == 31556952, "years constant")
  invisible(TRUE)
}

# --------------------------------------------------------------------------
# V01 - V38: the whole-word re-freeze of the 1.0.0 suite
# --------------------------------------------------------------------------

v01 <- function() {
  inp <- normalize(vec(1)[["input"]])
  r <- co_validate_schema(inp); check(r$ok, paste(r$errors, collapse = "; "))
  r <- co_validate_semantics(inp); check(r$ok, paste(r$errors, collapse = "; "))
}

v02 <- function() {
  inp <- normalize(vec(2)[["input"]])
  check(co_validate_schema(inp)$ok, "schema must accept the degenerate CRO")
  check(co_validate_semantics(inp)$ok, "semantics must accept it")
  p <- co_is_partial(inp)
  expected_missing <- co_strings(vec(2)[["expect"]][["missing"]])
  check(p$partial && identical(p$missing, expected_missing),
        paste("missing =", paste(p$missing, collapse = ",")))
}

schema_fails <- function(n, must_mention) {
  inp <- normalize(vec(n)[["input"]])
  r <- co_validate_schema(inp)
  check(!r$ok, "expected schema-invalid")
  check(any(grepl(must_mention, r$errors, fixed = TRUE)),
        paste(r$errors, collapse = "; "))
}

v03 <- function() schema_fails(3, "effects")
v04 <- function() schema_fails(4, "causes")
v05 <- function() schema_fails(5, "modality")
v06 <- function() schema_fails(6, "colour")
v07 <- function() schema_fails(7, "causes")

v08 <- function() {
  r <- co_validate_schema(normalize(vec(8)[["input"]]))
  check(r$ok, paste(r$errors, collapse = "; "))
}

v09 <- function() schema_fails(9, "label")
v10 <- function() schema_fails(10, "category")

v11 <- function() {
  r <- co_validate_schema(normalize(vec(11)[["input"]]))
  check(r$ok, paste(r$errors, collapse = "; "))
}

v12 <- function() schema_fails(12, "confidence")

v13 <- function() {
  inp <- normalize(vec(13)[["input"]])
  r <- co_validate_schema(inp); check(r$ok, paste(r$errors, collapse = "; "))
  r <- co_validate_semantics(inp); check(r$ok, paste(r$errors, collapse = "; "))
}

semantics_fails <- function(n, must_mention) {
  inp <- normalize(vec(n)[["input"]])
  r <- co_validate_semantics(inp)
  check(!r$ok, "expected semantically-invalid")
  check(any(grepl(must_mention, r$errors, fixed = TRUE)),
        paste(r$errors, collapse = "; "))
}

v14 <- function() {
  inp <- normalize(vec(14)[["input"]])
  check(co_validate_schema(inp)$ok, "schema must accept the reversed window")
  semantics_fails(14, "minimum_delay")
}

v15 <- function() semantics_fails(15, "acyclic")
v16 <- function() semantics_fails(16, "acyclic")

v17 <- function() {
  v <- vec(17)
  parent <- normalize(v[["given"]][["parent"]])
  child <- normalize(v[["input"]])
  rv <- co_refinement_valid(child, parent)
  check(!rv$ok && grepl("rival", rv$reason, fixed = TRUE), rv$reason)
}

v18 <- function() semantics_fails(18, "not a legal field")
v19 <- function() semantics_fails(19, "language-tagged")

v20 <- function() {
  dog <- sym("continuant:dog"); mam <- sym("continuant:mammal")
  ani <- sym("continuant:animal")
  enrich <- function(about, entry, i) {
    signed("enrichment",
           co_obj(about = about, field = "subsumes", entry = entry), "taxo", i)
  }
  s <- co_store_new(enforcing = TRUE)
  co_store_put_record(s, enrich(dog, mam, 1L))
  co_store_put_record(s, enrich(mam, ani, 2L))
  msg <- rejected_message(co_store_put_record(s, enrich(ani, dog, 3L)))
  check(!is.null(msg), "enforcing store accepted a cycle")
  check(grepl("cycle", msg, fixed = TRUE), msg)
  s2 <- co_store_new(enforcing = TRUE)
  co_store_put_record(s2, enrich(dog, mam, 1L))
  co_store_put_record(s2, enrich(mam, ani, 2L))
  bad <- enrich(ani, dog, 3L)
  co_store_force_merge_record(s2, bad)
  ate <- co_active_taxonomy_edges(s2, "subsumes")
  check(length(ate$excluded) == 1L &&
          identical(ate$excluded[[1]][["id"]], bad[["id"]]),
        "the latest cycle-completing record must be the one excluded")
  repair <- co_store_gaps(s2, "inconsistent_hierarchy")
  check(bad[["id"]] %in% gap_ids(repair),
        "the excluded record must surface as a repair gap")
}

adm <- function(n) {
  g <- vec(n)[["given"]]
  cro <- co_obj(causes = co_arr(sym("occurrent:c")),
                effects = co_arr(sym("occurrent:e")),
                temporal = g[["temporal"]])
  co_admissible(cro, as.numeric(g[["elapsed_seconds"]]))
}

v21 <- function() check(isTRUE(adm(21)), "inside the window is admissible")
v22 <- function() check(identical(adm(22), FALSE), "outside is not admissible")
v23 <- function() check(isTRUE(adm(23)), "month constant must admit 34560000 s")

v24 <- function() {
  v <- vec(24)
  check(identical(co_identify(normalize(v[["inputA"]])),
                  co_identify(normalize(v[["inputB"]]))),
        "key order must not change identity")
}

v25 <- function() {
  v <- vec(25)
  check(identical(co_identify(normalize(v[["inputA"]])),
                  co_identify(normalize(v[["inputB"]]))),
        "number formatting must not change identity")
}

v26 <- function() {
  s <- co_store_new()
  obj <- co_obj(type = "occurrent", label = "press_button", category = "action")
  a <- co_store_put(s, obj); b <- co_store_put(s, obj)
  check(identical(a, b) && length(s$objects) == 1L, "put must be idempotent")
}

v27 <- function() {
  s <- co_store_new()
  occ <- co_store_put(s, co_obj(type = "occurrent", label = "press_button",
                                category = "action"))
  entry <- co_obj(lang = "en", text = "press the button")
  r1 <- signed("enrichment", co_obj(about = occ, field = "aliases",
                                    entry = entry), "alice", 1L)
  r2 <- signed("enrichment", co_obj(about = occ, field = "aliases",
                                    entry = entry), "bob", 2L)
  id1 <- co_store_put_record(s, r1); id2 <- co_store_put_record(s, r2)
  check(!identical(id1, id2), "two sources must yield two records")
  view <- co_store_get(s, occ)[["enrichments"]][["aliases"]]
  check(length(view) == 1L && length(view[[1]][["contributors"]]) == 2L,
        "one canonical entry with two contributors expected")
}

v28 <- function() {
  s <- co_store_new()
  claim <- co_obj(type = "causal_relation_object",
                  causes = co_arr(sym("occurrent:A")),
                  effects = co_arr(sym("occurrent:B")), modality = "sufficient")
  i1 <- co_store_put(s, claim); i2 <- co_store_put(s, claim)
  check(identical(i1, i2) && length(s$objects) == 1L, "one object expected")
  co_store_put_record(s, signed("assertion",
    co_obj(about = i1, evidence_type = "observation", strength = 0.8,
           confidence = 0.8), "lab1", 1L))
  co_store_put_record(s, signed("assertion",
    co_obj(about = i1, evidence_type = "observation", strength = 0.8,
           confidence = 0.8), "lab2", 2L))
  check(length(co_store_assertions_about(s, i1)) == 2L, "two assertions")
}

v29 <- function() {
  rec <- signed("assertion", co_obj(about = sym("causal_relation_object:demo"),
    evidence_type = "intervention", strength = 0.7, confidence = 0.9), "signer")
  check(isTRUE(co_verify_record(rec)), "a valid signature must verify")
}

v30 <- function() {
  rec <- signed("assertion", co_obj(about = sym("causal_relation_object:demo"),
    evidence_type = "intervention", strength = 0.7, confidence = 0.9), "signer")
  tampered <- rec; tampered[["confidence"]] <- 0.1
  check(identical(co_verify_record(tampered), FALSE),
        "a tampered record must fail verification")
}

v31 <- function() {
  s <- co_store_new()
  x <- co_store_put(s, co_obj(type = "causal_relation_object",
    causes = co_arr(sym("occurrent:A")), effects = co_arr(sym("occurrent:B"))))
  a <- signed("assertion", co_obj(about = x, evidence_type = "observation",
                                  confidence = 0.8), "lab1", 1L)
  co_store_put_record(s, a)
  co_store_put_record(s, signed("retraction", co_obj(retracts = a[["id"]]),
                                "lab1", 2L))
  check(length(co_store_assertions_about(s, x)) == 0L, "retracted leaves view")
  hist <- co_store_assertions_about(s, x, include_retracted = TRUE)
  check(length(hist) == 1L && isTRUE(hist[[1]][["retracted"]]),
        "history keeps the record, flagged retracted")
  foreign <- signed("retraction", co_obj(retracts = a[["id"]]), "mallory", 3L)
  msg <- rejected_message(co_store_put_record(s, foreign))
  check(!is.null(msg), "foreign retraction accepted")
}

v32 <- function() {
  s <- co_store_new()
  occ <- co_store_put(s, co_obj(type = "occurrent", label = "press_button",
                                category = "action"))
  e <- signed("enrichment", co_obj(about = occ, field = "aliases",
    entry = co_obj(lang = "ja", text = "botan")), "bob", 1L)
  co_store_put_record(s, e)
  check(length(co_store_get(s, occ)[["enrichments"]][["aliases"]]) == 1L,
        "the alias must appear")
  co_store_put_record(s, signed("retraction", co_obj(retracts = e[["id"]]),
                                "bob", 2L))
  check(length(co_store_get(s, occ)[["enrichments"]][["aliases"]]) == 0L,
        "the author's retraction must clear the default view")
  hist <- co_store_get(s, occ, view = "history")[["enrichments"]][["aliases"]]
  check(length(hist) == 1L, "history must keep the alias")
}

v33 <- function() {
  s <- co_store_new()
  k1 <- key("K1")$public; k2 <- key("K2")$public
  a <- signed("assertion", co_obj(about = sym("causal_relation_object:claim"),
    evidence_type = "observation", confidence = 0.9), "K1", 1L)
  co_store_put_record(s, a)
  co_store_put_record(s, signed("succession", co_obj(successor = k2), "K1", 2L))
  check(k1 %in% co_store_lineage(s, k2) && k2 %in% co_store_lineage(s, k1),
        "the lineage closure must contain both keys")
  co_store_put_record(s, signed("retraction", co_obj(retracts = a[["id"]]),
                                "K2", 3L))
  check(length(co_store_assertions_about(s,
          sym("causal_relation_object:claim"))) == 0L,
        "the successor's retraction must take effect")
}

v34 <- function() {
  g <- normalize(vec(34)[["given"]])
  check(isTRUE(co_conflicts(g[["A"]], g[["B"]])), "preventive vs sufficient")
}

v35 <- function() {
  g <- normalize(vec(35)[["given"]])
  check(identical(co_conflicts(g[["A"]], g[["B"]]), FALSE),
        "contributory vs sufficient must not conflict")
}

v36 <- function() {
  A <- sym("occurrent:A"); B <- sym("occurrent:B")
  C <- sym("occurrent:C"); D <- sym("occurrent:D")
  m1 <- co_obj(id = sym("causal_relation_object:m1"), causes = co_arr(A), effects = co_arr(B))
  m2 <- co_obj(id = sym("causal_relation_object:m2"), causes = co_arr(B), effects = co_arr(C))
  m3 <- co_obj(id = sym("causal_relation_object:m3"), causes = co_arr(D), effects = co_arr(C))
  P <- co_obj(causes = co_arr(A), effects = co_arr(C),
              mechanism = co_arr(m1[["id"]], m2[["id"]]))
  members <- list(); members[[m1[["id"]]]] <- m1; members[[m2[["id"]]]] <- m2
  check(identical(co_hierarchy_consistent(P, members), "consistent"),
        "A -> B -> C must be consistent")
  P2 <- P; P2[["mechanism"]] <- co_arr(m1[["id"]], m3[["id"]])
  members2 <- list(); members2[[m1[["id"]]]] <- m1; members2[[m3[["id"]]]] <- m3
  check(identical(co_hierarchy_consistent(P2, members2), "inconsistent"),
        "no path to C must be inconsistent")
  members3 <- list(); members3[[m1[["id"]]]] <- m1
  check(identical(co_hierarchy_consistent(P, members3), "indeterminate"),
        "a missing member must be indeterminate")
}

v37 <- function() {
  s <- co_store_new()
  occ <- co_store_put(s, co_obj(type = "occurrent", label = "press_button",
                                category = "action"))
  co_store_put_record(s, signed("enrichment", co_obj(about = occ,
    field = "aliases", entry = co_obj(lang = "en", text = "Press the Button")),
    "alice", 1L))
  res <- co_store_resolve(s, "Press  The   Button", "en")
  check(length(res) == 1L && identical(res[[1]], occ), "alias match")
  res2 <- co_store_resolve(s, "press_button", "en")
  check(length(res2) >= 1L && identical(res2[[1]], occ),
        "canonical-label match must rank first")
}

v38 <- function() {
  s <- co_store_new()
  P <- co_store_put(s, co_obj(type = "causal_relation_object",
    causes = co_arr(sym("occurrent:A")), effects = co_arr(sym("occurrent:B"))))
  check(P %in% gap_ids(co_store_gaps(s, "missing_field")),
        "the degenerate claim must be a visible gap")
  R <- co_store_put(s, co_obj(type = "causal_relation_object",
    causes = co_arr(sym("occurrent:A")), effects = co_arr(sym("occurrent:B")),
    temporal = co_obj(minimum_delay = 0, maximum_delay = 1, unit = "seconds"),
    modality = "sufficient", refines = P))
  ids <- gap_ids(co_store_gaps(s, "missing_field"))
  check(!(P %in% ids), "the gap did not close")
  check(!(R %in% ids), "the refinement itself must be complete")
}

# --------------------------------------------------------------------------
# V39 - V107: the 2.0.0 additions
# --------------------------------------------------------------------------

v39 <- function() {
  st <- b_stratum("cellular", "neuroendocrine", 6, "cell", list("cell_biology"))
  r <- co_validate_schema(st); check(r$ok, paste(r$errors, collapse = "; "))
}

v40 <- function() {
  bad <- mk(co_obj(type = "stratum", label = "cellular", ordinal = 6))
  r <- co_validate_schema(bad, "stratum")
  check(!r$ok && any(grepl("scheme", r$errors, fixed = TRUE)),
        paste(r$errors, collapse = "; "))
}

v41 <- function() {
  a <- b_stratum("cellular", "neuroendocrine", 6)
  b <- b_stratum("neuronal", "neuroendocrine", 6)
  for (x in list(a, b)) { r <- co_validate_schema(x); check(r$ok, paste(r$errors, collapse = "; ")) }
  check(!identical(a[["id"]], b[["id"]]), "distinct labels must differ")
}

v42 <- function() {
  s <- neuro(); s4p <- b_stratum("molecular", "physics", 4)
  c <- b_occ("chronic_social_subordination", s[["14"]][["id"]])
  e <- b_occ("gene_expression", s4p[["id"]])
  smap <- list(); smap[[s[["14"]][["id"]]]] <- s[["14"]]; smap[[s4p[["id"]]]] <- s4p
  omap <- list(); omap[[c[["id"]]]] <- c; omap[[e[["id"]]]] <- e
  P <- b_cro(c[["id"]], e[["id"]])
  check(identical(co_classify_cro(P, omap, smap), "scheme_mismatch"),
        "cross-scheme endpoints must be scheme_mismatch")
}

v43 <- function() {
  for (x in list(b_stratum("macromolecular", "neuroendocrine", 4),
                 b_stratum("region", "neuroendocrine", 9))) {
    r <- co_validate_schema(x); check(r$ok, paste(r$errors, collapse = "; "))
  }
}

v44 <- function() {
  st <- b_stratum("cellular", "neuroendocrine", 6)
  o <- b_occ("neuron_fires", st[["id"]])
  r <- co_validate_schema(o); check(r$ok, paste(r$errors, collapse = "; "))
  r <- co_validate_semantics(o); check(r$ok, paste(r$errors, collapse = "; "))
}

v45 <- function() {
  o <- b_occ("press_button")
  r <- co_validate_schema(o); check(r$ok, paste(r$errors, collapse = "; "))
  e <- b_occ("light_on")
  P <- b_cro(o[["id"]], e[["id"]])
  omap <- list(); omap[[o[["id"]]]] <- o; omap[[e[["id"]]]] <- e
  check(identical(co_classify_cro(P, omap, list()), "unclassifiable"),
        "unstratified endpoints must be unclassifiable")
}

v46 <- function() {
  s <- neuro()
  a <- b_occ("depolarization", s[["5"]][["id"]])
  b <- b_occ("depolarization", s[["6"]][["id"]])
  check(!identical(a[["id"]], b[["id"]]), "same label, different stratum differ")
}

bridge_fixture <- function(relation) {
  s <- neuro()
  coarse <- b_occ("action_potential_fires", s[["6"]][["id"]])
  fine <- list(b_occ("sodium_channels_open", s[["4"]][["id"]]),
               b_occ("sodium_influx", s[["4"]][["id"]]))
  fine_ids <- vapply(fine, function(f) f[["id"]], character(1))
  b <- b_bridge(coarse[["id"]], as.list(fine_ids), relation)
  omap <- list(); omap[[coarse[["id"]]]] <- coarse
  for (f in fine) omap[[f[["id"]]]] <- f
  smap <- list(); smap[[s[["4"]][["id"]]]] <- s[["4"]]; smap[[s[["6"]][["id"]]]] <- s[["6"]]
  list(b = b, omap = omap, smap = smap)
}

valid_bridge <- function(relation) {
  fx <- bridge_fixture(relation)
  r <- co_validate_schema(fx$b); check(r$ok, paste(r$errors, collapse = "; "))
  rr <- co_bridge_wellformed(fx$b, fx$omap, fx$smap); check(rr$ok, rr$reason)
}

v47 <- function() valid_bridge("constitutes")
v48 <- function() valid_bridge("aggregates")
v49 <- function() valid_bridge("realizes")
v50 <- function() valid_bridge("supervenes_on")

v51 <- function() {
  s <- neuro()
  coarse <- b_occ("x_coarse", s[["4"]][["id"]])
  fine <- b_occ("x_fine", s[["6"]][["id"]])
  b <- b_bridge(coarse[["id"]], list(fine[["id"]]), "constitutes")
  omap <- list(); omap[[coarse[["id"]]]] <- coarse; omap[[fine[["id"]]]] <- fine
  smap <- list(); smap[[s[["4"]][["id"]]]] <- s[["4"]]; smap[[s[["6"]][["id"]]]] <- s[["6"]]
  check(!co_bridge_wellformed(b, omap, smap)$ok, "coarse < fine must be malformed")
}

v52 <- function() {
  s <- neuro()
  coarse <- b_occ("c", s[["6"]][["id"]])
  f1 <- b_occ("f1", s[["4"]][["id"]]); f2 <- b_occ("f2", s[["5"]][["id"]])
  b <- b_bridge(coarse[["id"]], list(f1[["id"]], f2[["id"]]), "constitutes")
  omap <- list(); omap[[coarse[["id"]]]] <- coarse
  omap[[f1[["id"]]]] <- f1; omap[[f2[["id"]]]] <- f2
  smap <- list(); smap[[s[["4"]][["id"]]]] <- s[["4"]]
  smap[[s[["5"]][["id"]]]] <- s[["5"]]; smap[[s[["6"]][["id"]]]] <- s[["6"]]
  check(!co_bridge_wellformed(b, omap, smap)$ok, "fine spanning strata malformed")
}

v53 <- function() {
  x <- sym("occurrent:x"); y <- sym("occurrent:y")
  b1 <- b_bridge(x, list(y), "constitutes")
  b2 <- b_bridge(y, list(x), "constitutes")
  edges <- list()
  for (b in list(b1, b2)) {
    for (f in co_strings(b[["fine"]])) {
      old <- if (co_has_key(edges, f)) edges[[f]] else character(0)
      edges[[f]] <- c(old, b[["coarse"]])
    }
  }
  check(isTRUE(co_has_cycle(edges)), "the bridge graph must have a cycle")
}

v54 <- function() {
  a <- b_stratum("cellular", "neuroendocrine", 6)
  b <- b_stratum("molecular", "physics", 4)
  coarse <- b_occ("c", a[["id"]]); fine <- b_occ("f", b[["id"]])
  br <- b_bridge(coarse[["id"]], list(fine[["id"]]), "constitutes")
  omap <- list(); omap[[coarse[["id"]]]] <- coarse; omap[[fine[["id"]]]] <- fine
  smap <- list(); smap[[a[["id"]]]] <- a; smap[[b[["id"]]]] <- b
  check(!co_bridge_wellformed(br, omap, smap)$ok, "cross-scheme bridge malformed")
}

v55 <- function() {
  s <- neuro()
  coarse <- b_occ("decision_made", s[["6"]][["id"]])
  f1 <- b_occ("cascade_a", s[["4"]][["id"]]); f2 <- b_occ("cascade_b", s[["4"]][["id"]])
  b1 <- b_bridge(coarse[["id"]], list(f1[["id"]]), "realizes")
  b2 <- b_bridge(coarse[["id"]], list(f2[["id"]]), "realizes")
  check(!identical(b1[["id"]], b2[["id"]]), "different fine sets differ")
  for (b in list(b1, b2)) { r <- co_validate_schema(b); check(r$ok, paste(r$errors, collapse = "; ")) }
}

reach_fixture <- function() {
  s <- neuro()
  ap <- b_occ("action_potential_fires", s[["6"]][["id"]])
  nt <- b_occ("neurotransmitter_released", s[["6"]][["id"]])
  fa <- b_occ("calcium_enters", s[["4"]][["id"]])
  fb <- b_occ("vesicle_fuses", s[["4"]][["id"]])
  m1 <- b_cro(fa[["id"]], fb[["id"]])
  P <- b_cro(ap[["id"]], nt[["id"]], mechanism = co_arr(m1[["id"]]))
  bridges <- list(b_bridge(ap[["id"]], list(fa[["id"]]), "constitutes"),
                  b_bridge(nt[["id"]], list(fb[["id"]]), "constitutes"))
  members <- list(); members[[m1[["id"]]]] <- m1
  list(P = P, members = members, bridges = bridges)
}

v56 <- function() {
  fx <- reach_fixture()
  check(identical(co_hierarchy_consistent(fx$P, fx$members, fx$bridges),
                  "consistent"), "bridged reachability must be consistent")
}

v57 <- function() {
  fx <- reach_fixture()
  check(identical(co_hierarchy_consistent(fx$P, fx$members, list()),
                  "inconsistent"), "literal reachability must be inconsistent")
}

v58 <- function() {
  fx <- reach_fixture()
  literal <- co_hierarchy_consistent(fx$P, fx$members, list())
  bridged <- co_hierarchy_consistent(fx$P, fx$members, fx$bridges)
  check(!identical(literal, "consistent") && identical(bridged, "consistent"),
        "bridge closure must change the verdict")
}

classify_fx <- function(cause_ord, effect_ord) {
  s <- neuro()
  co <- as.character(cause_ord); eo <- as.character(effect_ord)
  c <- b_occ("c", s[[co]][["id"]]); e <- b_occ("e", s[[eo]][["id"]])
  smap <- list(); smap[[s[[co]][["id"]]]] <- s[[co]]; smap[[s[[eo]][["id"]]]] <- s[[eo]]
  omap <- list(); omap[[c[["id"]]]] <- c; omap[[e[["id"]]]] <- e
  co_classify_cro(b_cro(c[["id"]], e[["id"]]), omap, smap)
}

v59 <- function() check(identical(classify_fx(6, 6), "intra_stratal"), "intra")
v60 <- function() check(identical(classify_fx(6, 5), "adjacent_stratal"), "adjacent")
v61 <- function() check(identical(classify_fx(14, 4), "skipping"), "skipping")

skip_fixture <- function(cause_ord, effect_ord, ...) {
  s <- neuro()
  co <- as.character(cause_ord); eo <- as.character(effect_ord)
  c <- b_occ("c", s[[co]][["id"]]); e <- b_occ("e", s[[eo]][["id"]])
  smap <- list(); smap[[s[[co]][["id"]]]] <- s[[co]]; smap[[s[[eo]][["id"]]]] <- s[[eo]]
  omap <- list(); omap[[c[["id"]]]] <- c; omap[[e[["id"]]]] <- e
  P <- b_cro(c[["id"]], e[["id"]], ...)
  list(P = P, cls = co_classify_cro(P, omap, smap))
}

v62 <- function() {
  fx <- skip_fixture(14, 4)
  check(identical(co_skip_gaps(fx$P, fx$cls), "incomplete_mechanism"),
        "skips absent surfaces incomplete_mechanism")
}

v63 <- function() {
  fx <- skip_fixture(14, 4, skips = TRUE)
  check(length(co_skip_gaps(fx$P, fx$cls)) == 0L,
        "skips true over a genuine gap surfaces nothing")
}

v64 <- function() {
  fx <- skip_fixture(14, 4, skips = TRUE,
                     mechanism = co_arr(sym("causal_relation_object:m")))
  check(identical(co_skip_gaps(fx$P, fx$cls), "contradictory_skip"),
        "skips true + mechanism is contradictory")
  r <- co_validate_semantics(fx$P)
  check(!r$ok && any(grepl("contradictory_skip", r$errors, fixed = TRUE)),
        "the contradiction must also be a hard semantics failure")
}

v65 <- function() {
  fx <- skip_fixture(6, 6, skips = TRUE)
  check(identical(co_skip_gaps(fx$P, fx$cls), "vacuous_skip"),
        "skips true over an intra-stratal claim is vacuous")
}

v66 <- function() {
  s <- neuro()
  c <- b_occ("c", s[["14"]][["id"]]); e <- b_occ("e", s[["4"]][["id"]])
  absent <- b_cro(c[["id"]], e[["id"]])
  false_ <- b_cro(c[["id"]], e[["id"]], skips = FALSE)
  check(!identical(absent[["id"]], false_[["id"]]),
        "absent skips and skips:false must be distinct identities")
}

v67 <- function() {
  s <- neuro()
  c1 <- b_occ("c1", s[["4"]][["id"]]); c2 <- b_occ("c2", s[["6"]][["id"]])
  e <- b_occ("e", s[["6"]][["id"]])
  P <- b_cro(c(c1[["id"]], c2[["id"]]), e[["id"]])
  omap <- list(); omap[[c1[["id"]]]] <- c1; omap[[c2[["id"]]]] <- c2; omap[[e[["id"]]]] <- e
  check(isTRUE(co_endpoints_mixed(P, omap)), "mixed endpoints must surface")
}

v68 <- function() {
  P <- b_cro(sym("occurrent:a"), sym("occurrent:b"), modality = "enabling")
  r <- co_validate_schema(P); check(r$ok, paste(r$errors, collapse = "; "))
}

v69 <- function() {
  a <- co_obj(causes = co_arr(sym("occurrent:a")), effects = co_arr(sym("occurrent:b")),
              modality = "enabling")
  b <- co_obj(causes = co_arr(sym("occurrent:a")), effects = co_arr(sym("occurrent:b")),
              modality = "sufficient")
  check(identical(co_conflicts(a, b), FALSE), "enabling vs sufficient no conflict")
}

v70 <- function() {
  a <- co_obj(causes = co_arr(sym("occurrent:a")), effects = co_arr(sym("occurrent:b")),
              modality = "enabling")
  b <- co_obj(causes = co_arr(sym("occurrent:a")), effects = co_arr(sym("occurrent:b")),
              modality = "preventive")
  check(isTRUE(co_conflicts(a, b)), "enabling vs preventive must conflict")
}

v71 <- function() {
  b <- b_cnt("hippocampus")
  p <- b_port(b[["id"]], "perforant_path", "in", list(sym("occurrent:signal")))
  r <- co_validate_schema(p); check(r$ok, paste(r$errors, collapse = "; "))
}

v72 <- function() {
  b <- b_cnt("hippocampus")[["id"]]; x <- sym("occurrent:signal")
  check(!identical(b_port(b, "perforant_path", "in", list(x))[["id"]],
                   b_port(b, "fornix", "in", list(x))[["id"]]),
        "distinct labels give distinct ports")
}

conduit_fixture <- function(transform = FALSE, bad_carry = FALSE, in_from = FALSE) {
  x <- sym("occurrent:motor_command"); y <- sym("occurrent:error_signal")
  z <- sym("occurrent:unrelated")
  m1 <- b_cnt("motor_cortex")[["id"]]; m2 <- b_cnt("spinal_neuron")[["id"]]
  frm <- b_port(m1, "out_port", if (in_from) "in" else "out", list(x))
  to <- b_port(m2, "in_port", "in", if (transform) list(y) else list(x))
  carries <- if (bad_carry) list(z) else list(x)
  xform <- NULL; cro_map <- list()
  if (transform) {
    law <- b_cro(x, y); cro_map[[law[["id"]]]] <- law; xform <- law[["id"]]
  }
  c <- b_conduit(frm[["id"]], to[["id"]], carries, transform = xform)
  pmap <- list(); pmap[[frm[["id"]]]] <- frm; pmap[[to[["id"]]]] <- to
  list(c = c, pmap = pmap, cro_map = cro_map)
}

v73 <- function() {
  fx <- conduit_fixture()
  r <- co_validate_schema(fx$c); check(r$ok, paste(r$errors, collapse = "; "))
  rr <- co_conduit_wellformed(fx$c, fx$pmap); check(rr$ok, rr$reason)
}

v74 <- function() {
  fx <- conduit_fixture(transform = TRUE)
  r <- co_validate_schema(fx$c); check(r$ok, paste(r$errors, collapse = "; "))
  rr <- co_conduit_wellformed(fx$c, fx$pmap, fx$cro_map); check(rr$ok, rr$reason)
}

v75 <- function() {
  fx <- conduit_fixture(bad_carry = TRUE)
  check(!co_conduit_wellformed(fx$c, fx$pmap)$ok, "carry not accepted malformed")
}

v76 <- function() {
  fx <- conduit_fixture(in_from = TRUE)
  check(!co_conduit_wellformed(fx$c, fx$pmap)$ok, "in-directed from malformed")
}

v77 <- function() {
  fx <- conduit_fixture(transform = TRUE)
  rr <- co_conduit_wellformed(fx$c, fx$pmap, fx$cro_map); check(rr$ok, rr$reason)
  law <- fx$cro_map[[names(fx$cro_map)[[1]]]]
  check(!(co_strings(law[["effects"]])[[1]] %in% co_strings(fx$c[["carries"]])),
        "the transform output is not itself carried")
}

v78 <- function() {
  b <- b_cnt("hippocampus")[["id"]]
  check(!identical(b_rlz(b, "disposition", "long_term_potentiation")[["id"]],
                   b_rlz(b, "disposition", "pattern_separation")[["id"]]),
        "distinct labels give distinct realizables")
}

v79 <- function() {
  b <- b_cnt("hippocampus")[["id"]]
  u1 <- b_rlz(b, "disposition"); u2 <- b_rlz(b, "disposition")
  r <- co_validate_schema(u1); check(r$ok, paste(r$errors, collapse = "; "))
  check(identical(u1[["id"]], u2[["id"]]), "label-free realizables coincide")
  check(!identical(b_rlz(b, "disposition", "some_function")[["id"]], u1[["id"]]),
        "adding a label changes identity")
}

v80 <- function() {
  parent <- b_occ("fires"); child <- b_occ("fires_action_potential")
  e <- co_obj(type = "enrichment", about = child[["id"]],
              field = "occurrent_subsumes", entry = parent[["id"]])
  r <- co_validate_semantics(e); check(r$ok, paste(r$errors, collapse = "; "))
}

v81 <- function() {
  a <- sym("occurrent:a"); b <- sym("occurrent:b")
  edges <- list(); edges[[a]] <- b; edges[[b]] <- a
  check(isTRUE(co_has_cycle(edges)), "a two-cycle must be detected")
}

v82 <- function() {
  whole <- b_occ("eat"); part <- b_occ("chew")
  e <- co_obj(type = "enrichment", about = part[["id"]],
              field = "occurrent_part_of", entry = whole[["id"]])
  r <- co_validate_semantics(e); check(r$ok, paste(r$errors, collapse = "; "))
}

v83 <- function() {
  spec <- co_enrichment_fields[["occurrent_part_of"]]
  check(identical(spec$shape, "occurrent") &&
          identical(spec$kinds, "occurrent"),
        "occurrent_part_of must be occurrent -> occurrent")
  s <- co_store_new()
  whole <- co_store_put(s, b_occ("eat")); part <- co_store_put(s, b_occ("chew"))
  for (oid in names(s$objects)) {
    check(!identical(co_get(s$objects[[oid]], "type"), "causal_relation_object"),
          "no spurious CRO was created")
  }
}

v84 <- function() {
  s <- neuro()
  a <- b_occ("run", s[["9"]][["id"]]); b <- b_occ("sprint", s[["6"]][["id"]])
  check(!identical(a[["stratum"]], b[["stratum"]]), "different strata differ")
}

v85 <- function() {
  c <- b_cnt("human_patient")
  ti <- b_individual(c[["id"]], designator = "salted_hash_abc123")
  r <- co_validate_schema(ti); check(r$ok, paste(r$errors, collapse = "; "))
}

v86 <- function() {
  bad <- mk(co_obj(type = "token_individual", designator = "x"))
  r <- co_validate_schema(bad, "token_individual")
  check(!r$ok && any(grepl("instantiates", r$errors, fixed = TRUE)),
        paste(r$errors, collapse = "; "))
}

v87 <- function() {
  c <- b_cnt("human_patient")[["id"]]
  check(!identical(b_individual(c, designator = "hash_a")[["id"]],
                   b_individual(c, designator = "hash_b")[["id"]]),
        "different designators differ")
}

v88 <- function() {
  o <- b_occ("bilateral_hippocampal_resection")
  t <- b_token(o[["id"]], co_obj(start = "1953-08-25T00:00:00Z",
                                 end = "1953-08-25T00:00:00Z"))
  r <- co_validate_schema(t); check(r$ok, paste(r$errors, collapse = "; "))
}

v89 <- function() {
  o <- b_occ("amnesia_onset")[["id"]]
  bounded <- b_token(o, co_obj(start = "1953-08-25T00:00:00Z", end = "1953-08-26T00:00:00Z"))
  instantaneous <- b_token(o, co_obj(start = "1953-08-25T00:00:00Z"))
  ongoing <- b_token(o, co_obj(start = "1953-08-25T00:00:00Z", open = TRUE))
  ids <- unique(c(bounded[["id"]], instantaneous[["id"]], ongoing[["id"]]))
  check(length(ids) == 3L, "three interval shapes give three identities")
}

v90 <- function() {
  o <- b_occ("resection")[["id"]]; c <- b_cnt("human_patient")[["id"]]
  patient <- b_individual(c, designator = "p")[["id"]]
  surgeon <- b_individual(c, designator = "s")[["id"]]
  t <- b_token(o, co_obj(start = "1953-08-25T00:00:00Z"),
               participants = co_arr(
                 co_obj(role = "patient", filler = patient),
                 co_obj(role = "agent", filler = surgeon)))
  r <- co_validate_schema(t); check(r$ok, paste(r$errors, collapse = "; "))
}

v91 <- function() {
  q <- b_quality("cortisol_concentration", "quantity", "ug/dL")
  r <- co_validate_schema(q); check(r$ok, paste(r$errors, collapse = "; "))
}

state_fixture <- function(datatype, value, unit = NULL) {
  q <- b_quality("cortisol_concentration", datatype, unit)
  c <- b_cnt("human_patient")[["id"]]
  subj <- b_individual(c, designator = "p")[["id"]]
  st <- b_state(subj, q[["id"]], value,
                co_obj(start = "2026-01-01T00:00:00Z", end = "2026-01-01T01:00:00Z"))
  list(st = st, q = q)
}

v92 <- function() {
  fx <- state_fixture("quantity", co_obj(quantity = 15.0, unit = "ug/dL"), "ug/dL")
  r <- co_validate_schema(fx$st); check(r$ok, paste(r$errors, collapse = "; "))
  check(length(co_state_gaps(fx$st, fx$q)) == 0L, "coherent quantity state")
}

v93 <- function() {
  fx <- state_fixture("categorical", co_obj(categorical = "elevated"))
  r <- co_validate_schema(fx$st); check(r$ok, paste(r$errors, collapse = "; "))
  check(length(co_state_gaps(fx$st, fx$q)) == 0L, "coherent categorical state")
}

v94 <- function() {
  fx <- state_fixture("boolean", co_obj(boolean = TRUE))
  r <- co_validate_schema(fx$st); check(r$ok, paste(r$errors, collapse = "; "))
  check(length(co_state_gaps(fx$st, fx$q)) == 0L, "coherent boolean state")
}

v95 <- function() {
  fx <- state_fixture("quantity", co_obj(categorical = "elevated"), "ug/dL")
  check(identical(co_state_gaps(fx$st, fx$q), "value_type_mismatch"),
        "a categorical value against a quantity quality mismatches")
}

v96 <- function() {
  fx <- state_fixture("quantity", co_obj(quantity = 15.0, unit = "mg/dL"), "ug/dL")
  check(identical(co_state_gaps(fx$st, fx$q), "unit_mismatch"),
        "a differing unit surfaces unit_mismatch")
}

law_and_tokens <- function() {
  o_cause <- b_occ("resection"); o_effect <- b_occ("amnesia_onset")
  law <- b_cro(o_cause[["id"]], o_effect[["id"]],
               temporal = co_obj(minimum_delay = 0, maximum_delay = 1, unit = "days"),
               modality = "sufficient")
  t_cause <- b_token(o_cause[["id"]], co_obj(start = "1953-08-25T00:00:00Z"))
  t_effect <- b_token(o_effect[["id"]], co_obj(start = "1953-08-25T00:00:00Z", open = TRUE))
  list(law = law, t_cause = t_cause, t_effect = t_effect)
}

v97 <- function() {
  fx <- law_and_tokens()
  claim <- b_tcc(fx$t_cause[["id"]], fx$t_effect[["id"]],
                 covering_law = fx$law[["id"]],
                 actual_delay = co_obj(duration = 0, unit = "instant"),
                 counterfactual = TRUE)
  r <- co_validate_schema(claim); check(r$ok, paste(r$errors, collapse = "; "))
}

v98 <- function() {
  fx <- law_and_tokens()
  claim <- b_tcc(fx$t_cause[["id"]], fx$t_effect[["id"]])
  r <- co_validate_schema(claim); check(r$ok, paste(r$errors, collapse = "; "))
  check(!co_has(claim, "covering_law"), "covering_law is optional")
}

v99 <- function() {
  fx <- law_and_tokens()
  check(isTRUE(co_delay_within_window(co_obj(duration = 0, unit = "instant"),
                                      fx$law[["temporal"]])),
        "instant delay falls within [0,1] days")
}

v100 <- function() {
  temporal <- co_obj(minimum_delay = 0, maximum_delay = 1, unit = "hours")
  check(identical(co_delay_within_window(co_obj(duration = 5, unit = "days"),
                                         temporal), FALSE),
        "5 days is outside a 1-hour window")
}

v101 <- function() {
  o <- b_occ("x")[["id"]]
  cause <- b_token(o, co_obj(start = "2026-01-02T00:00:00Z"))
  effect <- b_token(o, co_obj(start = "2026-01-01T00:00:00Z"))
  claim <- b_tcc(cause[["id"]], effect[["id"]])
  tmap <- list(); tmap[[cause[["id"]]]] <- cause; tmap[[effect[["id"]]]] <- effect
  check(isTRUE(co_retrocausal(claim, tmap)), "cause after effect is retrocausal")
}

v102 <- function() {
  other <- b_cro(sym("occurrent:foo"), sym("occurrent:bar"))
  fx <- law_and_tokens()
  claim <- b_tcc(fx$t_cause[["id"]], fx$t_effect[["id"]],
                 covering_law = other[["id"]])
  tmap <- list(); tmap[[fx$t_cause[["id"]]]] <- fx$t_cause
  tmap[[fx$t_effect[["id"]]]] <- fx$t_effect
  check(isTRUE(co_covering_law_mismatch(claim, tmap, other)),
        "tokens must instantiate the covering law")
}

v103 <- function() {
  a <- signed("assertion", co_obj(about = sym("token_occurrence:t"),
    evidence_type = "observation", confidence = 0.9), "signer")
  r <- co_validate_schema(a); check(r$ok, paste(r$errors, collapse = "; "))
}

v104 <- function() {
  ev <- list(sym("token_occurrence:t1"), sym("token_causal_claim:c1"))
  base <- co_obj(type = "assertion", about = sym("causal_relation_object:law"),
                 source = key("signer")$public, evidence_type = "intervention",
                 strength = 0.95, confidence = 0.99,
                 timestamp = "2026-07-14T00:00:00Z")
  a <- base; a[["evidenced_by"]] <- co_arr_from(ev)
  withid <- a; withid[["id"]] <- co_identify(a)
  r <- co_validate_schema(withid); check(r$ok, paste(r$errors, collapse = "; "))
  check(!identical(co_identify(a), co_identify(base)),
        "evidenced_by is identity-bearing")
}

v105 <- function() {
  a <- signed("assertion", co_obj(about = sym("causal_relation_object:law"),
    evidence_type = "simulation", confidence = 0.5), "signer")
  r <- co_validate_schema(a); check(r$ok, paste(r$errors, collapse = "; "))
  rank <- c(intervention = 0, observation = 1, simulation = 2)
  check(rank[["intervention"]] < rank[["observation"]] &&
          rank[["observation"]] < rank[["simulation"]], "evidence ranking")
}

v106 <- function() {
  scan <- function(node, acc) {
    if (co_is_str(node)) {
      m <- regmatches(node, regexec("^([a-z0-9_]+):[0-9a-f]{64}$", node))[[1]]
      if (length(m) == 2L) acc$ids <- c(acc$ids, m[[2]])
    } else if (co_is_arr(node)) {
      for (x in node) scan(x, acc)
    } else if (co_is_obj(node)) {
      for (x in node) scan(x, acc)
    }
    invisible(NULL)
  }
  for (n in 1:38) {
    acc <- new.env(parent = emptyenv()); acc$ids <- character(0)
    scan(vec(n), acc)
    for (scheme in acc$ids) {
      check(scheme %in% co_whole_word,
            sprintf("V106: abbreviated scheme '%s' in vector %d", scheme, n))
    }
  }
  rec <- co_obj(type = "occurrent", label = "press_button", category = "action")
  check(identical(co_identify(rec), co_identify(rec)), "identity deterministic")
  check(identical(strsplit(co_identify(rec), ":", fixed = TRUE)[[1]][[1]],
                  "occurrent"), "identity is whole-word")
}

v107 <- function() {
  hexid <- strrep("0", 64L)
  # NOTE: the abbreviated prefix here is INTENTIONAL (the negative test) and
  # must NOT be re-minted; the letters are assembled so re-mint passes skip it.
  cro_abbr <- paste0("c", "r", "o")
  abbreviated <- co_obj(type = "causal_relation_object",
                        id = paste0(cro_abbr, ":", hexid),
                        causes = co_arr(paste0("occurrent:", hexid)),
                        effects = co_arr(paste0("occurrent:", hexid)))
  check(!co_validate_schema(abbreviated, "causal_relation_object")$ok,
        "an abbreviated scheme must be rejected")
  abbr_str <- co_obj(type = "stratum", id = paste0("str", ":", hexid),
                     label = "cellular", scheme = "neuroendocrine", ordinal = 6)
  check(!co_validate_schema(abbr_str, "stratum")$ok,
        "the abbreviated stratum scheme must be rejected")
  whole <- co_obj(type = "causal_relation_object",
                  id = paste0("causal_relation_object:", hexid),
                  causes = co_arr(paste0("occurrent:", hexid)),
                  effects = co_arr(paste0("occurrent:", hexid)))
  r <- co_validate_schema(whole, "causal_relation_object")
  check(r$ok, paste(r$errors, collapse = "; "))
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

main <- function() {
  cat("causalontology-r conformance run (specification 2.0.0)\n")
  cat("internal checks (RFC 8032 known-answer, RFC 8785, fixed constants) ... ")
  internal_checks()
  cat("ok\n")
  failures <- 0L
  total <- 107L
  for (n in 1:total) {
    fn <- match.fun(sprintf("v%02d", n))
    name <- sub("\\.json$", "", basename(vecfile(n)))
    result <- tryCatch({ fn(); NULL },
                       error = function(e) conditionMessage(e))
    if (is.null(result)) {
      cat(sprintf("PASS  %s\n", name))
    } else {
      failures <- failures + 1L
      cat(sprintf("FAIL  %s :: %s\n", name, result))
    }
  }
  cat(strrep("-", 60L), "\n", sep = "")
  cat(sprintf("%d/%d vectors passed\n", total - failures, total))
  if (failures > 0L) quit(save = "no", status = 1L)
  cat(paste0("causalontology-r is CONFORMANT to the suite ",
             "(vectors frozen at specification 2.0.0).\n"))
}

main()

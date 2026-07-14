#!/usr/bin/env Rscript
# The Causalontology conformance runner for causalontology-r.
#
# Runs every vector in conformance/vectors/ against the R binding. An
# implementation is conformant if and only if it passes every vector;
# this runner exits nonzero on any failure. It mirrors the reference
# harness bindings/python/tests/run_conformance.py vector for vector.
#
# The vectors are frozen at specification 1.0.0: they carry concrete
# 64-hex identifiers and real Ed25519 keys, and normalize() below simply
# passes such frozen values through unchanged. Symbolic identifiers
# ("occ:c", "cnt:dog") used by the behavioral scenarios are normalized
# deterministically: object ids become scheme:sha256(name), and symbolic
# key names become real Ed25519 keypairs whose 32-byte seed is
# sha256("key:" + name).
#
# Run from anywhere:   Rscript bindings/r/conformance.R
# Dependencies:        sodium (Ed25519), openssl (SHA-256); base R otherwise.

# --------------------------------------------------------------------------
# locate the binding directory and the repository root, then load the code
# --------------------------------------------------------------------------

co_main_args <- commandArgs(trailingOnly = FALSE)
co_file_arg <- grep("^--file=", co_main_args, value = TRUE)
if (length(co_file_arg) >= 1L) {
  co_script_path <- normalizePath(sub("^--file=", "", co_file_arg[[1]]))
  co_binding_dir <- dirname(co_script_path)
} else {
  # interactive fallback: assume the working directory is the repo root
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
  co_set_root(co_repo_root())   # CAUSALONTOLOGY_ROOT or walk up from getwd()
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
# symbolic-identifier normalization
# --------------------------------------------------------------------------

co_schemes_pattern <- "^(occ|cro|cnt|rlz|ast|enr|ret|suc|ed25519):"

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

# Load vector n's JSON file (for its structured inputs).
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

# Run an expression expecting a RejectedWrite; returns its message or NULL.
rejected_message <- function(expr) {
  tryCatch({ force(expr); NULL },
           co_rejected_write = function(e) conditionMessage(e))
}

# The ids carried by a list of gap records.
gap_ids <- function(gaps) {
  if (length(gaps) == 0L) return(character(0))
  out <- character(length(gaps))
  for (i in seq_along(gaps)) out[[i]] <- gaps[[i]][["id"]]
  out
}

# --------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# --------------------------------------------------------------------------

internal_checks <- function() {
  # RFC 8032, TEST 1 known-answer: this gates every sodium assumption
  # (32-byte seed as signing key, argument orders, key derivation).
  sk <- co_hex2bin(paste0(
    "9d61b19deffd5a60ba844af492ec2cc4",
    "4449c5697b326919703bac031cae7f60"))
  sk <- sodium::sig_keygen(seed = sk)  # expand the 32-byte seed to the 64-byte secret
  pk <- sodium::sig_pubkey(sk)
  expected <- paste0(
    "d75a980182b10ab7d54bfed3c964073a",
    "0ee172f3daa62325af021a68f707511a")
  check(identical(co_bin2hex(pk), expected),
        paste("RFC 8032 TEST 1 public key mismatch:", co_bin2hex(pk)))
  sig <- sodium::sig_sign(raw(0), sk)
  check(co_ed25519_verify(raw(0), sig, pk), "TEST 1 signature must verify")
  check(!co_ed25519_verify(charToRaw("x"), sig, pk),
        "signature over the wrong message must not verify")
  # JCS basics
  check(identical(co_jcs(co_obj(b = 2, a = 1)), "{\"a\":1,\"b\":2}"),
        "JCS key sorting failed")
  check(identical(co_jcs(1.0), "1"), "JCS 1.0 must print as 1")
  check(identical(co_jcs(6.000), "6"), "JCS 6.000 must print as 6")
  check(identical(co_jcs(0.7), "0.7"), "JCS 0.7 must print as 0.7")
  invisible(TRUE)
}

# --------------------------------------------------------------------------
# the 38 vectors
# --------------------------------------------------------------------------

v01 <- function() {
  inp <- normalize(vec(1)[["input"]])
  r <- co_validate_schema(inp)
  check(r$ok, paste(r$errors, collapse = "; "))
  r <- co_validate_semantics(inp)
  check(r$ok, paste(r$errors, collapse = "; "))
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
  r <- co_validate_schema(inp)
  check(r$ok, paste(r$errors, collapse = "; "))
  r <- co_validate_semantics(inp)
  check(r$ok, paste(r$errors, collapse = "; "))
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
  semantics_fails(14, "dmin")
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
  dog <- sym("cnt:dog")
  mam <- sym("cnt:mammal")
  ani <- sym("cnt:animal")
  enrich <- function(about, entry, i) {
    signed("enrichment",
           co_obj(about = about, field = "subsumes", entry = entry),
           "taxo", i)
  }
  # enforcing tier rejects the cycle-completing write
  s <- co_store_new(enforcing = TRUE)
  co_store_put_record(s, enrich(dog, mam, 1L))
  co_store_put_record(s, enrich(mam, ani, 2L))
  msg <- rejected_message(co_store_put_record(s, enrich(ani, dog, 3L)))
  check(!is.null(msg), "enforcing store accepted a cycle")
  check(grepl("cycle", msg, fixed = TRUE), msg)
  # decentralized merge: the view breaks the cycle deterministically
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
  cro <- co_obj(causes = co_arr(sym("occ:c")),
                effects = co_arr(sym("occ:e")),
                temporal = g[["temporal"]])
  co_admissible(cro, as.numeric(g[["elapsed_seconds"]]))
}

v21 <- function() check(isTRUE(adm(21)), "inside the window is admissible")
v22 <- function() check(identical(adm(22), FALSE),
                        "outside the window is not admissible")
v23 <- function() check(isTRUE(adm(23)),
                        "the fixed month constant must admit 34560000 s")

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
  obj <- co_obj(type = "occurrent", label = "press_button",
                category = "action")
  a <- co_store_put(s, obj)
  b <- co_store_put(s, obj)
  check(identical(a, b) && length(s$objects) == 1L,
        "identical put must be idempotent")
}

v27 <- function() {
  s <- co_store_new()
  occ <- co_store_put(s, co_obj(type = "occurrent", label = "press_button",
                                category = "action"))
  entry <- co_obj(lang = "en", text = "press the button")
  r1 <- signed("enrichment",
               co_obj(about = occ, field = "aliases", entry = entry),
               "alice", 1L)
  r2 <- signed("enrichment",
               co_obj(about = occ, field = "aliases", entry = entry),
               "bob", 2L)
  id1 <- co_store_put_record(s, r1)
  id2 <- co_store_put_record(s, r2)
  check(!identical(id1, id2), "two sources must yield two records")
  view <- co_store_get(s, occ)[["enrichments"]][["aliases"]]
  check(length(view) == 1L && length(view[[1]][["contributors"]]) == 2L,
        "one canonical entry with two contributors expected")
}

v28 <- function() {
  s <- co_store_new()
  claim <- co_obj(type = "cro", causes = co_arr(sym("occ:A")),
                  effects = co_arr(sym("occ:B")), modality = "sufficient")
  i1 <- co_store_put(s, claim)
  i2 <- co_store_put(s, claim)
  check(identical(i1, i2) && length(s$objects) == 1L,
        "one object expected")
  co_store_put_record(s, signed(
    "assertion", co_obj(about = i1, evidence_type = "observation",
                        strength = 0.8, confidence = 0.8), "lab1", 1L))
  co_store_put_record(s, signed(
    "assertion", co_obj(about = i1, evidence_type = "observation",
                        strength = 0.8, confidence = 0.8), "lab2", 2L))
  check(length(co_store_assertions_about(s, i1)) == 2L,
        "two assertions expected")
}

v29 <- function() {
  rec <- signed("assertion",
                co_obj(about = sym("cro:demo"),
                       evidence_type = "intervention",
                       strength = 0.7, confidence = 0.9), "signer")
  check(isTRUE(co_verify_record(rec)), "a valid signature must verify")
}

v30 <- function() {
  rec <- signed("assertion",
                co_obj(about = sym("cro:demo"),
                       evidence_type = "intervention",
                       strength = 0.7, confidence = 0.9), "signer")
  tampered <- rec
  tampered[["confidence"]] <- 0.1
  check(identical(co_verify_record(tampered), FALSE),
        "a tampered record must fail verification")
}

v31 <- function() {
  s <- co_store_new()
  x <- co_store_put(s, co_obj(type = "cro", causes = co_arr(sym("occ:A")),
                              effects = co_arr(sym("occ:B"))))
  a <- signed("assertion",
              co_obj(about = x, evidence_type = "observation",
                     confidence = 0.8), "lab1", 1L)
  co_store_put_record(s, a)
  co_store_put_record(s, signed("retraction", co_obj(retracts = a[["id"]]),
                                "lab1", 2L))
  check(length(co_store_assertions_about(s, x)) == 0L,
        "the retracted assertion must leave the default view")
  hist <- co_store_assertions_about(s, x, include_retracted = TRUE)
  check(length(hist) == 1L && isTRUE(hist[[1]][["retracted"]]),
        "history must keep the record, flagged retracted")
  foreign <- signed("retraction", co_obj(retracts = a[["id"]]),
                    "mallory", 3L)
  msg <- rejected_message(co_store_put_record(s, foreign))
  check(!is.null(msg), "foreign retraction accepted")
  check(length(co_store_assertions_about(s, x)) == 0L,
        "still excluded by lab1's own retraction")
  check(length(co_store_assertions_about(s, x,
                                         include_retracted = TRUE)) == 1L,
        "history unchanged")
}

v32 <- function() {
  s <- co_store_new()
  occ <- co_store_put(s, co_obj(type = "occurrent", label = "press_button",
                                category = "action"))
  e <- signed("enrichment",
              co_obj(about = occ, field = "aliases",
                     entry = co_obj(lang = "ja", text = "botan")),
              "bob", 1L)
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
  k1 <- key("K1")$public
  k2 <- key("K2")$public
  a <- signed("assertion",
              co_obj(about = sym("cro:claim"),
                     evidence_type = "observation", confidence = 0.9),
              "K1", 1L)
  co_store_put_record(s, a)
  succ <- signed("succession", co_obj(successor = k2), "K1", 2L)
  co_store_put_record(s, succ)
  check(k1 %in% co_store_lineage(s, k2) && k2 %in% co_store_lineage(s, k1),
        "the lineage closure must contain both keys")
  r <- signed("retraction", co_obj(retracts = a[["id"]]), "K2", 3L)
  co_store_put_record(s, r)   # successor may retract predecessor's record
  check(length(co_store_assertions_about(s, sym("cro:claim"))) == 0L,
        "the successor's retraction must take effect")
}

v34 <- function() {
  g <- normalize(vec(34)[["given"]])
  check(isTRUE(co_conflicts(g[["A"]], g[["B"]])),
        "preventive vs sufficient must conflict")
}

v35 <- function() {
  g <- normalize(vec(35)[["given"]])
  check(identical(co_conflicts(g[["A"]], g[["B"]]), FALSE),
        "contributory vs sufficient must not conflict")
}

v36 <- function() {
  A <- sym("occ:A"); B <- sym("occ:B"); C <- sym("occ:C"); D <- sym("occ:D")
  m1 <- co_obj(id = sym("cro:m1"), causes = co_arr(A), effects = co_arr(B))
  m2 <- co_obj(id = sym("cro:m2"), causes = co_arr(B), effects = co_arr(C))
  m3 <- co_obj(id = sym("cro:m3"), causes = co_arr(D), effects = co_arr(C))
  P <- co_obj(causes = co_arr(A), effects = co_arr(C),
              mechanism = co_arr(m1[["id"]], m2[["id"]]))
  members <- list()
  members[[m1[["id"]]]] <- m1
  members[[m2[["id"]]]] <- m2
  check(identical(co_hierarchy_consistent(P, members), "consistent"),
        "A -> B -> C must be consistent")
  P2 <- P
  P2[["mechanism"]] <- co_arr(m1[["id"]], m3[["id"]])
  members2 <- list()
  members2[[m1[["id"]]]] <- m1
  members2[[m3[["id"]]]] <- m3
  check(identical(co_hierarchy_consistent(P2, members2), "inconsistent"),
        "no path to C must be inconsistent")
  members3 <- list()
  members3[[m1[["id"]]]] <- m1
  check(identical(co_hierarchy_consistent(P, members3), "indeterminate"),
        "a missing member must be indeterminate")
}

v37 <- function() {
  s <- co_store_new()
  occ <- co_store_put(s, co_obj(type = "occurrent", label = "press_button",
                                category = "action"))
  co_store_put_record(s, signed(
    "enrichment",
    co_obj(about = occ, field = "aliases",
           entry = co_obj(lang = "en", text = "Press the Button")),
    "alice", 1L))
  res <- co_store_resolve(s, "Press  The   Button", "en")
  check(length(res) == 1L && identical(res[[1]], occ), "alias match")
  res2 <- co_store_resolve(s, "press_button", "en")
  check(length(res2) >= 1L && identical(res2[[1]], occ),
        "canonical-label match must rank first")
}

v38 <- function() {
  s <- co_store_new()
  P <- co_store_put(s, co_obj(type = "cro", causes = co_arr(sym("occ:A")),
                              effects = co_arr(sym("occ:B"))))
  check(P %in% gap_ids(co_store_gaps(s, "missing_field")),
        "the degenerate claim must be a visible gap")
  R <- co_store_put(s, co_obj(
    type = "cro", causes = co_arr(sym("occ:A")),
    effects = co_arr(sym("occ:B")),
    temporal = co_obj(dmin = 0, dmax = 1, unit = "seconds"),
    modality = "sufficient", refines = P))
  ids <- gap_ids(co_store_gaps(s, "missing_field"))
  check(!(P %in% ids), "the gap did not close")
  check(!(R %in% ids), "the refinement itself must be complete")
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

main <- function() {
  cat("causalontology-r conformance run\n")
  cat("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
  internal_checks()
  cat("ok\n")
  failures <- 0L
  for (n in 1:38) {
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
  cat(sprintf("%d/%d vectors passed\n", 38L - failures, 38L))
  if (failures > 0L) quit(save = "no", status = 1L)
  cat(paste0("causalontology-r is CONFORMANT to the suite ",
             "(vectors frozen at specification 1.0.0).\n"))
}

main()

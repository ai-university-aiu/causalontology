# causalontology-r -- json.R
#
# A lossless JSON layer written in base R.
#
# R has no built-in JSON support, so this file implements a
# recursive-descent JSON parser over base R string operations. The
# representation is designed so
# that the canonicalizer (jcs.R) can reproduce RFC 8785 byte-for-byte:
#
#   JSON object  -> a named list of class "co_obj" (named lists preserve
#                   insertion order in R, mirroring Python dict order)
#   JSON array   -> an unnamed list of class "co_arr"
#   JSON string  -> character(1), UTF-8
#   JSON number  -> double(1) carrying attr "co_shape": "int" when the
#                   source literal had no '.', 'e', or 'E'; "float"
#                   otherwise. R's native integer type is only 32-bit, so
#                   every number is held as a double (exact for integers
#                   up to 2^53 -- far beyond anything the standard uses;
#                   the largest constant is years = 31556952 seconds).
#   JSON true/false -> logical(1)
#   JSON null    -> the sentinel co_null below (NOT R NULL: assigning NULL
#                   into a list DELETES the element, the classic R trap)
#
# Values built programmatically by the conformance harness use the same
# shapes via the co_obj()/co_arr() constructors; plain untagged doubles are
# accepted everywhere and serialized by value (integral -> integer form),
# which matches the reference for every value the suite uses.

# --------------------------------------------------------------------------
# the JSON null sentinel and the container constructors
# --------------------------------------------------------------------------

# The unique JSON null sentinel: a zero-length list with a marker class.
co_null <- structure(list(), class = "co_json_null")

co_is_null <- function(x) inherits(x, "co_json_null")
co_is_obj  <- function(x) inherits(x, "co_obj")
co_is_arr  <- function(x) inherits(x, "co_arr")
co_is_str  <- function(x) is.character(x) && length(x) == 1L
co_is_bool <- function(x) is.logical(x) && length(x) == 1L
co_is_num  <- function(x) is.numeric(x) && !is.logical(x) && length(x) == 1L

# Normalize a scalar supplied by R code into the JSON value model.
co_wrap <- function(x) {
  if (co_is_null(x) || co_is_obj(x) || co_is_arr(x)) return(x)
  if (is.integer(x)) {
    # R integer literals (1L) become int-shaped doubles.
    v <- as.double(x)
    attr(v, "co_shape") <- "int"
    return(v)
  }
  x
}

# Build a JSON object from named arguments (co_obj(a = 1, b = "x")).
co_obj <- function(...) {
  items <- list(...)
  nm <- names(items)
  if (length(items) > 0L && (is.null(nm) || any(!nzchar(nm)))) {
    stop("co_obj() requires every argument to be named")
  }
  if (is.null(nm)) nm <- character(0)
  out <- vector("list", length(items))
  for (i in seq_along(items)) out[[i]] <- co_wrap(items[[i]])
  structure(stats::setNames(out, nm), class = "co_obj")
}

# Build a JSON array from positional arguments (co_arr("x", "y")).
co_arr <- function(...) {
  items <- list(...)
  out <- vector("list", length(items))
  for (i in seq_along(items)) out[[i]] <- co_wrap(items[[i]])
  structure(out, class = "co_arr")
}

# Build a JSON array from an existing list or character vector.
co_arr_from <- function(lst) {
  if (is.character(lst)) lst <- as.list(unname(lst))
  out <- vector("list", length(lst))
  for (i in seq_along(lst)) out[[i]] <- co_wrap(lst[[i]])
  structure(out, class = "co_arr")
}

# --------------------------------------------------------------------------
# field access (dict-like, exact-match only -- no $ partial matching)
# --------------------------------------------------------------------------

co_has <- function(obj, name) {
  if (!is.list(obj)) return(FALSE)
  nm <- names(obj)
  !is.null(nm) && name %in% nm
}

co_get <- function(obj, name, default = NULL) {
  if (co_has(obj, name)) obj[[name]] else default
}

# Delete a key if present (mirrors Python dict.pop(name, None)).
co_del <- function(obj, name) {
  if (co_has(obj, name)) obj[[name]] <- NULL
  obj
}

# Does a plain named list carry this key? (used for id-keyed stores)
co_has_key <- function(lst, key) {
  nm <- names(lst)
  !is.null(nm) && key %in% nm
}

# A co_arr (or character vector) of strings as a plain character vector.
co_strings <- function(arr) {
  if (is.null(arr) || co_is_null(arr)) return(character(0))
  if (is.character(arr)) return(as.character(unname(arr)))
  n <- length(arr)
  if (n == 0L) return(character(0))
  out <- character(n)
  for (i in seq_len(n)) out[[i]] <- as.character(arr[[i]])[[1]]
  out
}

# --------------------------------------------------------------------------
# bytes, hex, hashing
# --------------------------------------------------------------------------

# UTF-8 bytes of a string (multibyte text hashes as UTF-8 bytes, never as
# a locale encoding -- hence enc2utf8 before charToRaw).
co_utf8 <- function(s) charToRaw(enc2utf8(s))

# Lowercase hex of a raw vector (as.character on raw yields "9d" pairs).
co_bin2hex <- function(bytes) paste(as.character(bytes), collapse = "")

# Raw vector from a hex string; NULL when the input is not clean hex
# (mirrors Python bytes.fromhex raising ValueError).
co_hex2bin <- function(hex) {
  if (!co_is_str(hex)) return(NULL)
  if (nchar(hex, type = "bytes") %% 2L != 0L) return(NULL)
  if (!grepl("^[0-9a-fA-F]*$", hex)) return(NULL)
  n <- nchar(hex, type = "bytes") %/% 2L
  if (n == 0L) return(raw(0))
  pairs <- substring(hex, seq.int(1L, 2L * n, by = 2L), seq.int(2L, 2L * n, by = 2L))
  as.raw(strtoi(pairs, base = 16L))
}

# SHA-256 in pure base R (FIPS 180-4). No CRAN crypto package is available
# in this toolchain (neither openssl nor sodium is installed), so the hash
# is hand-rolled. 32-bit words are carried as DOUBLES in [0, 2^32): R's
# native 32-bit signed integer cannot represent 0x80000000 (that bit
# pattern is NA_integer_), and bitwShiftL overflows to NA past bit 31, so a
# signed-int representation is unusable. Bitwise ops are done on 16-bit
# halves (each < 2^16, safely an R integer); shifts and the modular add use
# ordinary floating arithmetic (exact for integers up to 2^53).
.co_bitop16 <- function(op) function(a, b) {
  op(a %% 65536, b %% 65536) + op(a %/% 65536, b %/% 65536) * 65536
}
.co_band <- .co_bitop16(bitwAnd)
.co_bor  <- .co_bitop16(bitwOr)
.co_bxor <- .co_bitop16(bitwXor)
.co_bnot <- function(a) 4294967295 - a
.co_shr  <- function(x, n) floor(x / (2^n))
.co_shl  <- function(x, n) (x * (2^n)) %% 4294967296
.co_rotr <- function(x, n) (.co_shr(x, n) + .co_shl(x, 32 - n)) %% 4294967296
.co_add32 <- function(...) { s <- 0; for (a in list(...)) s <- s + a; s %% 4294967296 }
.co_xor3 <- function(a, b, c) .co_bxor(.co_bxor(a, b), c)

.co_sha256_K <- c(
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
.co_sha256_H0 <- c(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)

# SHA-256 digest of raw bytes, as a plain raw vector.
co_sha256_raw <- function(bytes) {
  stopifnot(is.raw(bytes))
  bits <- length(bytes) * 8
  msg <- c(as.double(as.integer(bytes)), 128)   # append the 0x80 marker byte
  while (length(msg) %% 64 != 56) msg <- c(msg, 0)
  lenb <- numeric(8); b <- bits                  # 64-bit big-endian bit length
  for (i in 8:1) { lenb[i] <- b %% 256; b <- floor(b / 256) }
  msg <- c(msg, lenb)
  K <- .co_sha256_K
  H <- .co_sha256_H0
  for (blk in seq_len(length(msg) / 64)) {
    off <- (blk - 1) * 64
    w <- numeric(64)
    for (t in 1:16) {
      j <- off + (t - 1) * 4
      w[t] <- msg[j+1]*2^24 + msg[j+2]*2^16 + msg[j+3]*2^8 + msg[j+4]
    }
    for (t in 17:64) {
      s0 <- .co_xor3(.co_rotr(w[t-15],7),  .co_rotr(w[t-15],18), .co_shr(w[t-15],3))
      s1 <- .co_xor3(.co_rotr(w[t-2],17),  .co_rotr(w[t-2],19),  .co_shr(w[t-2],10))
      w[t] <- .co_add32(w[t-16], s0, w[t-7], s1)
    }
    a<-H[1]; b<-H[2]; c<-H[3]; d<-H[4]; e<-H[5]; f<-H[6]; g<-H[7]; h<-H[8]
    for (t in 1:64) {
      S1 <- .co_xor3(.co_rotr(e,6), .co_rotr(e,11), .co_rotr(e,25))
      ch <- .co_bxor(.co_band(e,f), .co_band(.co_bnot(e),g))
      t1 <- .co_add32(h, S1, ch, K[t], w[t])
      S0 <- .co_xor3(.co_rotr(a,2), .co_rotr(a,13), .co_rotr(a,22))
      maj <- .co_xor3(.co_band(a,b), .co_band(a,c), .co_band(b,c))
      t2 <- .co_add32(S0, maj)
      h<-g; g<-f; f<-e; e<-.co_add32(d,t1); d<-c; c<-b; b<-a; a<-.co_add32(t1,t2)
    }
    H <- c(.co_add32(H[1],a), .co_add32(H[2],b), .co_add32(H[3],c), .co_add32(H[4],d),
           .co_add32(H[5],e), .co_add32(H[6],f), .co_add32(H[7],g), .co_add32(H[8],h))
  }
  out <- raw(32)
  for (i in 1:8) {
    u <- H[i]
    out[(i-1)*4+1] <- as.raw(floor(u/2^24) %% 256)
    out[(i-1)*4+2] <- as.raw(floor(u/2^16) %% 256)
    out[(i-1)*4+3] <- as.raw(floor(u/2^8)  %% 256)
    out[(i-1)*4+4] <- as.raw(u %% 256)
  }
  out
}

# SHA-256 digest of raw bytes as lowercase hex.
co_sha256_hex <- function(bytes) co_bin2hex(co_sha256_raw(bytes))

# --------------------------------------------------------------------------
# code-point string ordering (locale-independent)
# --------------------------------------------------------------------------

# a > b by Unicode code points, like Python's str comparison. R's native
# ">" collates by locale, which can reorder punctuation -- never use it
# for deterministic tie-breaking.
co_str_gt <- function(a, b) {
  ai <- utf8ToInt(enc2utf8(a))
  bi <- utf8ToInt(enc2utf8(b))
  n <- min(length(ai), length(bi))
  if (n > 0L) {
    for (i in seq_len(n)) {
      if (ai[[i]] != bi[[i]]) return(ai[[i]] > bi[[i]])
    }
  }
  length(ai) > length(bi)
}

# Sort keys by code point. method = "radix" sorts in the C locale
# (bytewise over UTF-8, which preserves code-point order), immune to
# LC_COLLATE. All schema and object keys here are ASCII anyway.
co_sort_codepoint <- function(keys) {
  if (length(keys) <= 1L) return(keys)
  sort(keys, method = "radix")
}

# --------------------------------------------------------------------------
# deep structural equality (mirrors Python == on parsed JSON)
# --------------------------------------------------------------------------

co_equal <- function(a, b) {
  if (is.null(a) || is.null(b)) return(is.null(a) && is.null(b))
  if (co_is_null(a) || co_is_null(b)) return(co_is_null(a) && co_is_null(b))
  if (co_is_obj(a) || co_is_obj(b)) {
    if (!(co_is_obj(a) && co_is_obj(b))) return(FALSE)
    na <- names(a); if (is.null(na)) na <- character(0)
    nb <- names(b); if (is.null(nb)) nb <- character(0)
    if (length(na) != length(nb)) return(FALSE)
    if (!setequal(na, nb)) return(FALSE)     # dict equality ignores order
    for (k in na) {
      if (!co_equal(a[[k]], b[[k]])) return(FALSE)
    }
    return(TRUE)
  }
  if (co_is_arr(a) || co_is_arr(b)) {
    if (!(co_is_arr(a) && co_is_arr(b))) return(FALSE)
    if (length(a) != length(b)) return(FALSE)
    for (i in seq_len(length(a))) {          # seq_len: safe when length 0
      if (!co_equal(a[[i]], b[[i]])) return(FALSE)
    }
    return(TRUE)
  }
  if (is.logical(a) || is.logical(b)) {
    return(is.logical(a) && is.logical(b) && identical(unname(a), unname(b)))
  }
  if (is.numeric(a) || is.numeric(b)) {
    if (!(is.numeric(a) && is.numeric(b))) return(FALSE)
    return(isTRUE(as.numeric(a)[[1]] == as.numeric(b)[[1]]))  # 1 == 1.0
  }
  if (is.character(a) && is.character(b)) {
    return(identical(enc2utf8(unname(a)), enc2utf8(unname(b))))
  }
  identical(a, b)
}

# --------------------------------------------------------------------------
# repository root discovery (shared by schema loading and the harness)
# --------------------------------------------------------------------------

co_state <- new.env(parent = emptyenv())

co_set_root <- function(path) assign("root", path, envir = co_state)

co_repo_root <- function() {
  if (exists("root", envir = co_state, inherits = FALSE)) {
    return(get("root", envir = co_state, inherits = FALSE))
  }
  env <- Sys.getenv("CAUSALONTOLOGY_ROOT", unset = "")
  if (nzchar(env)) return(env)
  dir <- normalizePath(getwd())
  repeat {
    if (dir.exists(file.path(dir, "conformance", "vectors"))) return(dir)
    parent <- dirname(dir)
    if (identical(parent, dir)) stop("cannot locate the repository root")
    dir <- parent
  }
}

# --------------------------------------------------------------------------
# the JSON parser (recursive descent, character by character)
# --------------------------------------------------------------------------

co_parse_json <- function(text) {
  text <- enc2utf8(text)
  if (startsWith(text, intToUtf8(0xFEFF))) {   # tolerate a UTF-8 BOM
    text <- substring(text, 2L)
  }
  st <- new.env(parent = emptyenv())
  st$chars <- strsplit(text, "", fixed = FALSE)[[1]]
  st$n <- length(st$chars)
  st$pos <- 1L
  val <- co_p_value(st)
  co_p_skip_ws(st)
  if (st$pos <= st$n) stop("JSON: trailing content at position ", st$pos)
  val
}

co_p_peek <- function(st) {
  if (st$pos > st$n) "" else st$chars[[st$pos]]
}

co_p_take <- function(st) {
  if (st$pos > st$n) stop("JSON: unexpected end of input")
  ch <- st$chars[[st$pos]]
  st$pos <- st$pos + 1L
  ch
}

co_p_skip_ws <- function(st) {
  while (st$pos <= st$n && st$chars[[st$pos]] %in% c(" ", "\t", "\n", "\r")) {
    st$pos <- st$pos + 1L
  }
  invisible(NULL)
}

co_p_expect <- function(st, ch) {
  got <- co_p_take(st)
  if (!identical(got, ch)) {
    stop("JSON: expected '", ch, "' but found '", got, "' at position ", st$pos - 1L)
  }
  invisible(NULL)
}

co_p_value <- function(st) {
  co_p_skip_ws(st)
  ch <- co_p_peek(st)
  if (identical(ch, "{")) return(co_p_object(st))
  if (identical(ch, "[")) return(co_p_array(st))
  if (identical(ch, "\"")) return(co_p_string(st))
  if (identical(ch, "t")) { co_p_literal(st, "true");  return(TRUE) }
  if (identical(ch, "f")) { co_p_literal(st, "false"); return(FALSE) }
  if (identical(ch, "n")) { co_p_literal(st, "null");  return(co_null) }
  if (ch %in% c("-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9")) {
    return(co_p_number(st))
  }
  stop("JSON: unexpected character '", ch, "' at position ", st$pos)
}

co_p_literal <- function(st, word) {
  for (ch in strsplit(word, "", fixed = FALSE)[[1]]) co_p_expect(st, ch)
  invisible(NULL)
}

co_p_object <- function(st) {
  co_p_expect(st, "{")
  keys <- character(0)
  vals <- list()
  co_p_skip_ws(st)
  if (identical(co_p_peek(st), "}")) {
    co_p_take(st)
    return(structure(stats::setNames(list(), character(0)), class = "co_obj"))
  }
  repeat {
    co_p_skip_ws(st)
    key <- co_p_string(st)
    co_p_skip_ws(st)
    co_p_expect(st, ":")
    val <- co_p_value(st)
    idx <- match(key, keys)
    if (is.na(idx)) {                        # duplicate keys: last wins
      keys <- c(keys, key)
      vals[[length(vals) + 1L]] <- val
    } else {
      vals[[idx]] <- val
    }
    co_p_skip_ws(st)
    ch <- co_p_take(st)
    if (identical(ch, "}")) break
    if (!identical(ch, ",")) stop("JSON: expected ',' or '}' in object")
  }
  structure(stats::setNames(vals, keys), class = "co_obj")
}

co_p_array <- function(st) {
  co_p_expect(st, "[")
  vals <- list()
  co_p_skip_ws(st)
  if (identical(co_p_peek(st), "]")) {
    co_p_take(st)
    return(structure(list(), class = "co_arr"))
  }
  repeat {
    vals[[length(vals) + 1L]] <- co_p_value(st)
    co_p_skip_ws(st)
    ch <- co_p_take(st)
    if (identical(ch, "]")) break
    if (!identical(ch, ",")) stop("JSON: expected ',' or ']' in array")
  }
  structure(vals, class = "co_arr")
}

co_p_hex4 <- function(st) {
  h <- paste0(co_p_take(st), co_p_take(st), co_p_take(st), co_p_take(st))
  if (!grepl("^[0-9a-fA-F]{4}$", h)) stop("JSON: bad \\u escape '", h, "'")
  strtoi(h, base = 16L)
}

co_p_string <- function(st) {
  co_p_expect(st, "\"")
  buf <- character(0)
  repeat {
    ch <- co_p_take(st)
    if (identical(ch, "\"")) break
    if (identical(ch, "\\")) {
      esc <- co_p_take(st)
      if (esc == "\"")      buf <- c(buf, "\"")
      else if (esc == "\\") buf <- c(buf, "\\")
      else if (esc == "/")  buf <- c(buf, "/")
      else if (esc == "b")  buf <- c(buf, "\b")
      else if (esc == "f")  buf <- c(buf, "\f")
      else if (esc == "n")  buf <- c(buf, "\n")
      else if (esc == "r")  buf <- c(buf, "\r")
      else if (esc == "t")  buf <- c(buf, "\t")
      else if (esc == "u") {
        cp <- co_p_hex4(st)
        if (cp >= 0xD800 && cp <= 0xDBFF) {  # UTF-16 surrogate pair
          if (!identical(co_p_take(st), "\\") || !identical(co_p_take(st), "u")) {
            stop("JSON: lone high surrogate")
          }
          lo <- co_p_hex4(st)
          if (lo < 0xDC00 || lo > 0xDFFF) stop("JSON: bad low surrogate")
          cp <- 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
          stop("JSON: lone low surrogate")
        }
        buf <- c(buf, intToUtf8(cp))
      } else {
        stop("JSON: bad escape '\\", esc, "'")
      }
    } else {
      buf <- c(buf, ch)
    }
  }
  s <- paste(buf, collapse = "")
  enc2utf8(s)
}

co_p_number <- function(st) {
  numchars <- c("-", "+", ".", "e", "E",
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9")
  buf <- character(0)
  while (st$pos <= st$n && st$chars[[st$pos]] %in% numchars) {
    buf <- c(buf, st$chars[[st$pos]])
    st$pos <- st$pos + 1L
  }
  lit <- paste(buf, collapse = "")
  if (!grepl("^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$", lit)) {
    stop("JSON: bad number literal '", lit, "'")
  }
  v <- as.numeric(lit)
  # The SHAPE TAG: no '.', 'e', or 'E' in the literal means integer-shaped.
  attr(v, "co_shape") <- if (grepl("[.eE]", lit)) "float" else "int"
  v
}

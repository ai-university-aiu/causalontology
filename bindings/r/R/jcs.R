# causalontology-r -- jcs.R
#
# RFC 8785 (JSON Canonicalization Scheme) serialization, ported from the
# reference bindings/python/causalontology/canonical.py (_jcs and friends).
#
# Number policy (matching the reference for the value ranges the standard
# uses -- see the note in canonical.py):
#   integer-shaped (attr co_shape == "int")        -> sprintf("%.0f")
#   float-shaped but integral and |x| < 1e21       -> sprintf("%.0f")
#   otherwise                                      -> shortest round-trip
#     decimal, with C-style exponents ("1e-07") normalized to the
#     ECMAScript form ("1e-7") exactly as the reference does.
# Untagged doubles (values built by R code rather than parsed from JSON)
# fall through to the same by-value rules, which reproduce the reference
# output for every value in the suite (0 -> "0", 0.8 -> "0.8").

# Minimal string escaping per RFC 8785: the two mandatory escapes, the
# short names for the common controls, \u00xx for the rest below 0x20.
co_jcs_string <- function(s) {
  chars <- strsplit(enc2utf8(s), "", fixed = FALSE)[[1]]
  out <- character(length(chars))
  for (i in seq_along(chars)) {
    ch <- chars[[i]]
    if (identical(ch, "\"")) {
      out[[i]] <- "\\\""
    } else if (identical(ch, "\\")) {
      out[[i]] <- "\\\\"
    } else if (identical(ch, "\b")) {
      out[[i]] <- "\\b"
    } else if (identical(ch, "\t")) {
      out[[i]] <- "\\t"
    } else if (identical(ch, "\n")) {
      out[[i]] <- "\\n"
    } else if (identical(ch, "\f")) {
      out[[i]] <- "\\f"
    } else if (identical(ch, "\r")) {
      out[[i]] <- "\\r"
    } else {
      cp <- utf8ToInt(ch)
      if (cp < 0x20) {
        out[[i]] <- sprintf("\\u%04x", cp)
      } else {
        out[[i]] <- ch
      }
    }
  }
  paste0("\"", paste(out, collapse = ""), "\"")
}

# The shortest decimal string that round-trips to exactly x (the analogue
# of Python's repr / ECMAScript's Number::toString for our value range).
co_shortest_double <- function(x) {
  for (digits in 1:17) {
    s <- sprintf("%.*g", digits, x)
    if (isTRUE(as.numeric(s) == x)) return(s)
  }
  sprintf("%.17g", x)
}

co_jcs_number <- function(n) {
  # booleans are handled by co_jcs before this point
  shape <- attr(n, "co_shape")
  v <- as.numeric(n)[[1]]
  if (!is.finite(v)) stop("NaN and Infinity are not permitted (RFC 8785)")
  if (identical(shape, "int")) {
    return(sprintf("%.0f", v))          # exact for |v| <= 2^53
  }
  if (isTRUE(v == 0)) return("0")
  if (isTRUE(v == floor(v)) && abs(v) < 1e21) {
    return(sprintf("%.0f", v))          # 1.0 -> "1", 6.000 -> "6"
  }
  s <- co_shortest_double(v)            # 0.7 -> "0.7"
  if (grepl("e", s, fixed = TRUE)) {    # normalize exponent: 1e-07 -> 1e-7
    parts <- strsplit(s, "e", fixed = TRUE)[[1]]
    mant <- parts[[1]]
    ex <- parts[[2]]
    sign <- if (identical(substring(ex, 1L, 1L), "-")) "-" else "+"
    digits <- sub("^[+-]?0*", "", ex)
    if (!nzchar(digits)) digits <- "0"
    s <- paste0(mant, "e", sign, digits)
  }
  s
}

# Serialize one value in RFC 8785 canonical form.
co_jcs <- function(value) {
  if (is.null(value) || co_is_null(value)) return("null")
  if (co_is_obj(value)) {
    keys <- names(value)
    if (is.null(keys)) keys <- character(0)
    keys <- co_sort_codepoint(keys)     # sorted keys, code-point order
    parts <- character(length(keys))
    for (i in seq_along(keys)) {
      k <- keys[[i]]
      parts[[i]] <- paste0(co_jcs_string(k), ":", co_jcs(value[[k]]))
    }
    return(paste0("{", paste(parts, collapse = ","), "}"))
  }
  if (co_is_arr(value)) {
    parts <- character(length(value))
    for (i in seq_along(value)) parts[[i]] <- co_jcs(value[[i]])
    return(paste0("[", paste(parts, collapse = ","), "]"))
  }
  if (is.logical(value)) return(if (isTRUE(value[[1]])) "true" else "false")
  if (is.numeric(value)) return(co_jcs_number(value))
  if (is.character(value)) return(co_jcs_string(value[[1]]))
  stop("cannot canonicalize value of class ", paste(class(value), collapse = "/"))
}

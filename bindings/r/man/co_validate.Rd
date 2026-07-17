\name{co_validate}
\alias{co_validate}
\alias{co_validate_schema}
\alias{co_validate_semantics}
\title{Schema and semantic validation}
\description{
Validate a Causalontology object. \code{co_validate_schema} checks it against
the specification's JSON Schema for its kind; \code{co_validate_semantics}
checks the semantic rules (for example temporal-window ordering, modality
coherence, and the well-formedness rules for bridges, ports, and conduits).
}
\usage{
co_validate_schema(obj, kind = NULL)
co_validate_semantics(obj, kind = NULL)
}
\arguments{
  \item{obj}{A parsed Causalontology object (e.g. from
    \code{\link{co_parse_json}}).}
  \item{kind}{Optional object kind (character). If \code{NULL} it is inferred
    with \code{\link{co_infer_kind}}.}
}
\value{
A list with \code{ok} (logical, \code{TRUE} if valid) and \code{errors} (a
character vector of violation messages, empty when \code{ok} is \code{TRUE}).
}
\details{
\code{co_validate_schema} reads the specification JSON Schemas from disk; point
\code{\link{co_set_root}} at a checkout of the standard's repository (or set the
\code{CAUSALONTOLOGY_ROOT} environment variable) before calling it.
\code{co_validate_semantics} is self-contained and needs no external files.
}
\examples{
occ <- co_parse_json(
  '{"type":"occurrent","label":"press_button","category":"action"}')
sem <- co_validate_semantics(occ)
sem$ok

\dontrun{
# Schema validation needs the specification schemas on disk.
co_set_root("/path/to/causalontology")
co_validate_schema(occ)$ok
}
}
\seealso{\code{\link{co_set_root}}, \code{\link{co_store_new}}}
\keyword{ validation }

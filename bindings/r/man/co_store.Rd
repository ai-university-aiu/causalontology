\name{co_store}
\alias{co_store}
\alias{co_store_new}
\alias{co_store_put}
\alias{co_store_put_record}
\alias{co_store_get}
\alias{co_store_resolve}
\alias{co_store_gaps}
\alias{co_store_lineage}
\alias{co_store_assertions_about}
\alias{co_store_enrichments_about}
\title{The in-memory conformant store}
\description{
An in-memory Causalontology store: idempotent immutable puts of content objects,
signed add-only provenance records with quarantine of the unsigned, materialized
enrichment views, retraction and succession lineage, alias resolution, and the
stigmergy gap read. Content is addressed by identity, so a re-put of the same
object is a no-op.
}
\usage{
co_store_new(enforcing = TRUE)
co_store_put(s, obj, kind = NULL)
co_store_put_record(s, record, kind = NULL, force = FALSE)
co_store_get(s, identifier, view = "default")
co_store_resolve(s, text, lang = NULL)
co_store_gaps(s, kind = NULL)
co_store_lineage(s, key)
co_store_assertions_about(s, identifier, include_retracted = FALSE)
co_store_enrichments_about(s, identifier, include_retracted = FALSE)
}
\arguments{
  \item{enforcing}{Logical. If \code{TRUE} (the default) puts are validated
    against the JSON Schemas and semantic rules, which requires the schemas on
    disk (see \code{\link{co_set_root}}); if \code{FALSE} validation is skipped.}
  \item{s}{A store created by \code{co_store_new}.}
  \item{obj}{A parsed content object (e.g. from \code{\link{co_parse_json}}).}
  \item{record}{A signed provenance record (assertion, enrichment, retraction,
    or succession).}
  \item{kind}{Optional object kind (character); inferred when \code{NULL}.}
  \item{force}{Logical; if \code{TRUE}, admit a record without signature
    verification (used for imports).}
  \item{identifier}{A content-addressed id string \code{"<kind>:<hex>"}.}
  \item{view}{Either \code{"default"} (retractions applied) or \code{"history"}
    (everything, marked).}
  \item{text}{A label or alias to resolve.}
  \item{lang}{Optional language tag for alias resolution.}
  \item{key}{An id whose succession lineage to trace.}
  \item{include_retracted}{Logical; include retracted records in the result.}
}
\value{
\code{co_store_new} returns a store. \code{co_store_put} returns the object's
content-addressed id. \code{co_store_get} returns the object with its
materialized view (or \code{NULL} if absent). \code{co_store_resolve} returns
the matching ids; \code{co_store_gaps} the ranked open gaps;
\code{co_store_lineage} the succession chain; and
\code{co_store_assertions_about} / \code{co_store_enrichments_about} the records
about an object.
}
\examples{
# A non-enforcing store needs no schema files on disk.
s <- co_store_new(enforcing = FALSE)
occ <- co_parse_json(
  '{"type":"occurrent","label":"press_button","category":"action"}')
id <- co_store_put(s, occ)
id
got <- co_store_get(s, id)
hits <- co_store_resolve(s, "press_button")
gaps <- co_store_gaps(s)
lineage <- co_store_lineage(s, id)
co_store_assertions_about(s, id)
co_store_enrichments_about(s, id)
}
\seealso{\code{\link{co_parse_json}}, \code{\link{co_sign_record}},
  \code{\link{co_set_root}}}
\keyword{ store }

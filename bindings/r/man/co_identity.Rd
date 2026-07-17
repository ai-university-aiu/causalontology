\name{co_identity}
\alias{co_identity}
\alias{co_identify}
\alias{co_canonicalize}
\alias{co_infer_kind}
\title{Content-addressed identity and canonicalization}
\description{
Compute a Causalontology object's content-addressed identity. An object's id is
its kind followed by the SHA-256 hash of its RFC 8785 (JSON Canonicalization
Scheme) canonical identity-bearing bytes. Two objects with the same
identity-bearing content have the same id, in every binding.
}
\usage{
co_identify(obj, kind = NULL)
co_canonicalize(obj, kind = NULL)
co_infer_kind(obj)
}
\arguments{
  \item{obj}{A parsed Causalontology object (e.g. from
    \code{\link{co_parse_json}}).}
  \item{kind}{Optional object kind (character). If \code{NULL} it is inferred
    from the object's \code{type} field.}
}
\value{
\code{co_identify} returns the id string \code{"<kind>:<hex>"}.
\code{co_canonicalize} returns the canonical identity-bearing bytes as a
\code{raw} vector. \code{co_infer_kind} returns the kind (character).
}
\examples{
occ <- co_parse_json(
  '{"type":"occurrent","label":"press_button","category":"action"}')
co_infer_kind(occ)
co_identify(occ)
length(co_canonicalize(occ))
}
\seealso{\code{\link{co_signing}}, \code{\link{co_validate_schema}}}
\keyword{ identity }

\name{co_parse_json}
\alias{co_parse_json}
\title{Parse JSON into a Causalontology object}
\description{
Parse a JSON text into the internal object representation used by the binding.
The parser is order-preserving and distinguishes the JSON types (object, array,
string, number, boolean, null) as the standard requires, so that
canonicalization and identity are exact. Use this to build the records passed to
the identity, signing, validation, and store functions.
}
\usage{
co_parse_json(text)
}
\arguments{
  \item{text}{A single character string containing one JSON value.}
}
\value{
The parsed object in the binding's internal representation (suitable for
\code{\link{co_identify}}, \code{\link{co_sign_record}},
\code{\link{co_validate_semantics}}, and the \code{co_store_*} functions).
}
\examples{
occ <- co_parse_json(
  '{"type":"occurrent","label":"light_on","category":"state_change"}')
co_identify(occ)
}
\seealso{\code{\link{co_identify}}, \code{\link{co_store_put}}}
\keyword{ json }

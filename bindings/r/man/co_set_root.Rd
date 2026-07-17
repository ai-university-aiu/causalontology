\name{co_set_root}
\alias{co_set_root}
\title{Set the specification repository root}
\description{
Set the directory the binding uses to locate the specification's JSON Schemas
(and, for the conformance runner, the vectors). This is needed only by
\code{\link{co_validate_schema}} and schema-enforcing stores; the identity,
signing, and semantic-validation functions are self-contained. The
\code{CAUSALONTOLOGY_ROOT} environment variable has the same effect.
}
\usage{
co_set_root(path)
}
\arguments{
  \item{path}{A character string: the path to a checkout of the standard's
    repository (the directory containing \code{spec/schema/}).}
}
\value{
Called for its side effect; returns the path invisibly.
}
\examples{
\dontrun{
co_set_root("/path/to/causalontology")
}
}
\seealso{\code{\link{co_validate_schema}}}
\keyword{ configuration }

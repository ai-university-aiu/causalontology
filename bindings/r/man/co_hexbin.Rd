\name{co_hexbin}
\alias{co_hex2bin}
\alias{co_bin2hex}
\title{Convert between hexadecimal strings and raw bytes}
\description{
Small utilities for moving between lowercase hexadecimal strings and \code{raw}
byte vectors, used when constructing 32-byte seeds and when reading raw keys and
signatures.
}
\usage{
co_hex2bin(hex)
co_bin2hex(bytes)
}
\arguments{
  \item{hex}{A character string of an even number of hexadecimal digits.}
  \item{bytes}{A \code{raw} vector.}
}
\value{
\code{co_hex2bin} returns a \code{raw} vector; \code{co_bin2hex} returns a
lowercase hexadecimal character string.
}
\examples{
b <- co_hex2bin("00ff10")
b
co_bin2hex(b)
}
\seealso{\code{\link{co_keypair_from_seed}}}
\keyword{ utilities }

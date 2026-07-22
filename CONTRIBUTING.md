# Contributing

Thank you for your interest in Causalontology. The standard is defined by the
normative specification under [`spec/`](spec/) and gated by the conformance
vectors under [`conformance/vectors/`](conformance/vectors/).

## The one rule

**An implementation is Causalontology-conformant if and only if it passes every
vector in `conformance/vectors/` for the specification version it declares.**

That rule is how nineteen implementations in nineteen languages agree without
sharing a line of code. Everything below serves it.

## Contributing a new language binding

1. Implement the standard: content-addressed identity (RFC 8785 + Secure Hash Algorithm 256-bit (SHA-256)),
   record-level Ed25519 signing (RFC 8032), schema and semantic validation, and
   ideally the store protocol. Prefer the standard library; keep dependencies
   vetted and minimal.
2. Ship `conformance/vectors/` as your binding's own test suite and gate on it.
   All 119 vectors must pass.
3. Cross-check byte-identity: your content-addressed ids must match the Python
   reference for the same inputs. That byte-identity is the whole point.
4. Follow the naming conventions in [NAMING.md](NAMING.md) — whole-word
   identifier schemes (Principle P7), no abbreviations.
5. Open a pull request. Wire your binding into
   [`.github/workflows/conformance.yml`](.github/workflows/conformance.yml) so
   CI runs its vectors.

## Proposing a change to the specification

Specification changes follow the process in [GOVERNANCE.md](GOVERNANCE.md), in
the spirit of a W3C or IETF working group: a written change order, the
Semantic-Versioning rules (a new object kind or a breaking identity change is a
MAJOR version), and the vectors re-frozen once per release. A failing release is
not published.

## Reporting bugs and vulnerabilities

- Functional bugs: open a GitHub issue, ideally with a conformance-style
  reproduction (an input and the wrong output).
- Security issues: do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

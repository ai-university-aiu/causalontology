# Governance

- The specification is versioned with **Semantic Versioning**; every binding
  and store declares the version it implements. The conformance suite is
  versioned in lock-step — "conformant" always means "conformant to a named
  version".
- **The enumeration rule**: closed enumerations (occurrent categories,
  continuant categories, modalities, evidence types, enrichment fields) are
  part of the validator contract and, for the vocabulary categories, part of
  the identity guarantee. **Extending any closed enumeration is a MAJOR
  version change**, never MINOR. Adding a wholly new object kind (such as the
  reserved token-level `tok:` kind) is likewise MAJOR for validators that
  enforce closed kind lists.
- Every binding is gated in Continuous Integration on the conformance
  vectors; a failing release is not published.
- Change process (in the spirit of a W3C or IETF working group): a written
  proposal, review in the open, a **conformance impact statement** (which
  vectors change), and a decision recorded in this repository.
- The takedown procedure (spec/safety.md) is part of governance; every
  takedown and every registry re-binding after key compromise is publicly
  logged.

## The archive rule

Old versions of versioned documents never remain at their published location.
Whenever a new version of a versioned document is created (the Standalone
Design canon, or any future versioned series), the superseded version is moved
into `archive/` **in the same change**, and only the latest version of each
series lives outside `archive/`. On every document update, sweep for
stragglers: if more than one version of a series is present outside
`archive/`, move all but the highest version in. Nothing is deleted — the
archive is the lineage.

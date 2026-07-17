# Security Policy

Causalontology is a standard for signed, content-addressed causal knowledge.
Its integrity model rests on three primitives: content-addressed identity
(SHA-256 over RFC 8785 canonical bytes), record-level Ed25519 signatures
(RFC 8032), and deterministic, byte-identical behavior across all bindings. A
defect in any of these — or in a binding's implementation of them — is a
security concern.

## Supported versions

| Version | Supported |
|---|---|
| 2.0.x | Yes |
| 1.0.x | No (superseded by the 2.0.0 whole-word re-mint) |

Security fixes are made against the latest 2.0.x line.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
issue for a security report.

- Preferred: open a private security advisory via GitHub
  (**Security → Report a vulnerability** on the repository), or
- Email **ai.university.aiu@gmail.com** with the details.

Please include a description, the affected binding(s) or specification section,
and a reproduction (ideally a conformance-style vector: an input and the wrong
output). We aim to acknowledge within a few business days and to coordinate a
fix and disclosure timeline with you.

### In scope

- Identity or canonicalization flaws (two distinct records sharing an id; the
  same record producing different ids across bindings; RFC 8785 deviations).
- Signature flaws (forgeable or malleable Ed25519 signatures; verification that
  accepts tampered records; a binding that signs or verifies incorrectly).
- Any deviation that lets a binding accept a record another binding rejects, or
  vice versa, in a way that could be exploited.
- Vulnerabilities in the reference store (authentication, quarantine, retraction
  handling).

### Out of scope

- Vulnerabilities in third-party toolchains or transitive dependencies (report
  those upstream), though we welcome a heads-up.
- Denial of service from deliberately malformed input that is correctly
  rejected.

## Verifying artifacts

- **Records** are self-authenticating: the content-addressed id changes if any
  identity-bearing field is altered, and the Ed25519 signature binds the record
  to its author's public key. Verify both before trusting a record.
- **Maven Central artifacts** (the Java and Kotlin/Native releases) are signed
  with the project's OpenPGP key. Fingerprint:

  ```
  4286 FBC1 B2D0 4E46 A5C5  C060 429A CA5F CFA1 83D4
  ```

  Verify the `.asc` signature against this key before use.
- **Other registries** provide their own integrity guarantees (checksums,
  immutable versions, the Go checksum database `sum.golang.org`, the Zig package
  hash). Pin versions and verify checksums where your toolchain supports it.

## Coordinated disclosure

We follow coordinated disclosure: we will work with you on a fix, credit you
(unless you prefer otherwise), and publish an advisory once a fixed release is
available.

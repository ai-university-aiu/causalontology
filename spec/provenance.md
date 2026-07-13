# Provenance: signatures, evidence, retraction, succession, and trust

- **Source identity** = an Ed25519 public key (RFC 8032), written
  `ed25519:<64 hex>`. The key is the identity; display names bind in a
  registry. Nobody can forge a record without the private key — which is why
  attribution lives ONLY in signed records, never in unsigned tags (an
  unsigned "contributed_by" would enable a framing attack).
- **Signing**: over the record's canonical identity-bearing bytes (RFC 8785
  form with `id` and `signature` removed) — the same bytes that are hashed.
  Verification needs only the record itself. Ed25519 is deterministic, so
  re-submission is exactly idempotent.
- **Evidence grading**: intervention > observation > derivation > human_hint >
  imported. Acting beats watching.
- **Materialized views**: an object's enrichment sets are DERIVED from
  unretracted enrichment records; each entry carries its contributors; the
  same entry from two sources is one displayed entry with two contributors
  (corroboration). Default views exclude retracted and quarantined records.
- **Retraction**: a source's honest exit — for assertions AND enrichments.
  Default trust policies exclude retracted records; consumers may opt into
  history knowingly.
- **Succession**: key rotation with lineage; trust follows successors;
  successors may retract predecessors' records; conflicting successions freeze
  automatic following.
- **Trust without forced consensus**: the store records claims with signed
  assertions and lets every consumer choose a trust policy (by source,
  evidence type, confidence, recency). Recommended default aggregation (not
  mandated): confidence-weighted mean over trusted sources, intervention
  weighted above observation. Contradictions coexist and are surfaced.

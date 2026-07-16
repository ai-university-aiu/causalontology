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
- **Evidence grading**: intervention > observation > **simulation** > derivation
  > human_hint > imported. Acting beats watching; watching beats simulating.
  `simulation` (2.0.0) grades a synthetic mind's model-based/counterfactual
  evidence: real, gradeable, but ranked below observation and never silently
  graded as it.
- **Evidence hierarchy, now with a mechanism** (2.0.0): an assertion may carry
  `evidenced_by`, an array of the PARTICULAR token records
  (`token_occurrence:`, `token_causal_claim:`, `state_assertion:`) that are its
  evidence. A store can then distinguish a law induced from ten INTERVENTIONAL
  tokens from one induced from a thousand OBSERVED tokens and weight them. The
  `about` field is widened to accept all nine new content prefixes.
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

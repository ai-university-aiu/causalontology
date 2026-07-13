# Safety: abuse resistance, claims of consequence, takedown by tier

## Abuse resistance

- **Forgery**: impossible without the private key — every record is signed.
- **Sybil attacks**: keys are free to mint, so trust NEVER attaches to
  key-count; it attaches to consumer-chosen trust policies over specific
  sources. Tier A adds rate limits; reputation weights history and
  corroboration, never volume.
- **Data poisoning**: signed provenance makes poison attributable; retraction
  gives honest sources an exit while a poisoner's history stays pinned to its
  key; conflicts surface rather than silently average.
- **Vocabulary vandalism**: every enrichment is signed — attributable at every
  tier, suppressible by source key, removable by the author's own retraction.
  Grow-only views mean vandalism can never destroy good data.
- **Unsigned material**: quarantine visibility tier only, excluded from
  default queries.

## Claims of consequence

Health, safety, legal, and financial claims: always served with provenance and
confidence displayed, never as bare fact; records MUST be signed (unsigned ->
quarantined without exception); interfaces carry a standing notice that the
commons records who claims what, with what evidence — it does not dispense
medical, legal, or financial advice.

## Takedown, honestly, by tier

- **Tier A**: operator hard-delete, publicly logged (actor, target, ground).
- **Tier B**: origin deletes locally + signed suppression notice; peers
  SHOULD honor; compliance is per-node and auditable.
- **Tier C**: copies cannot be forcibly deleted; takedown = signed TOMBSTONE
  honored by all conformant default views, plus the public log. This is the
  honest limit of decentralization, stated in advance.

## Privacy

The commons is for general, TYPE-LEVEL causal knowledge; claims about
identifiable private individuals are out of scope and removable. Tier A can
honor erasure requests fully; Tier C only in the tombstone sense — a fact a
deployer must weigh before choosing a tier.

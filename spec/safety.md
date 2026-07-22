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

## Token-tier safety: the unforgetting store

*(Required by change order 2.0.0 §10.4 and N5.1.3. This is a BLOCKING
PRECONDITION for the token tier: it landed before `token_individual:` was
implemented, not after.)*

Causalontology 2.0.0 introduces the token tier: records of particular things
(`token_individual:`), particular happenings (`token_occurrence:`), particular
states (`state_assertion:`), and particular causings (`token_causal_claim:`).

This tier is what permits a mind to have a history. It is also the point at
which this specification becomes capable of harm, and implementers must
understand precisely why.

### The structural problem

Causalontology is content-addressed, add-only, and merges by set union. These
three properties are what make it a commons. They also mean:

- A record's identity IS the hash of its content. Change one byte and it
  becomes a different record.
- Therefore a record CANNOT BE EDITED. There is no update. There is only a new
  record.
- Therefore a record CANNOT BE REDACTED. Removing a designator changes the
  hash, which orphans every record that cited the old identity.
- Retraction (`retraction:`) withdraws a CLAIM. It does not ERASE a RECORD. The
  specification says so explicitly and correctly: "history never erased."
- Federation replicates by union. A record that has been published to peers
  cannot be recalled from them.

TAKEN TOGETHER: A PERSONAL IDENTIFIER WRITTEN INTO A PUBLISHED
`token_individual:` DESIGNATOR IS PERMANENT, GLOBAL, AND IRREVOCABLE.

It is not difficult to remove. It is IMPOSSIBLE to remove. This is not a
limitation of any implementation; it is a mathematical consequence of content
addressing, and no future version of this specification can repair it.

### The rules

- **R1. Tokens are local by default (Principle P2).** A conformant store MUST NOT publish
  token-tier records (`token_individual:`, `token_occurrence:`,
  `state_assertion:`, `token_causal_claim:`) to any federated peer or public
  endpoint unless explicitly instructed by its operator, per record or by
  explicit policy. The default configuration of every implementation MUST be
  non-publishing.
- **R2. No natural identifiers in published designators.** Where a token
  individual is published, its designator MUST NOT be a natural identifier: not
  a name, not a medical record number, not a national identifier, not an email
  address, not a device serial, not a street address. Implementations SHOULD
  use a salted hash, with the salt held locally and never published.
- **R3. The store must warn.** An implementation MUST emit a warning when a
  `token_individual:` with a non-hash-shaped designator is submitted for
  publication. It SHOULD refuse by default and require an explicit override.
- **R4. Special categories.** Token records concerning health, biometrics,
  genetics, sexual life, political opinion, religious belief, trade union
  membership, or criminal history are SPECIAL CATEGORY DATA under multiple
  legal regimes. Implementations serving such data MUST document their legal
  basis and MUST NOT publish such tokens to a public commons under any
  configuration.
- **R5. The commons accumulates laws, not diaries.** The intended flow is: a
  mind observes tokens locally, induces type-level claims from them, and
  contributes THE TYPES to the commons, citing its tokens only by hash in
  `evidenced_by` if at all. The commons is enriched by what was LEARNED, not by
  what was WATCHED. Implementers who find themselves publishing large volumes
  of tokens have misunderstood the architecture.
- **R6. Right to erasure is not satisfiable by retraction.** Implementers
  operating under GDPR Article 17 or equivalent MUST NOT represent retraction
  as erasure. It is not. The only way to satisfy an erasure request for
  published token data is to never have published it. This is why R1 exists.

### A note on why this section is normative and not advisory

The author of the 2.0.0 change order declined to propose the token tier on any
other terms.

A specification that gives the world an unforgetting, globally replicated,
cryptographically identified store of particular facts about particular people,
and does not say plainly that such a store cannot forget, has done something
irresponsible.

It can now be said plainly. It is said here.

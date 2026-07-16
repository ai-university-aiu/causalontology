/* causalontology.d.ts - hand-written TypeScript declarations for the
 * verified JavaScript binding (causalontology.js).
 *
 * These types describe the existing CommonJS implementation exactly as it
 * behaves at runtime; the JavaScript module remains the single source of
 * logic (it passes all 107 conformance vectors). The module is consumed as
 * `const co = require("./causalontology.js")` (or, from TypeScript,
 * `import co = require("./causalontology")`), so the declarations use the
 * CommonJS `export =` namespace pattern.
 *
 * Binary data note: at runtime every binary value (seeds, public keys,
 * signatures, canonical bytes) is a Node.js Buffer. Buffer extends
 * Uint8Array, so these declarations use Uint8Array (as the alias Bytes) to
 * stay dependency-free (no @types/node required to type-check); consumers
 * with @types/node can pass and receive Buffers unchanged.
 */

export = causalontology;

declare namespace causalontology {
  /* ------------------------------------------------------------------ *
   * Shared scalar and union types                                       *
   * ------------------------------------------------------------------ */

  /** Binary data. At runtime always a Node.js Buffer (Buffer extends Uint8Array). */
  type Bytes = Uint8Array;

  /** The seventeen whole-word Causalontology kinds (Principle P7). */
  type Kind =
    | "occurrent"
    | "causal_relation_object"
    | "continuant"
    | "realizable"
    | "stratum"
    | "bridge"
    | "port"
    | "conduit"
    | "quality"
    | "token_individual"
    | "token_occurrence"
    | "state_assertion"
    | "token_causal_claim"
    | "assertion"
    | "enrichment"
    | "retraction"
    | "succession";

  /** The thirteen content-object kinds (accepted by InMemoryStore.put). */
  type ContentKind =
    | "occurrent"
    | "causal_relation_object"
    | "continuant"
    | "realizable"
    | "stratum"
    | "bridge"
    | "port"
    | "conduit"
    | "quality"
    | "token_individual"
    | "token_occurrence"
    | "state_assertion"
    | "token_causal_claim";

  /** The four provenance-record kinds (accepted by InMemoryStore.putRecord). */
  type RecordKind = "assertion" | "enrichment" | "retraction" | "succession";

  /** The identifier scheme prefixes. Whole-word re-mint (P7): the scheme,
   * the type value, and the id prefix are one and the same string. */
  type IdPrefix = Kind;

  /** Causal modality of a Causal Relation Object (spec/semantics.md rule 6,
   * amended in 2.0.0 with `enabling`). */
  type Modality =
    | "necessary"
    | "sufficient"
    | "contributory"
    | "enabling"
    | "preventive";

  /** Temporal window units with fixed conversion constants (rule 4). */
  type TemporalUnit =
    | "instant"
    | "seconds"
    | "minutes"
    | "hours"
    | "days"
    | "weeks"
    | "months"
    | "years";

  /** How an assertion's source came to the claim; intervention is strongest.
   * Ordering strongest to weakest: intervention, observation, simulation,
   * testimony (2.0.0). */
  type EvidenceType =
    | "intervention"
    | "observation"
    | "simulation"
    | "derivation"
    | "human_hint"
    | "imported";

  /** The CLOSED occurrent category enumeration (occurrent.schema.json). */
  type OccurrentCategory = "action" | "event" | "process" | "state" | "state_change";

  /** The CLOSED continuant category enumeration (continuant.schema.json). */
  type ContinuantCategory =
    | "object"
    | "agent"
    | "place"
    | "substance"
    | "collection"
    | "information";

  /** The realizable-entity kind enumeration (realizable.schema.json). */
  type RealizableKind = "disposition" | "function" | "role";

  /** The seven enrichment fields (enrichment.schema.json; rule 12, with the
   * two occurrent-mereology forms added in 2.0.0). */
  type EnrichmentField =
    | "aliases"
    | "participants"
    | "subsumes"
    | "part_of"
    | "realized_in"
    | "occurrent_subsumes"
    | "occurrent_part_of";

  /* ------------------------------------------------------------------ *
   * Domain shapes (the eight kinds)                                     *
   * ------------------------------------------------------------------ */

  /** A bounded delay window between causes and effects (causal_relation_object.schema.json). */
  interface TemporalWindow {
    /** Minimum delay in `unit` (>= 0). */
    minimum_delay: number;
    /** Maximum delay in `unit` (>= 0; minimum_delay <= maximum_delay per semantics rule). */
    maximum_delay: number;
    /** The unit the window is expressed in. */
    unit: TemporalUnit;
  }

  /** An occurrent: something that happens (verb-first). */
  interface Occurrent {
    /** Content-addressed identifier "occurrent:<sha256 hex>"; assigned on put/identify. */
    id?: string;
    /** Kind tag; may be omitted where the kind is passed explicitly. */
    type?: "occurrent";
    /** Canonical lowercase snake_case label (press_button, light_on). */
    label: string;
    /** REQUIRED and CLOSED category. */
    category: OccurrentCategory;
  }

  /** A continuant: a participant that persists through occurrents. */
  interface Continuant {
    /** Content-addressed identifier "continuant:<sha256 hex>". */
    id?: string;
    /** Kind tag; may be omitted where the kind is passed explicitly. */
    type?: "continuant";
    /** Canonical lowercase snake_case label (bat_animal, bat_club). */
    label: string;
    /** REQUIRED and CLOSED category. */
    category: ContinuantCategory;
  }

  /** A Causal Relation Object (CRO): the causal claim itself. */
  interface CausalRelationObject {
    /** Content-addressed identifier "causal_relation_object:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "causal_relation_object";
    /** Occurrent identifiers ("occurrent:...") that jointly cause; at least one. */
    causes: string[];
    /** Occurrent identifiers ("occurrent:...") that jointly result; at least one. */
    effects: string[];
    /** Finer CRO identifiers whose composition realizes this one (acyclic). */
    mechanism?: string[];
    /** The bounded delay window between causes and effects. */
    temporal?: TemporalWindow;
    /** The causal modality of the claim. */
    modality?: Modality;
    /** Occurrent identifiers naming enabling conditions. */
    context?: string[];
    /** The more partial CRO this one enriches (lineage; acyclic). */
    refines?: string;
    /** TRUE asserts the relation crosses non-adjacent strata WITHOUT being
     * re-encoded at the intervening strata (2.0.0; identity-bearing). */
    skips?: boolean;
  }

  /** A realizable entity: a disposition, function, or role borne by a continuant. */
  interface Realizable {
    /** Content-addressed identifier "realizable:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "realizable";
    /** Which realizable this is. */
    kind: RealizableKind;
    /** The bearing continuant's identifier ("continuant:..."). */
    bearer: string;
  }

  /** A signed assertion: a source vouching for a content object. */
  interface Assertion {
    /** Content-addressed identifier "assertion:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "assertion";
    /** The content-object identifier the assertion is about. */
    about: string;
    /** The asserting key, "ed25519:<64 hex>". */
    source: string;
    /** How the source came to the claim. */
    evidence_type: EvidenceType;
    /** Free-text evidence reference. */
    evidence?: string;
    /** Causal-strength estimate in [0, 1]; meaningful only about a CRO. */
    strength?: number;
    /** The source's confidence in [0, 1]. */
    confidence: number;
    /** RFC 3339 date-time. */
    timestamp: string;
    /** Identifiers of the tokens/claims this assertion cites as evidence
     * (2.0.0; identity-bearing). */
    evidenced_by?: string[];
    /** Ed25519 signature (128 hex chars) over the canonical bytes. */
    signature?: string;
  }

  /** A language-tagged alias entry ({ lang, text }); lang is a BCP 47 tag. */
  interface AliasEntry {
    /** BCP 47 language tag. */
    lang: string;
    /** The alias text. */
    text: string;
  }

  /** An enrichment entry: an alias object for `aliases`, an identifier string otherwise. */
  type EnrichmentEntry = string | AliasEntry;

  /** A signed enrichment: adding to a content object's open fields. */
  interface Enrichment {
    /** Content-addressed identifier "enrichment:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "enrichment";
    /** The enriched content object ("occurrent:", "continuant:", or "realizable:..."; CROs are refined, not enriched). */
    about: string;
    /** Which open field the entry goes into (validity per rule 12). */
    field: EnrichmentField;
    /** The entry: an AliasEntry for `aliases`, an identifier string for the reference fields. */
    entry: EnrichmentEntry;
    /** The contributing key, "ed25519:<64 hex>". */
    source: string;
    /** RFC 3339 date-time. */
    timestamp: string;
    /** Ed25519 signature (128 hex chars). */
    signature?: string;
  }

  /** A signed retraction: withdrawing an assertion or enrichment. */
  interface Retraction {
    /** Content-addressed identifier "retraction:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "retraction";
    /** The assertion or enrichment identifier being withdrawn ("assertion:" or "enrichment:..."). */
    retracts: string;
    /** Must be the retracted record's source or in its succession lineage. */
    source: string;
    /** Optional free-text reason. */
    reason?: string;
    /** RFC 3339 date-time. */
    timestamp: string;
    /** Ed25519 signature (128 hex chars). */
    signature?: string;
  }

  /** A signed succession: a key handing over to a successor key. */
  interface Succession {
    /** Content-addressed identifier "succession:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "succession";
    /** The outgoing key, "ed25519:<64 hex>"; signs the record. */
    predecessor: string;
    /** The incoming key, "ed25519:<64 hex>". */
    successor: string;
    /** RFC 3339 date-time. */
    timestamp: string;
    /** Ed25519 signature by the PREDECESSOR key (128 hex chars). */
    signature?: string;
  }

  /** Any of the four content-object kinds. */
  type ContentObject = Occurrent | CausalRelationObject | Continuant | Realizable;

  /** Any of the four provenance-record kinds. */
  type ProvenanceRecord = Assertion | Enrichment | Retraction | Succession;

  /** Any object the canonicalization layer accepts. */
  type AnyObject = ContentObject | ProvenanceRecord | Record<string, unknown>;

  /* ------------------------------------------------------------------ *
   * Canonicalization and content-addressed identity                     *
   * ------------------------------------------------------------------ */

  /** The identity-bearing subset of an object: `type` plus the kind's identity fields. */
  interface IdentityBearing {
    /** The kind tag, always injected. */
    type: Kind;
    /** The identity-bearing fields copied from the object. */
    [field: string]: unknown;
  }

  /** Binding version string (tracks the specification version, pre-1.0). */
  const __version__: string;

  /** The identity-bearing field list per kind (spec/identity.md). */
  const IDENTITY_FIELDS: { readonly [K in Kind]: readonly string[] };

  /** Kind to identifier-scheme prefix ("occurrent" -> "occurrent", ...). */
  const PREFIX: { readonly [K in Kind]: IdPrefix };

  /** Identifier-scheme prefix back to kind ("occurrent" -> "occurrent", ...). */
  const KIND_OF_PREFIX: { readonly [P in IdPrefix]: Kind };

  /**
   * Infer an object's kind from its `type` field, `id` prefix, or shape.
   * Throws for a bare occurrent/continuant shape (they are indistinguishable;
   * pass the kind explicitly).
   */
  function inferKind(obj: AnyObject): Kind;

  /** The identity-bearing subset of an object, as [kind, subsetWithType]. */
  function identityBearing(obj: AnyObject, kind?: Kind): [Kind, IdentityBearing];

  /** The RFC 8785 (JCS) identity-bearing bytes of an object (a Buffer at runtime). */
  function canonicalize(obj: AnyObject, kind?: Kind): Bytes;

  /** The content-addressed identifier: prefix + ":" + lowercase SHA-256 hex. */
  function identify(obj: AnyObject, kind?: Kind): string;

  /* ------------------------------------------------------------------ *
   * Schema validation                                                   *
   * ------------------------------------------------------------------ */

  /**
   * Structural validity against the kind's JSON Schema in spec/schema/.
   * Returns the tuple [ok, reasons] exactly as the runtime does.
   */
  function validateSchema(obj: AnyObject, kind?: Kind): [ok: boolean, reasons: string[]];

  /* ------------------------------------------------------------------ *
   * Semantics (the locally checkable rules of spec/semantics.md)        *
   * ------------------------------------------------------------------ */

  /** Rule 4: the fixed unit-to-seconds conversion constants (average Gregorian). */
  const UNIT_SECONDS: { readonly [U in TemporalUnit]: number };

  /** The locally checkable semantic rules, as the tuple [ok, reasons]. */
  function validateSemantics(obj: AnyObject, kind?: Kind): [ok: boolean, reasons: string[]];

  /** Which optional CRO fields (mechanism/temporal/modality/context) are unspecified. */
  function isPartial(cro: CausalRelationObject): [partial: boolean, missing: string[]];

  /** Rule 4: is the elapsed time (seconds) inside the CRO's temporal window? */
  function admissible(cro: CausalRelationObject, elapsedSeconds: number): boolean;

  /** Rule 6: the formal conflict test between two CROs. */
  function conflicts(a: CausalRelationObject, b: CausalRelationObject): boolean;

  /** Rule 3: is child a valid refinement of parent? Returns [ok, reason]. */
  function refinementValid(
    child: CausalRelationObject,
    parent: CausalRelationObject,
  ): [ok: boolean, reason: string];

  /** The three verdicts of the rule 7 hierarchy-consistency check. */
  type HierarchyVerdict = "consistent" | "inconsistent" | "indeterminate";

  /** A Bridge: one coarse occurrent resolving to finer occurrents (2.0.0). */
  interface Bridge {
    /** Content-addressed identifier "bridge:<sha256 hex>". */
    id?: string;
    /** Kind tag. */
    type?: "bridge";
    /** The coarser occurrent's identifier ("occurrent:..."). */
    coarse: string;
    /** The finer occurrents' identifiers ("occurrent:..."). */
    fine: string[];
    /** The inter-stratal relation (constitutes, aggregates, realizes, ...). */
    relation: string;
  }

  /**
   * ALGORITHM B (amended Rule 7): is the parent's mechanism consistent with
   * its causes/effects, ACROSS STRATA via bridged reachability? `members`
   * maps CRO identifier to CRO object for the mechanism entries (a plain
   * object or a Map both work); `bridges` is the store's bridges (empty ->
   * 1.0.0 literal reachability).
   */
  function hierarchyConsistent(
    parent: CausalRelationObject,
    members:
      | ReadonlyMap<string, CausalRelationObject>
      | Readonly<Record<string, CausalRelationObject>>,
    bridges?: readonly Bridge[],
  ): HierarchyVerdict;

  /* ------------------------------------------------------------------ *
   * 2.0.0 normative algorithms (Section 12)                             *
   * ------------------------------------------------------------------ */

  /** The field-to-kind validity and entry shapes for each enrichment field. */
  const ENRICHMENT_FIELDS: {
    readonly [F in EnrichmentField]: readonly [readonly Kind[], string];
  };

  /** The stratal classification of a Causal Relation Object (Rule 15). */
  type Classification =
    | "intra_stratal"
    | "adjacent_stratal"
    | "skipping"
    | "mixed"
    | "unclassifiable"
    | "scheme_mismatch";

  /** ALGORITHM A: every finer occurrent an occurrent resolves to via Bridges. */
  function bridgeClosure(
    occurrentId: string,
    bridges: readonly Bridge[],
  ): Set<string>;

  /** ALGORITHM C (Rule 15): the stratal classification of a CRO. */
  function classifyCro(
    cro: CausalRelationObject,
    occMap: Readonly<Record<string, { stratum?: string }>>,
    stratumMap: Readonly<Record<string, { scheme: string; ordinal: number }>>,
  ): Classification;

  /** True iff causes or effects span more than one distinct stratum. */
  function endpointsMixed(
    cro: CausalRelationObject,
    occMap: Readonly<Record<string, { stratum?: string }>>,
  ): boolean;

  /** ALGORITHM D (Rule 16): the gaps a CRO surfaces for the skip decision. */
  function skipGaps(cro: CausalRelationObject, classification: string): string[];

  /** ALGORITHM E helper: normalize a delay to seconds by the fixed table. */
  function toSeconds(duration: number, unit: string): number;

  /** ALGORITHM E (Rule 20): does an observed delay fall within a window? */
  function delayWithinWindow(
    actualDelay: { duration: number; unit: string } | null | undefined,
    temporal: TemporalWindow | null | undefined,
  ): boolean;

  /** Rule 14: Bridge well-formedness. Returns [ok, reason]. */
  function bridgeWellformed(
    bridge: Bridge,
    occMap: Readonly<Record<string, { stratum?: string }>>,
    stratumMap: Readonly<Record<string, { scheme: string; ordinal: number }>>,
  ): [ok: boolean, reason: string];

  /** Rule 17: Conduit well-formedness. Returns [ok, reason]. */
  function conduitWellformed(
    conduit: {
      from: string;
      to: string;
      carries: string[];
      transform?: string;
    },
    portMap: Readonly<Record<string, {
      direction: string;
      accepts: string[];
    }>>,
    croMap?: Readonly<Record<string, { effects: string[] }>>,
  ): [ok: boolean, reason: string];

  /** Rule 19: the HARD gaps a state assertion surfaces against its quality. */
  function stateGaps(
    state: { value?: Record<string, unknown> },
    quality: { datatype?: string; unit?: string },
  ): string[];

  /** Rule 20: does the token claim mismatch its covering law? */
  function coveringLawMismatch(
    tcc: { causes: string[]; effects: string[] },
    tokenMap: Readonly<Record<string, { instantiates: string }>>,
    law: { causes: string[]; effects: string[] } | null | undefined,
  ): boolean;

  /** Rule 21: does any cause token start after any effect token? */
  function retrocausal(
    tcc: { causes: string[]; effects: string[] },
    tokenMap: Readonly<Record<string, { interval: { start: string } }>>,
  ): boolean;

  /** Rules 4 / 6.1: does a directed graph (node -> successors) have a cycle? */
  function hasCycle(
    edges:
      | ReadonlyMap<string, Iterable<string>>
      | Readonly<Record<string, Iterable<string>>>,
  ): boolean;

  /* ------------------------------------------------------------------ *
   * Signing (Ed25519, RFC 8032, over the canonical bytes)               *
   * ------------------------------------------------------------------ */

  /** [secret, "ed25519:<hex>"] from a 32-byte seed (the secret is the seed itself). */
  function keypairFromSeed(seed32: Bytes): [secret: Bytes, publicId: string];

  /** The record completed with its content-addressed `id` and hex `signature`. */
  function signRecord<T extends ProvenanceRecord>(
    record: T,
    secret: Bytes,
    kind?: RecordKind,
  ): T & { id: string; signature: string };

  /** True iff the record's signature verifies against its own key field. */
  function verifyRecord(record: ProvenanceRecord, kind?: RecordKind): boolean;

  /** The raw Ed25519 primitives (32-byte seeds/keys, 64-byte signatures). */
  const ed25519: {
    /** The 32-byte raw public key for a 32-byte secret key. */
    secretToPublic(seed: Bytes): Bytes;
    /** The 64-byte deterministic Ed25519 signature of msg under the secret key. */
    sign(seed: Bytes, msg: Bytes): Bytes;
    /** True iff signature is a valid Ed25519 signature of msg under publicRaw. */
    verify(publicRaw: Bytes, msg: Bytes, signature: Bytes): boolean;
  };

  /* ------------------------------------------------------------------ *
   * The in-memory conformant store                                      *
   * ------------------------------------------------------------------ */

  /** A content object as held by the store: identifier and kind tag are set. */
  type StoredContentObject = ContentObject & { id: string };

  /** A provenance record as held by the store: identifier is set. */
  type StoredRecord = ProvenanceRecord & { id: string };

  /** One contributor to a materialized enrichment entry. */
  interface EnrichmentContributor {
    /** The contributing key, "ed25519:<64 hex>". */
    source: string;
    /** The contribution's RFC 3339 timestamp. */
    timestamp: string;
  }

  /** One deduplicated materialized entry with every contributor that added it. */
  interface MaterializedEntry {
    /** The entry value (alias object or identifier string). */
    entry: EnrichmentEntry;
    /** Everyone who contributed this exact entry. */
    contributors: EnrichmentContributor[];
  }

  /** The materialized enrichment sets, one bucket list per enrichment field. */
  type MaterializedEnrichments = Partial<Record<EnrichmentField, MaterializedEntry[]>>;

  /** The `raw` view: the object alone, no materialized enrichments. */
  interface RawView {
    /** The stored content object. */
    object: StoredContentObject;
  }

  /** The `default`/`history` view: the object plus its materialized enrichments. */
  interface MaterializedView {
    /** The stored content object. */
    object: StoredContentObject;
    /** The materialized enrichment sets with contributors. */
    enrichments: MaterializedEnrichments;
  }

  /** A rule-6 or stigmergy gap reported by InMemoryStore.gaps(). */
  type Gap =
    /** A CRO lacking its temporal window or modality. */
    | { id: string; kind: "missing_field"; missing: string[] }
    /** A CRO with no mechanism decomposition yet. */
    | { id: string; kind: "empty_mechanism" }
    /** An enrichment excluded by the deterministic cycle-breaking view rule. */
    | { id: string; kind: "inconsistent_hierarchy"; note: string }
    /** A reference to an object absent from the store ("this page is wanted"). */
    | { id: string; kind: "dangling_reference"; ref: string }
    /** Two CROs satisfying the rule 6 formal conflict test. */
    | { kind: "conflict"; a: string; b: string };

  /** The gap discriminants. */
  type GapKind = Gap["kind"];

  /** An enforcing store refused a write; the reason is the error message. */
  class RejectedWrite extends Error {
    constructor(message: string);
  }

  /**
   * An in-memory conformant store (spec/store.md): immutable content objects
   * with idempotent put; signed, add-only provenance records; materialized
   * enrichment views with contributors; retraction handling; succession
   * lineage; the resolve minimum; the deterministic cycle-breaking view rule;
   * and the stigmergy gap read.
   */
  class InMemoryStore {
    /** Enforcing stores (the default) gate taxonomy writes that would cycle. */
    constructor(enforcing?: boolean);

    /** Whether the enforcement gate is active. */
    enforcing: boolean;

    /** Identifier to content object. */
    readonly objects: Map<string, StoredContentObject>;

    /** Identifier to verified provenance record. */
    readonly records: Map<string, StoredRecord>;

    /** Identifier to quarantined (unsigned/unverifiable) record. */
    readonly quarantine: Map<string, StoredRecord>;

    /**
     * Write a content object; idempotent; returns the identifier.
     * Throws RejectedWrite on schema or semantics failure.
     */
    put(obj: ContentObject, kind?: ContentKind): string;

    /**
     * Write a signed provenance record; add-only and idempotent; returns the
     * identifier. Throws RejectedWrite (and quarantines) when the signature
     * does not verify, and on semantics/retraction-lineage/cycle failures.
     */
    putRecord(record: ProvenanceRecord, kind?: RecordKind, force?: boolean): string;

    /** Simulate a decentralized replica merge (no enforcement gate). */
    forceMergeRecord(record: ProvenanceRecord, kind?: RecordKind): string;

    /** The succession chain closure containing key (includes key itself). */
    lineage(key: string): Set<string>;

    /**
     * The non-retracted assertions about an identifier; with includeRetracted,
     * retracted ones are included flagged `retracted: true`.
     */
    assertionsAbout(
      identifier: string,
      includeRetracted?: boolean,
    ): Array<Assertion & { retracted?: boolean }>;

    /** The enrichment records about an identifier (optionally retracted ones too). */
    enrichmentsAbout(identifier: string, includeRetracted?: boolean): Enrichment[];

    /** The `raw` view: the object alone; null when absent. */
    get(identifier: string, view: "raw"): RawView | null;
    /** The materialized view (default) or full-history view; null when absent. */
    get(identifier: string, view?: "default" | "history"): MaterializedView | null;

    /** The conformance minimum: exact label hits, then alias hits, then nothing. */
    resolve(text: string, lang?: string | null): string[];

    /** Every gap (the stigmergy read). */
    gaps(kind?: null): Gap[];
    /** Only the gaps of one kind. */
    gaps<K extends GapKind>(kind: K): Array<Extract<Gap, { kind: K }>>;
  }

  /* ------------------------------------------------------------------ *
   * Internals exposed for the conformance harness                       *
   * ------------------------------------------------------------------ */

  /** RFC 8785 (JCS) serialization of a JSON value; internal, exposed for the harness. */
  function _jcs(value: unknown): string;
}

/* type_check.ts - a compile-only exercise of the whole typed surface of
 * causalontology.d.ts. Nothing here is ever executed: `tsc -p .` with
 * noEmit checks that every exported function, constant, and store method
 * accepts correctly-typed arguments and returns the declared shapes, and
 * (via @ts-expect-error) that a wrong shape is rejected.
 */

import co = require("../causalontology");

/* ---------------------------------------------------------------- *
 * Domain objects of every kind                                      *
 * ---------------------------------------------------------------- */

const hex64 = "0".repeat(64);

const occ: co.Occurrent = { label: "press_button", category: "action" };

const cnt: co.Continuant = { label: "button", category: "object" };

const rlz: co.Realizable = { kind: "function", bearer: "continuant:" + hex64 };

const cro: co.CausalRelationObject = {
  causes: ["occurrent:" + hex64],
  effects: ["occurrent:" + hex64],
  mechanism: ["causal_relation_object:" + hex64],
  temporal: { minimum_delay: 0, maximum_delay: 5, unit: "seconds" },
  modality: "sufficient",
  context: ["occurrent:" + hex64],
  refines: "causal_relation_object:" + hex64,
};

const assertion: co.Assertion = {
  about: "causal_relation_object:" + hex64,
  source: "ed25519:" + hex64,
  evidence_type: "observation",
  evidence: "seen in the lab",
  strength: 0.9,
  confidence: 0.8,
  timestamp: "2026-07-13T00:00:00Z",
};

const aliasEnrichment: co.Enrichment = {
  about: "occurrent:" + hex64,
  field: "aliases",
  entry: { lang: "en", text: "push the button" },
  source: "ed25519:" + hex64,
  timestamp: "2026-07-13T00:00:00Z",
};

const refEnrichment: co.Enrichment = {
  about: "continuant:" + hex64,
  field: "subsumes",
  entry: "continuant:" + hex64,
  source: "ed25519:" + hex64,
  timestamp: "2026-07-13T00:00:00Z",
};

const retraction: co.Retraction = {
  retracts: "assertion:" + hex64,
  source: "ed25519:" + hex64,
  reason: "superseded",
  timestamp: "2026-07-13T00:00:00Z",
};

const succession: co.Succession = {
  predecessor: "ed25519:" + hex64,
  successor: "ed25519:" + hex64,
  timestamp: "2026-07-13T00:00:00Z",
};

/* One wrong shape must be rejected: a Modality typo. */
const badCro: co.CausalRelationObject = {
  causes: ["occurrent:" + hex64],
  effects: ["occurrent:" + hex64],
  // @ts-expect-error "sufficent" is not a Modality
  modality: "sufficent",
};

/* ---------------------------------------------------------------- *
 * Canonicalization and identity                                     *
 * ---------------------------------------------------------------- */

const inferred: co.Kind = co.inferKind(cro);

const pair: [co.Kind, co.IdentityBearing] = co.identityBearing(occ, "occurrent");
const ibType: co.Kind = pair[1].type;

const canonicalBytes: Uint8Array = co.canonicalize(occ, "occurrent");

const occId: string = co.identify(occ, "occurrent");
const croId: string = co.identify(cro);

const version: string = co.__version__;
const identityFields: readonly string[] = co.IDENTITY_FIELDS.assertion;
const croPrefix: co.IdPrefix = co.PREFIX.causal_relation_object;
const occKind: co.Kind = co.KIND_OF_PREFIX.occurrent;
const jcsText: string = co._jcs({ b: 1, a: [true, null, "x"] });

/* ---------------------------------------------------------------- *
 * Schema and semantics                                              *
 * ---------------------------------------------------------------- */

const [schemaOk, schemaReasons] = co.validateSchema(occ, "occurrent");
const schemaOkTyped: boolean = schemaOk;
const schemaReasonsTyped: string[] = schemaReasons;

const [semOk, semReasons] = co.validateSemantics(cro, "causal_relation_object");
const semOkTyped: boolean = semOk;
const semReasonsTyped: string[] = semReasons;

const [partial, missing] = co.isPartial(cro);
const partialTyped: boolean = partial;
const missingTyped: string[] = missing;

const admissibleNow: boolean = co.admissible(cro, 3.5);

const doTheyConflict: boolean = co.conflicts(cro, cro);

const [refOk, refReason] = co.refinementValid(cro, cro);
const refOkTyped: boolean = refOk;
const refReasonTyped: string = refReason;

const verdictFromMap: co.HierarchyVerdict = co.hierarchyConsistent(
  cro,
  new Map<string, co.CausalRelationObject>([["causal_relation_object:" + hex64, cro]]),
);
const verdictFromRecord: co.HierarchyVerdict = co.hierarchyConsistent(cro, {
  ["causal_relation_object:" + hex64]: cro,
});

const monthSeconds: number = co.UNIT_SECONDS.months;
const instantSeconds: number = co.UNIT_SECONDS.instant;

/* ---------------------------------------------------------------- *
 * Signing                                                           *
 * ---------------------------------------------------------------- */

declare const seed: Uint8Array; // at runtime: a 32-byte Buffer

const [secret, publicId] = co.keypairFromSeed(seed);
const secretTyped: Uint8Array = secret;
const publicIdTyped: string = publicId;

const signedAssertion = co.signRecord(assertion, secret);
const signedId: string = signedAssertion.id;
const signedSignature: string = signedAssertion.signature;
const signedConfidence: number = signedAssertion.confidence; // T passes through

const signedEnrichment = co.signRecord(aliasEnrichment, secret, "enrichment");
const signedRefEnrichment = co.signRecord(refEnrichment, secret);
const signedRetraction = co.signRecord(retraction, secret);
const signedSuccession = co.signRecord(succession, secret, "succession");

const verified: boolean = co.verifyRecord(signedAssertion);
const verifiedExplicit: boolean = co.verifyRecord(signedSuccession, "succession");

const rawPublic: Uint8Array = co.ed25519.secretToPublic(seed);
const rawSignature: Uint8Array = co.ed25519.sign(seed, canonicalBytes);
const rawVerified: boolean = co.ed25519.verify(rawPublic, canonicalBytes, rawSignature);

/* ---------------------------------------------------------------- *
 * The store                                                         *
 * ---------------------------------------------------------------- */

const store = new co.InMemoryStore();
const lenientStore = new co.InMemoryStore(false);
const enforcing: boolean = store.enforcing;

const putOccId: string = store.put(occ, "occurrent");
const putCntId: string = store.put(cnt, "continuant");
const putRlzId: string = store.put(rlz);
const putCroId: string = store.put(cro, "causal_relation_object");

const putRecordId: string = store.putRecord(signedAssertion);
const putForcedId: string = store.putRecord(signedEnrichment, "enrichment", true);
const mergedId: string = lenientStore.forceMergeRecord(signedRefEnrichment);

const objectsMember: Map<string, co.StoredContentObject> = store.objects;
const recordsMember: Map<string, co.StoredRecord> = store.records;
const quarantineMember: Map<string, co.StoredRecord> = store.quarantine;

/* get(): the materialized default view, the history view, and the raw view. */
const defaultView = store.get(putOccId);
if (defaultView !== null) {
  const viewObject: co.StoredContentObject = defaultView.object;
  const viewObjectId: string = viewObject.id;
  const enrichments: co.MaterializedEnrichments = defaultView.enrichments;
  const aliasBuckets = enrichments.aliases;
  if (aliasBuckets !== undefined) {
    for (const bucket of aliasBuckets) {
      const bucketEntry: co.EnrichmentEntry = bucket.entry;
      for (const contributor of bucket.contributors) {
        const contributorSource: string = contributor.source;
        const contributorTimestamp: string = contributor.timestamp;
      }
    }
  }
}

const historyView: co.MaterializedView | null = store.get(putOccId, "history");

const rawView: co.RawView | null = store.get(putOccId, "raw");
if (rawView !== null) {
  const rawObject: co.StoredContentObject = rawView.object;
}

/* Record queries. */
const assertions = store.assertionsAbout(putCroId, true);
for (const a of assertions) {
  const aboutTyped: string = a.about;
  const maybeRetracted: boolean | undefined = a.retracted;
}

const enrichmentRecords: co.Enrichment[] = store.enrichmentsAbout(putOccId);

const chain: Set<string> = store.lineage("ed25519:" + hex64);

const resolved: string[] = store.resolve("press button", "en");
const resolvedAnyLang: string[] = store.resolve("press button");

/* gaps(): the whole read and each narrowed kind. */
const allGaps: co.Gap[] = store.gaps();
const allGapsExplicit: co.Gap[] = store.gaps(null);

for (const gap of store.gaps("missing_field")) {
  const gapId: string = gap.id;
  const gapMissing: string[] = gap.missing;
}
for (const gap of store.gaps("empty_mechanism")) {
  const gapId: string = gap.id;
}
for (const gap of store.gaps("inconsistent_hierarchy")) {
  const gapNote: string = gap.note;
}
for (const gap of store.gaps("dangling_reference")) {
  const gapRef: string = gap.ref;
}
for (const gap of store.gaps("conflict")) {
  const gapA: string = gap.a;
  const gapB: string = gap.b;
}

/* RejectedWrite is a real Error subclass. */
const rejection: Error = new co.RejectedWrite("refused");
const rejectionInstance: co.RejectedWrite = rejection as co.RejectedWrite;
const rejectionMessage: string = rejectionInstance.message;

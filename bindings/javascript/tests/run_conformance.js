#!/usr/bin/env node
/* The Causalontology conformance runner for causalontology-js (spec 4.0.0).
 *
 * Runs every vector in conformance/vectors/ against the JavaScript binding.
 * An implementation is conformant if and only if it passes every vector;
 * this runner exits nonzero on any failure. Vectors V01-V107 are the
 * whole-word 2.0.0 baseline (Principle P7): V01-V38 re-frozen unaltered in
 * meaning, V39-V107 new. V108-V119 are the 3.0.0 additions; V120-V137 are
 * the 4.0.0 additions (attitude, predicted_occurrence, prediction_error).
 * It reproduces every assertion of the Python reference runner with the
 * same fixtures and the same expected results.
 *
 * Pre-freeze note (see conformance/README.md): the vectors carry symbolic
 * identifiers ("occurrent:press_button", "ed25519:alice"). This harness
 * normalizes them deterministically - symbolic object ids become
 * scheme:sha256(name), and symbolic key names become real Ed25519 keypairs
 * seeded from sha256("key:" + name).
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const co = require(path.join(__dirname, "..", "causalontology.js"));
const {
  identify, validateSchema, validateSemantics, isPartial, admissible,
  conflicts, refinementValid, hierarchyConsistent, bridgeClosure, classifyCro,
  endpointsMixed, skipGaps, toSeconds, delayWithinWindow, bridgeWellformed,
  conduitWellformed, stateGaps, coveringLawMismatch, retrocausal, hasCycle,
  seamWellformed, seamHome, predictionPairingMismatch,
  keypairFromSeed, signRecord, verifyRecord, InMemoryStore, RejectedWrite,
  ed25519, ENRICHMENT_FIELDS, _jcs,
} = co;

const ROOT = path.join(__dirname, "..", "..", "..");   // repository root
const VECDIR = path.join(ROOT, "conformance", "vectors");

// ---------------------------------------------------------------------------
// small assertion helpers
// ---------------------------------------------------------------------------
function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

function deq(a, b) {
  return _jcs(a) === _jcs(b);
}

function sha256hex(s) {
  return crypto.createHash("sha256").update(s, "utf-8").digest("hex");
}

// ---------------------------------------------------------------------------
// whole-word scheme normalization (Principle P7)
// ---------------------------------------------------------------------------
const SCHEMES = [
  "occurrent", "causal_relation_object", "continuant", "realizable",
  "assertion", "enrichment", "retraction", "succession",
  "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality",
  "token_individual", "token_occurrence", "state_assertion",
  "token_causal_claim",
  "attitude", "predicted_occurrence", "prediction_error",
];
const WHOLE_WORD = new Set([...SCHEMES, "ed25519"]);
const SYM_RE = new RegExp("^(" + SCHEMES.join("|") + "|ed25519):");
const KEYS = new Map();

/** A real, deterministic Ed25519 keypair for a symbolic key name. */
function key(name) {
  if (!KEYS.has(name)) {
    const seed = crypto.createHash("sha256")
      .update("key:" + name, "utf-8").digest();
    KEYS.set(name, keypairFromSeed(seed));
  }
  return KEYS.get(name);
}

/** Normalize one symbolic identifier to a well-formed one. */
function sym(s) {
  const idx = s.indexOf(":");
  const scheme = s.slice(0, idx);
  const name = s.slice(idx + 1);
  if (scheme === "ed25519") {
    if (/^[0-9a-f]{64}$/.test(name)) return s; // frozen key passes through
    return key(name)[1];
  }
  if (/^[0-9a-f]{64}$/.test(name)) return s;
  return scheme + ":" + sha256hex(name);
}

/** Recursively normalize symbolic identifiers and placeholders. */
function normalize(x) {
  if (typeof x === "string") {
    if (x === "<128 hex>") return "ab".repeat(64);
    if (SYM_RE.test(x)) return sym(x);
    return x;
  }
  if (Array.isArray(x)) return x.map(normalize);
  if (x !== null && typeof x === "object") {
    const out = {};
    for (const [k, v] of Object.entries(x)) out[k] = normalize(v);
    return out;
  }
  return x;
}

/** Load vector n's JSON file (for its structured inputs). */
function vec(n) {
  const nn = String(n).padStart(2, "0");
  const hits = fs.readdirSync(VECDIR)
    .filter((f) => f.startsWith("v" + nn + "_") && f.endsWith(".json"));
  assert(hits.length === 1, "vector " + n + " not found");
  return JSON.parse(fs.readFileSync(path.join(VECDIR, hits[0]), "utf-8"));
}

function vecName(n) {
  const nn = String(n).padStart(2, "0");
  const hit = fs.readdirSync(VECDIR)
    .find((f) => f.startsWith("v" + nn + "_") && f.endsWith(".json"));
  return hit.replace(/\.json$/, "");
}

const TS = (i) => "2026-07-13T0" + i + ":00:00Z";

/** Build, timestamp, and sign a provenance record. */
function signed(kind, body, who, tsI = 0) {
  const [secret, pub] = key(who);
  const rec = { ...body };
  rec.type = kind;
  if (!("timestamp" in rec)) rec.timestamp = TS(tsI);
  if (kind === "succession") {
    if (!("predecessor" in rec)) rec.predecessor = pub;
  } else {
    rec.source = pub;
  }
  return signRecord(rec, secret, kind);
}

/** A content object completed with its real content-addressed id. */
function mk(obj) {
  const o = { ...obj };
  o.id = identify(o);
  return o;
}

// builders --------------------------------------------------------------------
function stratum(label, scheme, ordinal, unit, governs) {
  const o = { type: "stratum", label, scheme, ordinal };
  if (unit) o.unit = unit;
  if (governs) o.governs = governs;
  return mk(o);
}

function occ(label, stratumId, category = "event") {
  const o = { type: "occurrent", label, category };
  if (stratumId) o.stratum = stratumId;
  return mk(o);
}

function cnt(label, category = "object") {
  return mk({ type: "continuant", label, category });
}

function cro(causes, effects, kw = {}) {
  const o = { type: "causal_relation_object", causes, effects };
  Object.assign(o, kw);
  return mk(o);
}

function bridge(coarse, fine, relation) {
  return mk({ type: "bridge", coarse, fine, relation });
}

function port(bearer, label, direction, accepts, realizable) {
  const o = { type: "port", bearer, label, direction, accepts };
  if (realizable) o.realizable = realizable;
  return mk(o);
}

function conduit(frm, to, carries, label = "conn", transform) {
  const o = { type: "conduit", label, from: frm, to, carries };
  if (transform) o.transform = transform;
  return mk(o);
}

function quality(label, datatype, unit, stratumId) {
  const o = { type: "quality", label, datatype };
  if (unit) o.unit = unit;
  if (stratumId) o.stratum = stratumId;
  return mk(o);
}

function individual(instantiates, designator, part_of) {
  const o = { type: "token_individual", instantiates };
  if (designator) o.designator = designator;
  if (part_of) o.part_of = part_of;
  return mk(o);
}

function token(instantiates, interval, participants, locus) {
  const o = { type: "token_occurrence", instantiates, interval };
  if (participants) o.participants = participants;
  if (locus) o.locus = locus;
  return mk(o);
}

function state(subject, qual, value, interval) {
  return mk({ type: "state_assertion", subject, quality: qual, value,
              interval });
}

function tcc(causes, effects, opts = {}) {
  const o = { type: "token_causal_claim", causes, effects };
  if (opts.covering_law) o.covering_law = opts.covering_law;
  if (opts.actual_delay) o.actual_delay = opts.actual_delay;
  if (opts.counterfactual !== undefined) o.counterfactual = opts.counterfactual;
  return mk(o);
}

// ---------------------------------------------------------------------------
// internal sanity checks (not conformance vectors)
// ---------------------------------------------------------------------------
function internalChecks() {
  // RFC 8032, TEST 1 known-answer
  const sk = Buffer.from(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "hex");
  const pk = ed25519.secretToPublic(sk);
  assert(pk.toString("hex") ===
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "RFC 8032 TEST 1 public key mismatch: " + pk.toString("hex"));
  const sig = ed25519.sign(sk, Buffer.from(""));
  assert(ed25519.verify(pk, Buffer.from(""), sig),
    "RFC 8032 TEST 1 signature did not verify");
  assert(!ed25519.verify(pk, Buffer.from("x"), sig),
    "RFC 8032 signature verified a different message");
  assert(sig.toString("hex") ===
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "RFC 8032 TEST 1 signature bytes mismatch");
  // JCS basics
  assert(_jcs({ b: 2, a: 1 }) === '{"a":1,"b":2}', "JCS key sort failed");
  assert(_jcs(1.0) === "1" && _jcs(6.0) === "6" && _jcs(0.7) === "0.7",
    "JCS number serialization failed");
  assert(toSeconds(1, "months") === 2629746, "months constant");
  assert(toSeconds(1, "years") === 31556952, "years constant");
}

// ---------------------------------------------------------------------------
// the 137 vectors
// ---------------------------------------------------------------------------
const vectors = {};

// V01 - V38: the whole-word re-freeze of the 1.0.0 suite -------------------

vectors.v01 = () => {
  const inp = normalize(vec(1).input);
  let [ok, why] = validateSchema(inp);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(inp);
  assert(ok, why.join("; "));
};

vectors.v02 = () => {
  const inp = normalize(vec(2).input);
  assert(validateSchema(inp)[0], "schema");
  assert(validateSemantics(inp)[0], "semantics");
  const [partial, missing] = isPartial(inp);
  assert(partial && deq(missing, vec(2).expect.missing),
    "missing = " + JSON.stringify(missing));
};

function schemaFails(n, mustMention) {
  const inp = normalize(vec(n).input);
  const [ok, why] = validateSchema(inp);
  assert(!ok, "expected schema-invalid");
  assert(why.some((w) => w.includes(mustMention)), why.join("; "));
}

vectors.v03 = () => schemaFails(3, "effects");
vectors.v04 = () => schemaFails(4, "causes");
vectors.v05 = () => schemaFails(5, "modality");
vectors.v06 = () => schemaFails(6, "colour");
vectors.v07 = () => schemaFails(7, "causes");

vectors.v08 = () => {
  const [ok, why] = validateSchema(normalize(vec(8).input));
  assert(ok, why.join("; "));
};

vectors.v09 = () => schemaFails(9, "label");
vectors.v10 = () => schemaFails(10, "category");

vectors.v11 = () => {
  const [ok, why] = validateSchema(normalize(vec(11).input));
  assert(ok, why.join("; "));
};

vectors.v12 = () => schemaFails(12, "confidence");

vectors.v13 = () => {
  const inp = normalize(vec(13).input);
  let [ok, why] = validateSchema(inp);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(inp);
  assert(ok, why.join("; "));
};

function semanticsFails(n, mustMention) {
  const inp = normalize(vec(n).input);
  const [ok, why] = validateSemantics(inp);
  assert(!ok, "expected semantically-invalid");
  assert(why.some((w) => w.includes(mustMention)), why.join("; "));
}

vectors.v14 = () => {
  const inp = normalize(vec(14).input);
  assert(validateSchema(inp)[0], "schema should pass");
  semanticsFails(14, "minimum_delay");
};

vectors.v15 = () => semanticsFails(15, "acyclic");
vectors.v16 = () => semanticsFails(16, "acyclic");

vectors.v17 = () => {
  const v = vec(17);
  const parent = normalize(v.given.parent);
  const child = normalize(v.input);
  const [ok, reason] = refinementValid(child, parent);
  assert(!ok && reason.includes("rival"), reason);
};

vectors.v18 = () => semanticsFails(18, "not a legal field");
vectors.v19 = () => semanticsFails(19, "language-tagged");

vectors.v20 = () => {
  const dog = sym("continuant:dog"), mam = sym("continuant:mammal"),
        ani = sym("continuant:animal");
  const enrich = (about, entry, i) =>
    signed("enrichment", { about, field: "subsumes", entry }, "taxo", i);
  const s = new InMemoryStore(true);
  s.putRecord(enrich(dog, mam, 1));
  s.putRecord(enrich(mam, ani, 2));
  let threw = false;
  try {
    s.putRecord(enrich(ani, dog, 3));
  } catch (e) {
    assert(e instanceof RejectedWrite && e.message.includes("cycle"),
      String(e));
    threw = true;
  }
  assert(threw, "enforcing store accepted a cycle");
  const s2 = new InMemoryStore(true);
  s2.putRecord(enrich(dog, mam, 1));
  s2.putRecord(enrich(mam, ani, 2));
  const bad = enrich(ani, dog, 3);
  s2.forceMergeRecord(bad);
  const [, excluded] = s2._activeTaxonomyEdges("subsumes");
  assert(excluded.length === 1 && excluded[0].id === bad.id,
    "wrong record excluded");
  assert(s2.gaps("inconsistent_hierarchy").some((g) => g.id === bad.id),
    "no repair gap emitted");
};

function adm(n) {
  const g = vec(n).given;
  const c = { causes: [sym("occurrent:c")], effects: [sym("occurrent:e")],
              temporal: g.temporal };
  return admissible(c, g.elapsed_seconds);
}

vectors.v21 = () => assert(adm(21) === true, "expected admissible");
vectors.v22 = () => assert(adm(22) === false, "expected inadmissible");
vectors.v23 = () => assert(adm(23) === true, "expected admissible");

vectors.v24 = () => {
  const v = vec(24);
  assert(identify(normalize(v.inputA)) === identify(normalize(v.inputB)),
    "key order changed identity");
};

vectors.v25 = () => {
  const v = vec(25);
  assert(identify(normalize(v.inputA)) === identify(normalize(v.inputB)),
    "number formatting changed identity");
};

vectors.v26 = () => {
  const s = new InMemoryStore();
  const obj = { type: "occurrent", label: "press_button", category: "action" };
  assert(s.put({ ...obj }) === s.put({ ...obj }) && s.objects.size === 1,
    "put not idempotent");
};

vectors.v27 = () => {
  const s = new InMemoryStore();
  const occid = s.put({ type: "occurrent", label: "press_button",
                        category: "action" });
  const entry = { lang: "en", text: "press the button" };
  const r1 = signed("enrichment", { about: occid, field: "aliases", entry },
    "alice", 1);
  const r2 = signed("enrichment", { about: occid, field: "aliases", entry },
    "bob", 2);
  assert(s.putRecord(r1) !== s.putRecord(r2), "expected two records");
  const view = s.get(occid).enrichments.aliases;
  assert(view.length === 1 && view[0].contributors.length === 2,
    "expected one entry with two contributors");
};

vectors.v28 = () => {
  const s = new InMemoryStore();
  const claim = { type: "causal_relation_object", causes: [sym("occurrent:A")],
                  effects: [sym("occurrent:B")], modality: "sufficient" };
  const i1 = s.put({ ...claim });
  const i2 = s.put({ ...claim });
  assert(i1 === i2 && s.objects.size === 1, "expected one object");
  for (const [who, ts] of [["lab1", 1], ["lab2", 2]]) {
    s.putRecord(signed("assertion",
      { about: i1, evidence_type: "observation", strength: 0.8,
        confidence: 0.8 }, who, ts));
  }
  assert(s.assertionsAbout(i1).length === 2, "expected two assertions");
};

vectors.v29 = () => {
  const rec = signed("assertion",
    { about: sym("causal_relation_object:demo"), evidence_type: "intervention",
      strength: 0.7, confidence: 0.9 }, "signer");
  assert(verifyRecord(rec) === true, "valid signature did not verify");
};

vectors.v30 = () => {
  const rec = signed("assertion",
    { about: sym("causal_relation_object:demo"), evidence_type: "intervention",
      strength: 0.7, confidence: 0.9 }, "signer");
  assert(verifyRecord({ ...rec, confidence: 0.1 }) === false,
    "tampered record verified");
};

vectors.v31 = () => {
  const s = new InMemoryStore();
  const x = s.put({ type: "causal_relation_object", causes: [sym("occurrent:A")],
                    effects: [sym("occurrent:B")] });
  const a = signed("assertion",
    { about: x, evidence_type: "observation", confidence: 0.8 }, "lab1", 1);
  s.putRecord(a);
  s.putRecord(signed("retraction", { retracts: a.id }, "lab1", 2));
  assert(s.assertionsAbout(x).length === 0, "retracted assertion visible");
  const hist = s.assertionsAbout(x, true);
  assert(hist.length === 1 && hist[0].retracted === true, "history wrong");
  let threw = false;
  try {
    s.putRecord(signed("retraction", { retracts: a.id }, "mallory", 3));
  } catch (e) {
    assert(e instanceof RejectedWrite, String(e));
    threw = true;
  }
  assert(threw, "foreign retraction accepted");
};

vectors.v32 = () => {
  const s = new InMemoryStore();
  const occid = s.put({ type: "occurrent", label: "press_button",
                        category: "action" });
  const e = signed("enrichment",
    { about: occid, field: "aliases", entry: { lang: "ja", text: "botan" } },
    "bob", 1);
  s.putRecord(e);
  assert((s.get(occid).enrichments.aliases || []).length === 1,
    "enrichment missing");
  s.putRecord(signed("retraction", { retracts: e.id }, "bob", 2));
  assert((s.get(occid).enrichments.aliases || []).length === 0,
    "retracted enrichment still visible");
  assert((s.get(occid, "history").enrichments.aliases || []).length === 1,
    "history view lost the enrichment");
};

vectors.v33 = () => {
  const s = new InMemoryStore();
  const k1 = key("K1")[1];
  const k2 = key("K2")[1];
  const a = signed("assertion",
    { about: sym("causal_relation_object:claim"), evidence_type: "observation",
      confidence: 0.9 }, "K1", 1);
  s.putRecord(a);
  s.putRecord(signed("succession", { successor: k2 }, "K1", 2));
  assert(s.lineage(k2).has(k1) && s.lineage(k1).has(k2), "lineage broken");
  s.putRecord(signed("retraction", { retracts: a.id }, "K2", 3));
  assert(s.assertionsAbout(sym("causal_relation_object:claim")).length === 0,
    "successor retraction not honored");
};

vectors.v34 = () => {
  const g = normalize(vec(34).given);
  assert(conflicts(g.A, g.B) === true, "expected a conflict");
};

vectors.v35 = () => {
  const g = normalize(vec(35).given);
  assert(conflicts(g.A, g.B) === false, "expected no conflict");
};

vectors.v36 = () => {
  const A = sym("occurrent:A"), B = sym("occurrent:B"),
        C = sym("occurrent:C"), D = sym("occurrent:D");
  const m1 = { id: sym("causal_relation_object:m1"), causes: [A], effects: [B] };
  const m2 = { id: sym("causal_relation_object:m2"), causes: [B], effects: [C] };
  const m3 = { id: sym("causal_relation_object:m3"), causes: [D], effects: [C] };
  const P = { causes: [A], effects: [C], mechanism: [m1.id, m2.id] };
  assert(hierarchyConsistent(P, { [m1.id]: m1, [m2.id]: m2 }) === "consistent",
    "chain should be consistent");
  const P2 = { ...P, mechanism: [m1.id, m3.id] };
  assert(hierarchyConsistent(P2, { [m1.id]: m1, [m3.id]: m3 }) === "inconsistent",
    "broken chain should be inconsistent");
  assert(hierarchyConsistent(P, { [m1.id]: m1 }) === "indeterminate",
    "missing member should be indeterminate");
};

vectors.v37 = () => {
  const s = new InMemoryStore();
  const occid = s.put({ type: "occurrent", label: "press_button",
                        category: "action" });
  s.putRecord(signed("enrichment",
    { about: occid, field: "aliases",
      entry: { lang: "en", text: "Press the Button" } }, "alice", 1));
  assert(deq(s.resolve("Press  The   Button", "en"), [occid]),
    "alias resolve failed");
  assert(s.resolve("press_button", "en")[0] === occid, "label resolve failed");
};

vectors.v38 = () => {
  const s = new InMemoryStore();
  const P = s.put({ type: "causal_relation_object", causes: [sym("occurrent:A")],
                    effects: [sym("occurrent:B")] });
  assert(s.gaps("missing_field").map((g) => g.id).includes(P),
    "the bare CRO must be a gap");
  const R = s.put({ type: "causal_relation_object", causes: [sym("occurrent:A")],
                    effects: [sym("occurrent:B")],
                    temporal: { minimum_delay: 0, maximum_delay: 1,
                                unit: "seconds" },
                    modality: "sufficient", refines: P });
  const gaps = s.gaps("missing_field").map((g) => g.id);
  assert(!gaps.includes(P) && !gaps.includes(R), "the gap did not close");
};

// V39 - V107: the 2.0.0 additions ------------------------------------------

function neuro() {
  const labels = { 4: "macromolecular", 5: "subcellular", 6: "cellular",
                   7: "synaptic", 9: "region", 14: "community_and_society" };
  const out = {};
  for (const o of Object.keys(labels)) {
    out[o] = stratum(labels[o], "neuroendocrine", Number(o));
  }
  return out;
}

vectors.v39 = () => {
  const st = stratum("cellular", "neuroendocrine", 6, "cell", ["cell_biology"]);
  const [ok, why] = validateSchema(st);
  assert(ok, why.join("; "));
};

vectors.v40 = () => {
  const bad = mk({ type: "stratum", label: "cellular", ordinal: 6 });
  const [ok, why] = validateSchema(bad, "stratum");
  assert(!ok && why.some((w) => w.includes("scheme")), why.join("; "));
};

vectors.v41 = () => {
  const a = stratum("cellular", "neuroendocrine", 6);
  const b = stratum("neuronal", "neuroendocrine", 6);
  for (const x of [a, b]) {
    const [ok, why] = validateSchema(x);
    assert(ok, why.join("; "));
  }
  assert(a.id !== b.id, "distinct strata must differ");
};

vectors.v42 = () => {
  const s = neuro();
  const s4p = stratum("molecular", "physics", 4);
  const c = occ("chronic_social_subordination", s[14].id);
  const e = occ("gene_expression", s4p.id);
  const smap = { [s[14].id]: s[14], [s4p.id]: s4p };
  const omap = { [c.id]: c, [e.id]: e };
  const P = cro([c.id], [e.id]);
  assert(classifyCro(P, omap, smap) === "scheme_mismatch", "expected mismatch");
};

vectors.v43 = () => {
  for (const x of [stratum("macromolecular", "neuroendocrine", 4),
                   stratum("region", "neuroendocrine", 9)]) {
    const [ok, why] = validateSchema(x);
    assert(ok, why.join("; "));
  }
};

vectors.v44 = () => {
  const st = stratum("cellular", "neuroendocrine", 6);
  const o = occ("neuron_fires", st.id);
  let [ok, why] = validateSchema(o);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(o);
  assert(ok, why.join("; "));
};

vectors.v45 = () => {
  const o = occ("press_button");
  const [ok, why] = validateSchema(o);
  assert(ok, why.join("; "));
  const e = occ("light_on");
  const P = cro([o.id], [e.id]);
  assert(classifyCro(P, { [o.id]: o, [e.id]: e }, {}) === "unclassifiable",
    "expected unclassifiable");
};

vectors.v46 = () => {
  const s = neuro();
  const a = occ("depolarization", s[5].id);
  const b = occ("depolarization", s[6].id);
  assert(a.id !== b.id, "same label, different stratum must differ");
};

function bridgeFixture(relation) {
  const s = neuro();
  const coarse = occ("action_potential_fires", s[6].id);
  const fine = [occ("sodium_channels_open", s[4].id),
                occ("sodium_influx", s[4].id)];
  const b = bridge(coarse.id, fine.map((f) => f.id), relation);
  const omap = { [coarse.id]: coarse };
  for (const f of fine) omap[f.id] = f;
  const smap = { [s[4].id]: s[4], [s[6].id]: s[6] };
  return [b, omap, smap];
}

function validBridge(relation) {
  const [b, omap, smap] = bridgeFixture(relation);
  let [ok, why] = validateSchema(b);
  assert(ok, why.join("; "));
  [ok, why] = bridgeWellformed(b, omap, smap);
  assert(ok, why);
}

vectors.v47 = () => validBridge("constitutes");
vectors.v48 = () => validBridge("aggregates");
vectors.v49 = () => validBridge("realizes");
vectors.v50 = () => validBridge("supervenes_on");

vectors.v51 = () => {
  const s = neuro();
  const coarse = occ("x_coarse", s[4].id);
  const fine = occ("x_fine", s[6].id);
  const b = bridge(coarse.id, [fine.id], "constitutes");
  const omap = { [coarse.id]: coarse, [fine.id]: fine };
  const smap = { [s[4].id]: s[4], [s[6].id]: s[6] };
  assert(!bridgeWellformed(b, omap, smap)[0], "coarse not > fine must fail");
};

vectors.v52 = () => {
  const s = neuro();
  const coarse = occ("c", s[6].id);
  const f1 = occ("f1", s[4].id), f2 = occ("f2", s[5].id);
  const b = bridge(coarse.id, [f1.id, f2.id], "constitutes");
  const omap = { [coarse.id]: coarse, [f1.id]: f1, [f2.id]: f2 };
  const smap = { [s[4].id]: s[4], [s[5].id]: s[5], [s[6].id]: s[6] };
  assert(!bridgeWellformed(b, omap, smap)[0], "fine spanning strata must fail");
};

vectors.v53 = () => {
  const x = sym("occurrent:x"), y = sym("occurrent:y");
  const b1 = bridge(x, [y], "constitutes");
  const b2 = bridge(y, [x], "constitutes");
  const edges = {};
  for (const b of [b1, b2]) {
    for (const f of b.fine) {
      if (!(f in edges)) edges[f] = [];
      edges[f].push(b.coarse);
    }
  }
  assert(hasCycle(edges) === true, "expected a cycle");
};

vectors.v54 = () => {
  const a = stratum("cellular", "neuroendocrine", 6);
  const b = stratum("molecular", "physics", 4);
  const coarse = occ("c", a.id), fine = occ("f", b.id);
  const br = bridge(coarse.id, [fine.id], "constitutes");
  const omap = { [coarse.id]: coarse, [fine.id]: fine };
  const smap = { [a.id]: a, [b.id]: b };
  assert(!bridgeWellformed(br, omap, smap)[0], "scheme mismatch must fail");
};

vectors.v55 = () => {
  const s = neuro();
  const coarse = occ("decision_made", s[6].id);
  const f1 = occ("cascade_a", s[4].id), f2 = occ("cascade_b", s[4].id);
  const b1 = bridge(coarse.id, [f1.id], "realizes");
  const b2 = bridge(coarse.id, [f2.id], "realizes");
  assert(b1.id !== b2.id, "distinct bridges must differ");
  for (const b of [b1, b2]) {
    const [ok, why] = validateSchema(b);
    assert(ok, why.join("; "));
  }
};

function reachFixture() {
  const s = neuro();
  const ap = occ("action_potential_fires", s[6].id);
  const nt = occ("neurotransmitter_released", s[6].id);
  const fa = occ("calcium_enters", s[4].id);
  const fb = occ("vesicle_fuses", s[4].id);
  const m1 = cro([fa.id], [fb.id]);
  const P = cro([ap.id], [nt.id], { mechanism: [m1.id] });
  const bridges = [bridge(ap.id, [fa.id], "constitutes"),
                   bridge(nt.id, [fb.id], "constitutes")];
  return [P, { [m1.id]: m1 }, bridges];
}

vectors.v56 = () => {
  const [P, members, bridges] = reachFixture();
  assert(hierarchyConsistent(P, members, bridges) === "consistent",
    "bridged reachability should be consistent");
};

vectors.v57 = () => {
  const [P, members] = reachFixture();
  assert(hierarchyConsistent(P, members, []) === "inconsistent",
    "literal reachability should be inconsistent");
};

vectors.v58 = () => {
  const [P, members, bridges] = reachFixture();
  const literal = hierarchyConsistent(P, members, []);
  const bridged = hierarchyConsistent(P, members, bridges);
  assert(literal !== "consistent" && bridged === "consistent",
    "literal must differ from bridged");
};

function classify(causeOrd, effectOrd) {
  const s = neuro();
  const c = occ("c", s[causeOrd].id), e = occ("e", s[effectOrd].id);
  const smap = { [s[causeOrd].id]: s[causeOrd], [s[effectOrd].id]: s[effectOrd] };
  const omap = { [c.id]: c, [e.id]: e };
  return classifyCro(cro([c.id], [e.id]), omap, smap);
}

vectors.v59 = () => assert(classify(6, 6) === "intra_stratal", "intra");
vectors.v60 = () => assert(classify(6, 5) === "adjacent_stratal", "adjacent");
vectors.v61 = () => assert(classify(14, 4) === "skipping", "skipping");

function skipFixture(causeOrd, effectOrd, kw = {}) {
  const s = neuro();
  const c = occ("c", s[causeOrd].id), e = occ("e", s[effectOrd].id);
  const smap = { [s[causeOrd].id]: s[causeOrd], [s[effectOrd].id]: s[effectOrd] };
  const omap = { [c.id]: c, [e.id]: e };
  const P = cro([c.id], [e.id], kw);
  return [P, classifyCro(P, omap, smap)];
}

vectors.v62 = () => {
  const [P, cls] = skipFixture(14, 4);
  assert(deq(skipGaps(P, cls), ["incomplete_mechanism"]),
    "absent skips must surface incomplete_mechanism");
};

vectors.v63 = () => {
  const [P, cls] = skipFixture(14, 4, { skips: true });
  assert(deq(skipGaps(P, cls), []), "skips:true must surface nothing");
};

vectors.v64 = () => {
  const [P, cls] = skipFixture(14, 4,
    { skips: true, mechanism: [sym("causal_relation_object:m")] });
  assert(deq(skipGaps(P, cls), ["contradictory_skip"]), "contradictory_skip");
  const [ok, why] = validateSemantics(P);
  assert(!ok && why.some((w) => w.includes("contradictory_skip")),
    "hard semantics failure expected");
};

vectors.v65 = () => {
  const [P, cls] = skipFixture(6, 6, { skips: true });
  assert(deq(skipGaps(P, cls), ["vacuous_skip"]), "vacuous_skip");
};

vectors.v66 = () => {
  const s = neuro();
  const c = occ("c", s[14].id), e = occ("e", s[4].id);
  const absent = cro([c.id], [e.id]);
  const false_ = cro([c.id], [e.id], { skips: false });
  assert(absent.id !== false_.id, "skips absent vs false must differ");
};

vectors.v67 = () => {
  const s = neuro();
  const c1 = occ("c1", s[4].id), c2 = occ("c2", s[6].id);
  const e = occ("e", s[6].id);
  const P = cro([c1.id, c2.id], [e.id]);
  assert(endpointsMixed(P, { [c1.id]: c1, [c2.id]: c2, [e.id]: e }) === true,
    "mixed endpoints expected");
};

vectors.v68 = () => {
  const P = cro([sym("occurrent:a")], [sym("occurrent:b")],
    { modality: "enabling" });
  const [ok, why] = validateSchema(P);
  assert(ok, why.join("; "));
};

vectors.v69 = () => {
  const a = { causes: [sym("occurrent:a")], effects: [sym("occurrent:b")],
              modality: "enabling" };
  const b = { causes: [sym("occurrent:a")], effects: [sym("occurrent:b")],
              modality: "sufficient" };
  assert(conflicts(a, b) === false, "enabling and sufficient do not conflict");
};

vectors.v70 = () => {
  const a = { causes: [sym("occurrent:a")], effects: [sym("occurrent:b")],
              modality: "enabling" };
  const b = { causes: [sym("occurrent:a")], effects: [sym("occurrent:b")],
              modality: "preventive" };
  assert(conflicts(a, b) === true, "enabling and preventive conflict");
};

vectors.v71 = () => {
  const b = cnt("hippocampus");
  const p = port(b.id, "perforant_path", "in", [sym("occurrent:signal")]);
  const [ok, why] = validateSchema(p);
  assert(ok, why.join("; "));
};

vectors.v72 = () => {
  const b = cnt("hippocampus").id;
  const x = sym("occurrent:signal");
  assert(port(b, "perforant_path", "in", [x]).id
    !== port(b, "fornix", "in", [x]).id, "distinct ports must differ");
};

function conduitFixture(opts = {}) {
  const { transform = false, badCarry = false, inFrom = false } = opts;
  const x = sym("occurrent:motor_command"), y = sym("occurrent:error_signal");
  const z = sym("occurrent:unrelated");
  const m1 = cnt("motor_cortex").id, m2 = cnt("spinal_neuron").id;
  const frm = port(m1, "out_port", inFrom ? "in" : "out", [x]);
  const to = port(m2, "in_port", "in", transform ? [y] : [x]);
  const carries = badCarry ? [z] : [x];
  let xform = null;
  const croMap = {};
  if (transform) {
    const law = cro([x], [y]);
    croMap[law.id] = law;
    xform = law.id;
  }
  const c = conduit(frm.id, to.id, carries, "conn", xform);
  return [c, { [frm.id]: frm, [to.id]: to }, croMap];
}

vectors.v73 = () => {
  const [c, pmap] = conduitFixture();
  let [ok, why] = validateSchema(c);
  assert(ok, why.join("; "));
  [ok, why] = conduitWellformed(c, pmap);
  assert(ok, why);
};

vectors.v74 = () => {
  const [c, pmap, cmap] = conduitFixture({ transform: true });
  let [ok, why] = validateSchema(c);
  assert(ok, why.join("; "));
  [ok, why] = conduitWellformed(c, pmap, cmap);
  assert(ok, why);
};

vectors.v75 = () => {
  const [c, pmap] = conduitFixture({ badCarry: true });
  assert(!conduitWellformed(c, pmap)[0], "bad carry must fail");
};

vectors.v76 = () => {
  const [c, pmap] = conduitFixture({ inFrom: true });
  assert(!conduitWellformed(c, pmap)[0], "in-direction from must fail");
};

vectors.v77 = () => {
  const [c, pmap, cmap] = conduitFixture({ transform: true });
  const [ok, why] = conduitWellformed(c, pmap, cmap);
  assert(ok, why);
  const law = Object.values(cmap)[0];
  assert(!c.carries.includes(law.effects[0]),
    "transform effect need not be carried");
};

function rlz(bearer, kind, label) {
  const o = { type: "realizable", kind, bearer };
  if (label) o.label = label;
  return mk(o);
}

vectors.v78 = () => {
  const b = cnt("hippocampus").id;
  assert(rlz(b, "disposition", "long_term_potentiation").id
    !== rlz(b, "disposition", "pattern_separation").id,
    "distinct realizables must differ");
};

vectors.v79 = () => {
  const b = cnt("hippocampus").id;
  const u1 = rlz(b, "disposition"), u2 = rlz(b, "disposition");
  const [ok, why] = validateSchema(u1);
  assert(ok, why.join("; "));
  assert(u1.id === u2.id, "identical unlabeled realizables coincide");
  assert(rlz(b, "disposition", "some_function").id !== u1.id,
    "label is identity-bearing");
};

vectors.v80 = () => {
  const parent = occ("fires"), child = occ("fires_action_potential");
  const e = { type: "enrichment", about: child.id,
              field: "occurrent_subsumes", entry: parent.id };
  const [ok, why] = validateSemantics(e);
  assert(ok, why.join("; "));
};

vectors.v81 = () => {
  const a = sym("occurrent:a"), b = sym("occurrent:b");
  assert(hasCycle({ [a]: [b], [b]: [a] }) === true, "expected a cycle");
};

vectors.v82 = () => {
  const whole = occ("eat"), part = occ("chew");
  const e = { type: "enrichment", about: part.id,
              field: "occurrent_part_of", entry: whole.id };
  const [ok, why] = validateSemantics(e);
  assert(ok, why.join("; "));
};

vectors.v83 = () => {
  const [legalKinds, shape] = ENRICHMENT_FIELDS.occurrent_part_of;
  assert(shape === "occurrent" && deq(legalKinds, ["occurrent"]),
    "occurrent_part_of spec");
  const s = new InMemoryStore();
  s.put(occ("eat"));
  s.put(occ("chew"));
  assert(![...s.objects.values()].some(
    (o) => o.type === "causal_relation_object"),
    "no spurious causal relation objects");
};

vectors.v84 = () => {
  const s = neuro();
  const a = occ("run", s[9].id), b = occ("sprint", s[6].id);
  assert(a.stratum !== b.stratum, "distinct strata references");
};

vectors.v85 = () => {
  const c = cnt("human_patient");
  const ti = individual(c.id, "salted_hash_abc123");
  const [ok, why] = validateSchema(ti);
  assert(ok, why.join("; "));
};

vectors.v86 = () => {
  const bad = mk({ type: "token_individual", designator: "x" });
  const [ok, why] = validateSchema(bad, "token_individual");
  assert(!ok && why.some((w) => w.includes("instantiates")), why.join("; "));
};

vectors.v87 = () => {
  const c = cnt("human_patient").id;
  assert(individual(c, "hash_a").id !== individual(c, "hash_b").id,
    "designator is identity-bearing");
};

vectors.v88 = () => {
  const o = occ("bilateral_hippocampal_resection");
  const t = token(o.id, { start: "1953-08-25T00:00:00Z",
                          end: "1953-08-25T00:00:00Z" });
  const [ok, why] = validateSchema(t);
  assert(ok, why.join("; "));
};

vectors.v89 = () => {
  const o = occ("amnesia_onset").id;
  const bounded = token(o, { start: "1953-08-25T00:00:00Z",
                             end: "1953-08-26T00:00:00Z" });
  const instantaneous = token(o, { start: "1953-08-25T00:00:00Z" });
  const ongoing = token(o, { start: "1953-08-25T00:00:00Z", open: true });
  assert(new Set([bounded.id, instantaneous.id, ongoing.id]).size === 3,
    "three distinct intervals");
};

vectors.v90 = () => {
  const o = occ("resection").id, c = cnt("human_patient").id;
  const patient = individual(c, "p").id;
  const surgeon = individual(c, "s").id;
  const t = token(o, { start: "1953-08-25T00:00:00Z" },
    [{ role: "patient", filler: patient },
     { role: "agent", filler: surgeon }]);
  const [ok, why] = validateSchema(t);
  assert(ok, why.join("; "));
};

vectors.v91 = () => {
  const q = quality("cortisol_concentration", "quantity", "ug/dL");
  const [ok, why] = validateSchema(q);
  assert(ok, why.join("; "));
};

function stateFixture(datatype, value, unit) {
  const q = quality("cortisol_concentration", datatype, unit);
  const c = cnt("human_patient").id;
  const subj = individual(c, "p").id;
  const st = state(subj, q.id, value,
    { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" });
  return [st, q];
}

vectors.v92 = () => {
  const [st, q] = stateFixture("quantity", { quantity: 15.0, unit: "ug/dL" },
    "ug/dL");
  const [ok, why] = validateSchema(st);
  assert(ok, why.join("; "));
  assert(deq(stateGaps(st, q), []), "coherent quantity has no gaps");
};

vectors.v93 = () => {
  const [st, q] = stateFixture("categorical", { categorical: "elevated" });
  const [ok, why] = validateSchema(st);
  assert(ok, why.join("; "));
  assert(deq(stateGaps(st, q), []), "coherent categorical has no gaps");
};

vectors.v94 = () => {
  const [st, q] = stateFixture("boolean", { boolean: true });
  const [ok, why] = validateSchema(st);
  assert(ok, why.join("; "));
  assert(deq(stateGaps(st, q), []), "coherent boolean has no gaps");
};

vectors.v95 = () => {
  const [st, q] = stateFixture("quantity", { categorical: "elevated" }, "ug/dL");
  assert(deq(stateGaps(st, q), ["value_type_mismatch"]), "value_type_mismatch");
};

vectors.v96 = () => {
  const [st, q] = stateFixture("quantity", { quantity: 15.0, unit: "mg/dL" },
    "ug/dL");
  assert(deq(stateGaps(st, q), ["unit_mismatch"]), "unit_mismatch");
};

function lawAndTokens() {
  const oCause = occ("resection"), oEffect = occ("amnesia_onset");
  const law = cro([oCause.id], [oEffect.id],
    { temporal: { minimum_delay: 0, maximum_delay: 1, unit: "days" },
      modality: "sufficient" });
  const tCause = token(oCause.id, { start: "1953-08-25T00:00:00Z" });
  const tEffect = token(oEffect.id,
    { start: "1953-08-25T00:00:00Z", open: true });
  return { law, oCause, oEffect, tCause, tEffect };
}

vectors.v97 = () => {
  const { law, tCause, tEffect } = lawAndTokens();
  const claim = tcc([tCause.id], [tEffect.id],
    { covering_law: law.id, actual_delay: { duration: 0, unit: "instant" },
      counterfactual: true });
  const [ok, why] = validateSchema(claim);
  assert(ok, why.join("; "));
};

vectors.v98 = () => {
  const { tCause, tEffect } = lawAndTokens();
  const claim = tcc([tCause.id], [tEffect.id]);
  const [ok, why] = validateSchema(claim);
  assert(ok, why.join("; "));
  assert(!("covering_law" in claim), "covering_law is optional");
};

vectors.v99 = () => {
  const { law } = lawAndTokens();
  assert(delayWithinWindow({ duration: 0, unit: "instant" }, law.temporal)
    === true, "instant delay within window");
};

vectors.v100 = () => {
  const temporal = { minimum_delay: 0, maximum_delay: 1, unit: "hours" };
  assert(delayWithinWindow({ duration: 5, unit: "days" }, temporal) === false,
    "5 days exceeds a 1-hour window");
};

vectors.v101 = () => {
  const o = occ("x").id;
  const cause = token(o, { start: "2026-01-02T00:00:00Z" });
  const effect = token(o, { start: "2026-01-01T00:00:00Z" });
  const claim = tcc([cause.id], [effect.id]);
  assert(retrocausal(claim, { [cause.id]: cause, [effect.id]: effect })
    === true, "cause after effect is retrocausal");
};

vectors.v102 = () => {
  const other = cro([sym("occurrent:foo")], [sym("occurrent:bar")]);
  const { tCause, tEffect } = lawAndTokens();
  const claim = tcc([tCause.id], [tEffect.id], { covering_law: other.id });
  assert(coveringLawMismatch(claim, { [tCause.id]: tCause,
    [tEffect.id]: tEffect }, other) === true, "covering law mismatch");
};

vectors.v103 = () => {
  const a = signed("assertion",
    { about: sym("token_occurrence:t"), evidence_type: "observation",
      confidence: 0.9 }, "signer");
  const [ok, why] = validateSchema(a);
  assert(ok, why.join("; "));
};

vectors.v104 = () => {
  const ev = [sym("token_occurrence:t1"), sym("token_causal_claim:c1")];
  const base = { type: "assertion", about: sym("causal_relation_object:law"),
                 source: key("signer")[1], evidence_type: "intervention",
                 strength: 0.95, confidence: 0.99,
                 timestamp: "2026-07-14T00:00:00Z" };
  const a = { ...base, evidenced_by: ev };
  const [ok, why] = validateSchema({ ...a, id: identify(a) });
  assert(ok, why.join("; "));
  assert(identify(a) !== identify(base), "evidenced_by is identity-bearing");
};

vectors.v105 = () => {
  const a = signed("assertion",
    { about: sym("causal_relation_object:law"), evidence_type: "simulation",
      confidence: 0.5 }, "signer");
  const [ok, why] = validateSchema(a);
  assert(ok, why.join("; "));
  const rank = { intervention: 0, observation: 1, simulation: 2 };
  assert(rank.intervention < rank.observation
    && rank.observation < rank.simulation, "evidence ranking");
};

vectors.v106 = () => {
  function scan(node, ids) {
    if (typeof node === "string") {
      const m = node.match(/^([a-z0-9_]+):[0-9a-f]{64}$/);
      if (m) ids.push(m[1]);
    } else if (Array.isArray(node)) {
      for (const x of node) scan(x, ids);
    } else if (node !== null && typeof node === "object") {
      for (const x of Object.values(node)) scan(x, ids);
    }
  }
  for (let n = 1; n <= 38; n++) {
    const ids = [];
    scan(vec(n), ids);
    for (const scheme of ids) {
      assert(WHOLE_WORD.has(scheme),
        "V106: abbreviated scheme " + JSON.stringify(scheme) +
        " in vector " + n);
    }
  }
  const rec = { type: "occurrent", label: "press_button", category: "action" };
  assert(identify(rec) === identify(rec), "identity deterministic");
  assert(identify(rec).split(":", 1)[0] === "occurrent", "whole-word prefix");
};

vectors.v107 = () => {
  const hexid = "0".repeat(64);
  // NOTE: the abbreviated prefix below is intentional (the negative test); it
  // must NOT be re-minted. "c"+"r"+"o" is assembled to survive re-mint tools.
  const croAbbr = "c" + "r" + "o";
  const abbreviated = { type: "causal_relation_object", id: croAbbr + ":" + hexid,
                        causes: ["occurrent:" + hexid],
                        effects: ["occurrent:" + hexid] };
  assert(!validateSchema(abbreviated, "causal_relation_object")[0],
    "abbreviated scheme must be rejected");
  const abbrStr = { type: "stratum", id: "str:" + hexid, label: "cellular",
                    scheme: "neuroendocrine", ordinal: 6 };
  assert(!validateSchema(abbrStr, "stratum")[0],
    "abbreviated stratum scheme must be rejected");
  const whole = { type: "causal_relation_object",
                  id: "causal_relation_object:" + hexid,
                  causes: ["occurrent:" + hexid],
                  effects: ["occurrent:" + hexid] };
  const [ok, why] = validateSchema(whole, "causal_relation_object");
  assert(ok, why.join("; "));
};

// V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam,
// realized_by) --------------------------------------------------------------

function seam(source, target, mechanismStatus, chain) {
  const o = { type: "cross_stratal_seam", source, target,
              mechanism_status: mechanismStatus };
  if (chain) o.chain = chain;
  return mk(o);
}

function seamFixture(srcOrd, tgtOrd, mechanismStatus, chainOrds) {
  const s = neuro();
  const src = occ("source_event", s[srcOrd].id);
  const tgt = occ("target_event", s[tgtOrd].id);
  const omap = { [src.id]: src, [tgt.id]: tgt };
  const smap = { [s[srcOrd].id]: s[srcOrd], [s[tgtOrd].id]: s[tgtOrd] };
  let chain = null;
  if (chainOrds != null) {
    chain = [];
    chainOrds.forEach((ord, i) => {
      const c = occ("chain_" + i, s[ord].id);
      omap[c.id] = c;
      smap[s[ord].id] = s[ord];
      chain.push(c.id);
    });
  }
  return [seam(src.id, tgt.id, mechanismStatus, chain), omap, smap];
}

// -- Change One: the ordinal (tick) temporal unit --
vectors.v108 = () => {
  const P = cro([sym("occurrent:a")], [sym("occurrent:b")],
    { temporal: { minimum_delay: 0, maximum_delay: 5, unit: "ticks" },
      modality: "sufficient" });
  let [ok, why] = validateSchema(P);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(P);
  assert(ok, why.join("; "));
};

vectors.v109 = () => {
  const P = cro([sym("occurrent:a")], [sym("occurrent:b")],
    { temporal: { minimum_delay: 2, maximum_delay: 5, unit: "ticks" } });
  assert(admissible(P, 3) === true, "3 ticks inside [2, 5]");
  assert(admissible(P, 2) === true && admissible(P, 5) === true,
    "inclusive at both ends");
  assert(admissible(P, 6) === false && admissible(P, 1) === false,
    "outside the tick window");
};

vectors.v110 = () => {
  const tickWindow = { minimum_delay: 0, maximum_delay: 5, unit: "ticks" };
  const wallWindow = { minimum_delay: 0, maximum_delay: 5, unit: "seconds" };
  assert(delayWithinWindow({ duration: 3, unit: "ticks" }, tickWindow)
    === true, "tick delay within tick window");
  assert(delayWithinWindow({ duration: 1, unit: "ticks" }, wallWindow)
    === false, "tick delay never within a wall-clock window");
  assert(delayWithinWindow({ duration: 1, unit: "seconds" }, tickWindow)
    === false, "wall-clock delay never within a tick window");
  const a = { causes: [sym("occurrent:a")], effects: [sym("occurrent:b")],
              temporal: tickWindow, modality: "sufficient" };
  const b = { causes: [sym("occurrent:a")], effects: [sym("occurrent:b")],
              temporal: wallWindow, modality: "preventive" };
  assert(conflicts(a, b) === false, "disjoint dimensions -> no overlap");
  let threw = false;
  try {
    toSeconds(1, "ticks");
  } catch (e) {
    threw = true;
  }
  assert(threw, "toSeconds accepted ticks");
};

vectors.v111 = () => {
  const base = { type: "causal_relation_object", causes: [sym("occurrent:a")],
                 effects: [sym("occurrent:b")], modality: "sufficient" };
  const tick = { ...base, temporal: { minimum_delay: 0, maximum_delay: 1,
                                      unit: "ticks" } };
  const secs = { ...base, temporal: { minimum_delay: 0, maximum_delay: 1,
                                      unit: "seconds" } };
  assert(identify(tick) !== identify(secs), "the unit is identity-bearing");
  // a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0 value)
  assert(identify(secs) === "causal_relation_object:" +
    "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
    "wall-clock identity drifted");
};

// -- Change Two: the managed cross-stratal seam (eighteenth kind) --
vectors.v112 = () => {
  const [sm, omap, smap] = seamFixture(14, 4, "unmodeled");
  let [ok, why] = validateSchema(sm);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(sm);
  assert(ok, why.join("; "));
  [ok, why] = seamWellformed(sm, omap, smap);
  assert(ok, why);
};

vectors.v113 = () => {
  const [a] = seamFixture(14, 4, "unmodeled");
  const [b, omap, smap] = seamFixture(14, 4, "absent");
  let [ok, why] = validateSchema(b);
  assert(ok, why.join("; "));
  [ok, why] = seamWellformed(b, omap, smap);
  assert(ok, why);
  assert(a.id !== b.id, "mechanism_status is identity-bearing");
};

vectors.v114 = () => {
  const [drawn, omap, smap] = seamFixture(14, 4, "unmodeled", [9, 7, 6, 5]);
  let [ok, why] = validateSchema(drawn);
  assert(ok, why.join("; "));
  [ok, why] = seamWellformed(drawn, omap, smap);
  assert(ok, why);
  const [bad, omap2, smap2] = seamFixture(14, 4, "absent", [9, 7, 6, 5]);
  [ok, why] = validateSemantics(bad);
  assert(!ok && why.some((w) => w.includes("contradictory_seam")),
    why.join("; "));
  assert(!seamWellformed(bad, omap2, smap2)[0],
    "a drawn chain with mechanism_status absent must be malformed");
};

vectors.v115 = () => {
  const [sm, omap, smap] = seamFixture(14, 4, "unmodeled");
  const s = neuro();
  assert(seamHome(sm, omap, smap) === s[14].id,
    "the home is the coarsest (max ordinal) stratum");
};

vectors.v116 = () => {
  const [adj, o1, s1] = seamFixture(6, 5, "unmodeled");  // adjacent (gap 1)
  assert(!seamWellformed(adj, o1, s1)[0], "adjacent seam must be malformed");
  const [cos, o2, s2] = seamFixture(6, 6, "unmodeled");  // co-stratal (gap 0)
  assert(!seamWellformed(cos, o2, s2)[0], "co-stratal seam must be malformed");
  const [sm] = seamFixture(14, 4, "unmodeled");
  assert(sm.id.startsWith("cross_stratal_seam:"), "a new identity scheme");
};

// -- Change Three: the realized_by reference --
function conduitRealized(realizedBy) {
  const frm = "port:" + "1".repeat(64);
  const to = "port:" + "2".repeat(64);
  const x = "occurrent:" + "3".repeat(64);
  const o = { type: "conduit", label: "conn", from: frm, to, carries: [x] };
  if (realizedBy) o.realized_by = realizedBy;
  return mk(o);
}

vectors.v117 = () => {
  const c = conduitRealized("causal_relation_object:" + "a".repeat(64));
  let [ok, why] = validateSchema(c);
  assert(ok, why.join("; "));
  const c2 = conduitRealized("native:region_stratum_predict");
  [ok, why] = validateSchema(c2);
  assert(ok, why.join("; ")); // a native scheme reference is legal
};

vectors.v118 = () => {
  const bound = conduitRealized("native:region_stratum_predict");
  const unbound = conduitRealized();
  assert(bound.id !== unbound.id, "realized_by is identity-bearing");
  // an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0 value)
  assert(unbound.id === "conduit:" +
    "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
    "unbound conduit identity drifted");
};

vectors.v119 = () => {
  const unbound = conduitRealized();
  const [ok, why] = validateSchema(unbound);
  assert(ok, why.join("; ")); // unbound is legal
  const bad = { ...unbound, realized_by: "not-a-scheme-qualified-reference" };
  assert(!validateSchema(bad, "conduit")[0],
    "a malformed realized_by reference must be rejected");
};

// V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
// prediction_error) ----------------------------------------------------------

function attitude(holder, attitudeType, content) {
  return mk({ type: "attitude", holder, attitude_type: attitudeType,
              content });
}

function predicted(instantiates, interval, predictorId, strength) {
  const o = { type: "predicted_occurrence", instantiates, interval,
              predictor: predictorId };
  if (strength != null) o.strength = strength;
  return mk(o);
}

function predictionError(predictedId, discrepancy, observed) {
  const o = { type: "prediction_error", predicted: predictedId, discrepancy };
  if (observed) o.observed = observed;
  return mk(o);
}

function predictor() {
  const c = cnt("forecasting_mind");
  return individual(c.id, "predictor_p").id;
}

// -- Group X: prediction and prediction error (Section A) --
vectors.v120 = () => {
  const o = occ("rainfall_begins");
  const p = predicted(o.id, { start_tick: 3, end_tick: 8 }, predictor());
  let [ok, why] = validateSchema(p);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(p);
  assert(ok, why.join("; "));
  assert(p.id.startsWith("predicted_occurrence:"), "a new identity scheme");
  const report = identify({ type: "token_occurrence", instantiates: o.id,
                            interval: { start_tick: 3, end_tick: 8 } },
                          "token_occurrence");
  assert(p.id !== report, "a forecast is not a report");
  assert(report.startsWith("token_occurrence:"), "report keeps its scheme");
};

vectors.v121 = () => {
  const o = occ("rainfall_begins");
  const wall = { start: "2026-07-23T00:00:00Z", end: "2026-07-24T00:00:00Z" };
  const who = predictor();
  const withStrength = predicted(o.id, wall, who, 0.8);
  const without = predicted(o.id, wall, who);
  for (const p of [withStrength, without]) {
    let [ok, why] = validateSchema(p);
    assert(ok, why.join("; "));
    [ok, why] = validateSemantics(p);
    assert(ok, why.join("; "));
  }
  assert(withStrength.id !== without.id, "strength is identity-bearing");
};

vectors.v122 = () => {
  const o = occ("rainfall_begins");
  const bad = mk({ type: "predicted_occurrence", instantiates: o.id,
                   interval: { start_tick: 3 } });
  const [ok, why] = validateSchema(bad, "predicted_occurrence");
  assert(!ok && why.some((w) => w.includes("predictor")), why.join("; "));
};

vectors.v123 = () => {
  const o = occ("rainfall_begins");
  const both = predicted(o.id, { start: "2026-07-23T00:00:00Z",
                                 start_tick: 3 }, predictor());
  let [ok, why] = validateSchema(both);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(both);
  assert(!ok && why.some((w) => w.includes("dimension_conflict")),
    why.join("; "));
};

vectors.v124 = () => {
  const o = occ("rainfall_begins");
  const p = predicted(o.id, { start: "2026-07-23T00:00:00Z" }, predictor());
  const t = token(o.id, { start: "2026-07-23T06:00:00Z" });
  const err = predictionError(p.id, 0.0, t.id);
  let [ok, why] = validateSchema(err);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(err);
  assert(ok, why.join("; "));
  assert(predictionPairingMismatch(err, p, t) === false,
    "a fulfilled prediction is no mismatch");
};

vectors.v125 = () => {
  const o = occ("rainfall_begins");
  const p = predicted(o.id, { start: "2026-07-23T00:00:00Z" }, predictor());
  const err = predictionError(p.id, -1.0);
  let [ok, why] = validateSchema(err);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(err);
  assert(ok, why.join("; "));
  assert(!("observed" in err), "observed is optional");
  assert(predictionPairingMismatch(err, p, null) === false,
    "an absent observed is never a mismatch");
};

vectors.v126 = () => {
  const o = occ("rainfall_begins");
  const p = predicted(o.id, { start_tick: 0 }, predictor());
  const bad = mk({ type: "prediction_error", predicted: p.id });
  const [ok, why] = validateSchema(bad, "prediction_error");
  assert(!ok && why.some((w) => w.includes("discrepancy")), why.join("; "));
};

vectors.v127 = () => {
  const o = occ("rainfall_begins"), other = occ("snowfall_begins");
  const p = predicted(o.id, { start: "2026-07-23T00:00:00Z" }, predictor());
  const t = token(other.id, { start: "2026-07-23T06:00:00Z" });
  const err = predictionError(p.id, 1.0, t.id);
  const [ok, why] = validateSchema(err);
  assert(ok, why.join("; "));
  assert(predictionPairingMismatch(err, p, t) === true, "pairing mismatch");
};

// -- Group Y: attitude and theory of mind (Section B) --
function believer(designator = "holder_h") {
  const c = cnt("believing_mind");
  return individual(c.id, designator).id;
}

vectors.v128 = () => {
  const [st] = stateFixture("quantity", { quantity: 15.0, unit: "ug/dL" },
    "ug/dL");
  const att = attitude(believer(), "believes", st.id);
  let [ok, why] = validateSchema(att);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(att);
  assert(ok, why.join("; "));
};

vectors.v129 = () => {
  const a = occ("switch_pressed"), b = occ("light_on");
  const actual = cro([a.id], [b.id], { modality: "sufficient" });
  const believed = cro([a.id], [b.id], { modality: "preventive" });
  assert(conflicts(believed, actual) === true, "the CLAIMS contradict");
  const att = attitude(believer(), "believes", believed.id);
  let [ok, why] = validateSchema(att);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(att);
  assert(ok, why.join("; ")); // validity unaffected
  const s = new InMemoryStore();
  s.put(a); s.put(b); s.put(actual); s.put(att);
  assert(deq(s.gaps("conflict"), []), "Rule 25: NO conflict raised");
};

vectors.v130 = () => {
  const o = occ("rainfall_begins");
  const att = attitude(believer(), "desires", o.id);
  let [ok, why] = validateSchema(att);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(att);
  assert(ok, why.join("; "));
};

vectors.v131 = () => {
  const o = occ("press_button");
  const att = attitude(believer(), "intends", o.id);
  let [ok, why] = validateSchema(att);
  assert(ok, why.join("; "));
  [ok, why] = validateSemantics(att);
  assert(ok, why.join("; "));
};

vectors.v132 = () => {
  const [st] = stateFixture("boolean", { boolean: true });
  const inner = attitude(believer("holder_b"), "believes", st.id);
  const outer = attitude(believer("holder_a"), "believes", inner.id);
  for (const att of [inner, outer]) {
    let [ok, why] = validateSchema(att);
    assert(ok, why.join("; "));
    [ok, why] = validateSemantics(att);
    assert(ok, why.join("; "));
  }
  assert(outer.id !== inner.id, "nesting mints a distinct identity");
  assert(outer.content === inner.id, "the outer content is the inner id");
};

vectors.v133 = () => {
  const o = occ("rainfall_begins");
  const bad = mk({ type: "attitude", holder: believer(),
                   attitude_type: "suspects", content: o.id });
  const [ok, why] = validateSchema(bad, "attitude");
  assert(!ok && why.some((w) => w.includes("attitude_type")), why.join("; "));
};

vectors.v134 = () => {
  const o = occ("rainfall_begins");
  const bad = mk({ type: "attitude", holder: believer(),
                   attitude_type: "believes", content: o.id,
                   strength: 0.9 });
  const [ok, why] = validateSchema(bad, "attitude");
  assert(!ok && why.some((w) => w.includes("strength")), why.join("; "));
};

vectors.v135 = () => {
  const o = occ("rainfall_begins");
  const att = attitude(believer(), "expects", o.id);
  const a = signed("assertion",
    { about: att.id, evidence_type: "observation", confidence: 0.9 },
    "signer");
  const [ok, why] = validateSchema(a);
  assert(ok, why.join("; "));
  assert(verifyRecord(a) === true, "assertion about an attitude verifies");
  // the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
  assert(att.holder.split(":", 1)[0] === "token_individual", "holder scheme");
  assert(a.source.split(":", 1)[0] === "ed25519", "source scheme");
  assert(att.holder !== a.source, "holder and source differ");
};

vectors.v136 = () => {
  // the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
  const secs = { type: "causal_relation_object", causes: [sym("occurrent:a")],
                 effects: [sym("occurrent:b")], modality: "sufficient",
                 temporal: { minimum_delay: 0, maximum_delay: 1,
                             unit: "seconds" } };
  assert(identify(secs) === "causal_relation_object:" +
    "d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
    "V111 identity drifted under 4.0.0");
  // the V118 unbound conduit, re-pinned under 4.0.0
  const unbound = conduitRealized();
  assert(unbound.id === "conduit:" +
    "dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
    "V118 identity drifted under 4.0.0");
};

vectors.v137 = () => {
  const hexid = "0".repeat(64);
  // NOTE: the abbreviated prefixes below are intentional (the negative test);
  // they must NOT be re-minted. Each is assembled to survive re-mint tools.
  const attAbbr = "a" + "t" + "t";
  const prdAbbr = "p" + "r" + "d";
  const errAbbr = "e" + "r" + "r";
  const badAtt = { type: "attitude", id: attAbbr + ":" + hexid,
                   holder: "token_individual:" + hexid,
                   attitude_type: "believes",
                   content: "state_assertion:" + hexid };
  assert(!validateSchema(badAtt, "attitude")[0],
    "abbreviated attitude scheme must be rejected");
  const badPrd = { type: "predicted_occurrence", id: prdAbbr + ":" + hexid,
                   instantiates: "occurrent:" + hexid,
                   interval: { start_tick: 0 },
                   predictor: "token_individual:" + hexid };
  assert(!validateSchema(badPrd, "predicted_occurrence")[0],
    "abbreviated predicted_occurrence scheme must be rejected");
  const badErr = { type: "prediction_error", id: errAbbr + ":" + hexid,
                   predicted: "predicted_occurrence:" + hexid,
                   discrepancy: 0.0 };
  assert(!validateSchema(badErr, "prediction_error")[0],
    "abbreviated prediction_error scheme must be rejected");
  const wholeAtt = { ...badAtt, id: "attitude:" + hexid };
  let [ok, why] = validateSchema(wholeAtt, "attitude");
  assert(ok, why.join("; "));
  const wholePrd = { ...badPrd, id: "predicted_occurrence:" + hexid };
  [ok, why] = validateSchema(wholePrd, "predicted_occurrence");
  assert(ok, why.join("; "));
  const wholeErr = { ...badErr, id: "prediction_error:" + hexid };
  [ok, why] = validateSchema(wholeErr, "prediction_error");
  assert(ok, why.join("; "));
};

// ---------------------------------------------------------------------------
function main() {
  console.log("causalontology-js conformance run (specification 4.0.0)");
  process.stdout.write(
    "internal checks (RFC 8032, RFC 8785, fixed constants) ... ");
  internalChecks();
  console.log("ok");
  let failures = 0;
  const total = 137;
  for (let n = 1; n <= total; n++) {
    const fn = vectors["v" + String(n).padStart(2, "0")];
    const name = vecName(n);
    try {
      fn();
      console.log("PASS  " + name);
    } catch (e) {
      failures += 1;
      console.log("FAIL  " + name + " :: " + (e && e.stack || e));
    }
  }
  console.log("-".repeat(60));
  console.log((total - failures) + "/" + total + " vectors passed");
  if (failures) process.exit(1);
  console.log("causalontology-js is CONFORMANT to the suite " +
    "(vectors frozen at specification 4.0.0).");
}

main();

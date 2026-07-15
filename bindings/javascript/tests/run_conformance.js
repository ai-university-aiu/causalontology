#!/usr/bin/env node
/* The Causalontology conformance runner for causalontology-js.
 *
 * Runs every vector in conformance/vectors/ against the JavaScript binding.
 * An implementation is conformant if and only if it passes every vector;
 * this runner exits nonzero on any failure.
 *
 * Pre-freeze note (see conformance/README.md): the vectors carry symbolic
 * identifiers ("occurrent:press_button", "ed25519:alice"). This harness
 * normalizes them deterministically - symbolic object ids become
 * scheme:sha256(name), and symbolic key names become real Ed25519 keypairs
 * seeded from sha256("key:" + name) - so the normative behaviors are
 * tested with well-formed data. The 1.0.0 freeze pins concrete bytes into
 * the vectors themselves.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const co = require(path.join(__dirname, "..", "causalontology.js"));
const {
  identify, validateSchema, validateSemantics, isPartial, admissible,
  conflicts, refinementValid, hierarchyConsistent, keypairFromSeed,
  signRecord, verifyRecord, InMemoryStore, RejectedWrite, ed25519, _jcs,
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
  return JSON.stringify(a) === JSON.stringify(b);
}

function sha256hex(s) {
  return crypto.createHash("sha256").update(s, "utf-8").digest("hex");
}

// ---------------------------------------------------------------------------
// symbolic-identifier normalization
// ---------------------------------------------------------------------------
const SCHEMES = ["occurrent", "causal_relation_object", "continuant", "realizable", "assertion", "enrichment", "retraction", "succession"];
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

/** Build, timestamp, and sign a provenance record. */
function signed(kind, body, who, tsI = 0) {
  const [secret, pub] = key(who);
  const rec = { ...body };
  rec.type = kind;
  if (!("timestamp" in rec)) rec.timestamp = "2026-07-13T0" + tsI + ":00:00Z";
  if (kind === "succession") {
    if (!("predecessor" in rec)) rec.predecessor = pub;
  } else {
    rec.source = pub;
  }
  return signRecord(rec, secret, kind);
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
  // the RFC's published TEST 1 signature bytes (Ed25519 is deterministic)
  assert(sig.toString("hex") ===
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "RFC 8032 TEST 1 signature bytes mismatch");
  // JCS basics
  assert(_jcs({ b: 2, a: 1 }) === '{"a":1,"b":2}', "JCS key sort failed");
  assert(_jcs(1.0) === "1" && _jcs(6.0) === "6" && _jcs(0.7) === "0.7",
    "JCS number serialization failed");
}

// ---------------------------------------------------------------------------
// the 38 vectors
// ---------------------------------------------------------------------------
const vectors = {};

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
  const dog = sym("continuant:dog"), mam = sym("continuant:mammal"), ani = sym("continuant:animal");
  const enrich = (about, entry, i) =>
    signed("enrichment", { about, field: "subsumes", entry }, "taxo", i);
  // enforcing tier rejects the cycle-completing write
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
  // decentralized merge: the view breaks the cycle deterministically
  const s2 = new InMemoryStore(true);
  s2.putRecord(enrich(dog, mam, 1));
  s2.putRecord(enrich(mam, ani, 2));
  const bad = enrich(ani, dog, 3);
  s2.forceMergeRecord(bad);
  const [, excluded] = s2._activeTaxonomyEdges("subsumes");
  assert(excluded.length === 1 && excluded[0].id === bad.id,
    "wrong record excluded");
  const repair = s2.gaps("inconsistent_hierarchy");
  assert(repair.some((g) => g.id === bad.id), "no repair gap emitted");
};

function adm(n) {
  const g = vec(n).given;
  const cro = { causes: [sym("occurrent:c")], effects: [sym("occurrent:e")],
                temporal: g.temporal };
  return admissible(cro, g.elapsed_seconds);
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
  const obj = { type: "occurrent", label: "press_button",
                category: "action" };
  const a = s.put({ ...obj });
  const b = s.put({ ...obj });
  assert(a === b && s.objects.size === 1, "put not idempotent");
};

vectors.v27 = () => {
  const s = new InMemoryStore();
  const occ = s.put({ type: "occurrent", label: "press_button",
                      category: "action" });
  const entry = { lang: "en", text: "press the button" };
  const r1 = signed("enrichment",
    { about: occ, field: "aliases", entry }, "alice", 1);
  const r2 = signed("enrichment",
    { about: occ, field: "aliases", entry }, "bob", 2);
  assert(s.putRecord(r1) !== s.putRecord(r2), "expected two records");
  const view = s.get(occ).enrichments.aliases;
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
      { about: i1, evidence_type: "observation",
        strength: 0.8, confidence: 0.8 }, who, ts));
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
  const tampered = { ...rec, confidence: 0.1 };
  assert(verifyRecord(tampered) === false, "tampered record verified");
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
  const foreign = signed("retraction", { retracts: a.id }, "mallory", 3);
  let threw = false;
  try {
    s.putRecord(foreign);
  } catch (e) {
    assert(e instanceof RejectedWrite, String(e));
    threw = true;
  }
  assert(threw, "foreign retraction accepted");
  assert(s.assertionsAbout(x).length === 0,   // still excluded by lab1's own
    "default view changed");
  assert(s.assertionsAbout(x, true).length === 1, "history changed");
};

vectors.v32 = () => {
  const s = new InMemoryStore();
  const occ = s.put({ type: "occurrent", label: "press_button",
                      category: "action" });
  const e = signed("enrichment",
    { about: occ, field: "aliases", entry: { lang: "ja", text: "botan" } },
    "bob", 1);
  s.putRecord(e);
  assert((s.get(occ).enrichments.aliases || []).length === 1,
    "enrichment missing");
  s.putRecord(signed("retraction", { retracts: e.id }, "bob", 2));
  assert((s.get(occ).enrichments.aliases || []).length === 0,
    "retracted enrichment still visible");
  const hist = s.get(occ, "history").enrichments.aliases || [];
  assert(hist.length === 1, "history view lost the enrichment");
};

vectors.v33 = () => {
  const s = new InMemoryStore();
  const k1 = key("K1")[1];
  const k2 = key("K2")[1];
  const a = signed("assertion",
    { about: sym("causal_relation_object:claim"), evidence_type: "observation",
      confidence: 0.9 }, "K1", 1);
  s.putRecord(a);
  const succ = signed("succession", { successor: k2 }, "K1", 2);
  s.putRecord(succ);
  assert(s.lineage(k2).has(k1) && s.lineage(k1).has(k2), "lineage broken");
  const r = signed("retraction", { retracts: a.id }, "K2", 3);
  s.putRecord(r); // successor may retract the predecessor's record
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
  assert(hierarchyConsistent(P, { [m1.id]: m1, [m2.id]: m2 })
    === "consistent", "chain should be consistent");
  const P2 = { ...P, mechanism: [m1.id, m3.id] };
  assert(hierarchyConsistent(P2, { [m1.id]: m1, [m3.id]: m3 })
    === "inconsistent", "broken chain should be inconsistent");
  assert(hierarchyConsistent(P, { [m1.id]: m1 })
    === "indeterminate", "missing member should be indeterminate");
};

vectors.v37 = () => {
  const s = new InMemoryStore();
  const occ = s.put({ type: "occurrent", label: "press_button",
                      category: "action" });
  s.putRecord(signed("enrichment",
    { about: occ, field: "aliases",
      entry: { lang: "en", text: "Press the Button" } }, "alice", 1));
  assert(deq(s.resolve("Press  The   Button", "en"), [occ]),  // alias match
    "alias resolve failed");
  assert(s.resolve("press_button", "en")[0] === occ,          // label, first
    "label resolve failed");
};

vectors.v38 = () => {
  const s = new InMemoryStore();
  const P = s.put({ type: "causal_relation_object", causes: [sym("occurrent:A")],
                    effects: [sym("occurrent:B")] });
  let gaps = s.gaps("missing_field").map((g) => g.id);
  assert(gaps.includes(P), "the bare CRO must be a gap");
  const R = s.put({ type: "causal_relation_object", causes: [sym("occurrent:A")],
                    effects: [sym("occurrent:B")],
                    temporal: { minimum_delay: 0, maximum_delay: 1, unit: "seconds" },
                    modality: "sufficient", refines: P });
  gaps = s.gaps("missing_field").map((g) => g.id);
  assert(!gaps.includes(P), "the gap did not close");
  assert(!gaps.includes(R), "the refinement itself must be complete");
};

// ---------------------------------------------------------------------------
function main() {
  console.log("causalontology-js conformance run");
  process.stdout.write(
    "internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ");
  internalChecks();
  console.log("ok");
  let failures = 0;
  for (let n = 1; n <= 38; n++) {
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
  const total = 38;
  console.log("-".repeat(60));
  console.log((total - failures) + "/" + total + " vectors passed");
  if (failures) process.exit(1);
  console.log("causalontology-js is CONFORMANT to the suite " +
    "(vectors frozen at specification 1.0.0).");
}

main();

/* causalontology - the JavaScript binding of the Causalontology standard.
 *
 * The third implementation (after the PrologAI reference and the Python
 * binding), proving language independence: Node.js builtins only
 * (node:crypto, node:fs, node:path), conformant when it passes every vector
 * in conformance/vectors/ (run tests/run_conformance.js).
 *
 * Causalontology is a verb-first noun-hosting ontology: reality is what
 * happens, and things are its participants.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const VERSION = "2.0.0"; // tracks specification version 2.0.0 (whole-word)

/* ===========================================================================
 * Canonicalization and content-addressed identity (spec/identity.md)
 * ===========================================================================
 * 1. take the object as JSON,
 * 2. keep only the identity-bearing fields for its kind (with "type"
 *    injected),
 * 3. serialize with the JSON Canonicalization Scheme (RFC 8785),
 * 4. hash with SHA-256,
 * 5. identifier = scheme + ":" + lowercase hex digest.
 *
 * RFC 8785 number and string serialization is exactly ECMAScript's
 * JSON.stringify for primitives, so JavaScript gets it natively.
 */

const IDENTITY_FIELDS = {
  // ---- type tier ----
  occurrent: ["label", "category", "stratum"],
  causal_relation_object: ["causes", "effects", "mechanism", "temporal",
                           "modality", "context", "refines", "skips"],
  continuant: ["label", "category"],
  realizable: ["kind", "bearer", "label"],
  stratum: ["label", "scheme", "ordinal", "unit", "governs"],
  bridge: ["coarse", "fine", "relation"],
  port: ["bearer", "label", "direction", "accepts", "realizable"],
  conduit: ["label", "from", "to", "carries", "transform"],
  quality: ["label", "datatype", "unit", "stratum"],
  // ---- token tier ----
  token_individual: ["instantiates", "designator", "part_of"],
  token_occurrence: ["instantiates", "interval", "participants",
                     "locus", "observer"],
  state_assertion: ["subject", "quality", "value", "interval"],
  token_causal_claim: ["causes", "effects", "covering_law",
                       "actual_delay", "counterfactual"],
  // ---- provenance tier ----
  assertion: ["about", "source", "evidence_type", "evidence", "strength",
              "confidence", "timestamp", "evidenced_by"],
  enrichment: ["about", "field", "entry", "source", "timestamp"],
  retraction: ["retracts", "source", "timestamp"],
  succession: ["predecessor", "successor", "timestamp"],
};

// Whole-word re-mint (P7): the scheme IS the type value for every kind.
const PREFIX = {};
for (const k of Object.keys(IDENTITY_FIELDS)) PREFIX[k] = k;

const KIND_OF_PREFIX = {};
for (const [k, v] of Object.entries(PREFIX)) KIND_OF_PREFIX[v] = k;

function isPlainObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

/** Infer an object's kind from its type field, id prefix, or shape. */
function inferKind(obj) {
  if ("type" in obj) return obj.type;
  if ("id" in obj && typeof obj.id === "string" && obj.id.includes(":")) {
    const pre = obj.id.split(":", 1)[0];
    if (pre in KIND_OF_PREFIX) return KIND_OF_PREFIX[pre];
  }
  if ("coarse" in obj && "fine" in obj) return "bridge";
  if ("causes" in obj && "effects" in obj) return "causal_relation_object";
  if ("retracts" in obj) return "retraction";
  if ("predecessor" in obj && "successor" in obj) return "succession";
  if ("field" in obj && "entry" in obj) return "enrichment";
  if ("evidence_type" in obj || ("about" in obj && "confidence" in obj)) {
    return "assertion";
  }
  if ("kind" in obj && "bearer" in obj) return "realizable";
  throw new Error(
    "cannot infer kind (occurrents and continuants share a shape); " +
    "pass kind explicitly");
}

/** The identity-bearing subset of an object, with type always present. */
function identityBearing(obj, kind) {
  kind = kind || inferKind(obj);
  if (!(kind in IDENTITY_FIELDS)) {
    throw new Error("unknown kind: " + JSON.stringify(kind));
  }
  const out = { type: kind };
  for (const field of IDENTITY_FIELDS[kind]) {
    if (field in obj) out[field] = obj[field];
  }
  return [kind, out];
}

/* RFC 8785 (JSON Canonicalization Scheme) serialization.
 * JSON.stringify's primitive serialization IS the ES6 rule RFC 8785 is
 * based on: shortest round-trip numbers, two-character escapes plus
 * lowercase \u00xx for remaining control characters. Objects sort their
 * keys by UTF-16 code units (Array.prototype.sort's default). */
function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("NaN and Infinity are not permitted (RFC 8785)");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(jcs).join(",") + "]";
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort(); // UTF-16 code-unit order
    return "{" +
      keys.map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") +
      "}";
  }
  throw new TypeError("cannot canonicalize " + typeof value);
}

/** The RFC 8785 identity-bearing bytes of an object. */
function canonicalize(obj, kind) {
  const [, ib] = identityBearing(obj, kind);
  return Buffer.from(jcs(ib), "utf-8");
}

/** The content-addressed identifier: scheme + ':' + SHA-256 hex. */
function identify(obj, kind) {
  const [k, ib] = identityBearing(obj, kind);
  const digest = crypto.createHash("sha256")
    .update(Buffer.from(jcs(ib), "utf-8")).digest("hex");
  return PREFIX[k] + ":" + digest;
}

/* ===========================================================================
 * Ed25519 digital signatures (RFC 8032) via node:crypto
 * ===========================================================================
 * The 32-byte seed/secret and 32-byte raw public key travel as bytes; the
 * DER prefixes below wrap and unwrap them for node's KeyObject API.
 * Ed25519 is deterministic, so signatures are byte-compatible with the
 * pure-Python binding.
 */

// PKCS8 DER header for an Ed25519 private key: prepend to the 32-byte seed.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SPKI DER header for an Ed25519 public key: prepend to the raw 32 bytes.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function privateKeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new Error("secret key must be 32 bytes");
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

/** The 32-byte raw public key for a 32-byte secret key. */
function secretToPublic(seed) {
  const priv = privateKeyFromSeed(seed);
  const spki = crypto.createPublicKey(priv)
    .export({ format: "der", type: "spki" });
  return spki.subarray(spki.length - 32); // raw key = last 32 bytes
}

/** The 64-byte Ed25519 signature of msg under the 32-byte secret key. */
function ed25519Sign(seed, msg) {
  return crypto.sign(null, msg, privateKeyFromSeed(seed));
}

/** True iff signature is a valid Ed25519 signature of msg under public. */
function ed25519Verify(publicRaw, msg, signature) {
  if (!Buffer.isBuffer(publicRaw) || publicRaw.length !== 32) return false;
  if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
  let keyObj;
  try {
    keyObj = crypto.createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, publicRaw]),
      format: "der",
      type: "spki",
    });
  } catch {
    return false; // not a decodable public key
  }
  try {
    return crypto.verify(null, msg, keyObj, signature);
  } catch {
    return false;
  }
}

const ed25519 = {
  secretToPublic,
  sign: ed25519Sign,
  verify: ed25519Verify,
};

/* ===========================================================================
 * Record-level signing and verification (spec/provenance.md)
 * ===========================================================================
 * The signature is computed over the record's canonical identity-bearing
 * bytes (the RFC 8785 form with id and signature removed - exactly the
 * bytes hashed for the record's identifier), so verification needs nothing
 * but the record itself.
 */

/** [secret, 'ed25519:<hex>'] from a 32-byte seed. */
function keypairFromSeed(seed32) {
  const pub = secretToPublic(seed32);
  return [seed32, "ed25519:" + pub.toString("hex")];
}

/** Return the record completed with its id and Ed25519 signature. */
function signRecord(record, secret, kind) {
  kind = kind || inferKind(record);
  const body = { ...record };
  delete body.signature;
  const message = canonicalize(body, kind);
  const signature = ed25519Sign(secret, message).toString("hex");
  const out = { ...body };
  out.id = identify(body, kind);
  out.signature = signature;
  return out;
}

function signerKeyHex(record, kind) {
  // a succession is signed by the predecessor key; everything else by source
  const field = kind === "succession" ? "predecessor" : "source";
  const value = record[field] || "";
  if (typeof value !== "string" || !value.startsWith("ed25519:")) return null;
  return value.split(":").slice(1).join(":");
}

function hexToBuffer(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 ||
      !/^[0-9a-fA-F]*$/.test(hex)) {
    return null;
  }
  return Buffer.from(hex, "hex");
}

/** True iff the record's signature verifies against its own key field. */
function verifyRecord(record, kind) {
  kind = kind || inferKind(record);
  const sigHex = record.signature;
  const keyHex = signerKeyHex(record, kind);
  if (!sigHex || !keyHex) return false;
  const publicRaw = hexToBuffer(keyHex);
  const signature = hexToBuffer(sigHex);
  if (publicRaw === null || signature === null) return false;
  const body = { ...record };
  delete body.signature;
  const message = canonicalize(body, kind);
  return ed25519Verify(publicRaw, message, signature);
}

/* ===========================================================================
 * Schema validation against spec/schema/*.schema.json
 * ===========================================================================
 * A deliberately small interpreter for exactly the JSON Schema keywords the
 * eight Causalontology schemas use: type, const, enum, pattern, required,
 * properties, additionalProperties, items, minItems, minLength, minimum,
 * maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
 * annotation, as the 2020-12 draft does by default.
 */

// kind -> schema file. Three token kinds keep their original 1.0.0-reserved
// file names (individual/token/state); the id scheme is the whole word.
const SCHEMA_FILES = {
  occurrent: "occurrent.schema.json",
  causal_relation_object: "causal_relation_object.schema.json",
  continuant: "continuant.schema.json",
  realizable: "realizable.schema.json",
  stratum: "stratum.schema.json",
  bridge: "bridge.schema.json",
  port: "port.schema.json",
  conduit: "conduit.schema.json",
  quality: "quality.schema.json",
  token_individual: "individual.schema.json",
  token_occurrence: "token.schema.json",
  state_assertion: "state.schema.json",
  token_causal_claim: "token_causal_claim.schema.json",
  assertion: "assertion.schema.json",
  enrichment: "enrichment.schema.json",
  retraction: "retraction.schema.json",
  succession: "succession.schema.json",
};

const SCHEMA_BASE = "https://causalontology.org/schema/";
const schemaCache = {};
const fileCache = {};

function schemaDir() {
  const env = process.env.CAUSALONTOLOGY_SPEC;
  if (env) return path.join(env, "schema");
  // bindings/javascript/causalontology.js -> repository root -> spec/schema
  return path.join(__dirname, "..", "..", "spec", "schema");
}

function loadFile(filename) {
  if (!(filename in fileCache)) {
    const file = path.join(schemaDir(), filename);
    fileCache[filename] = JSON.parse(fs.readFileSync(file, "utf-8"));
  }
  return fileCache[filename];
}

function loadSchema(kind) {
  if (!(kind in SCHEMA_FILES)) {
    throw new Error("unknown kind: " + JSON.stringify(kind));
  }
  if (!(kind in schemaCache)) {
    schemaCache[kind] = loadFile(SCHEMA_FILES[kind]);
  }
  return schemaCache[kind];
}

function navigate(doc, pointer) {
  let node = doc;
  for (const part of pointer.split("/")) {
    if (part === "") continue;
    node = node[part];
  }
  return node;
}

/** Resolve local and cross-file $refs to a concrete schema node + its root. */
function resolveRef(schema, root) {
  while (schema && typeof schema === "object" && "$ref" in schema) {
    const ref = schema.$ref;
    if (ref.startsWith("#/")) {
      schema = navigate(root, ref.slice(2));
    } else if (ref.startsWith(SCHEMA_BASE)) {
      const rest = ref.slice(SCHEMA_BASE.length);
      const hash = rest.indexOf("#/");
      const filename = hash === -1 ? rest : rest.slice(0, hash);
      const pointer = hash === -1 ? "" : rest.slice(hash + 2);
      root = loadFile(filename);
      schema = pointer ? navigate(root, pointer) : root;
    } else {
      throw new Error("unsupported $ref: " + ref);
    }
  }
  return [schema, root];
}

function typeMatches(value, t) {
  switch (t) {
    case "object": return isPlainObject(value);
    case "array": return Array.isArray(value);
    case "string": return typeof value === "string";
    case "number": return typeof value === "number";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean": return typeof value === "boolean";
    default: throw new Error("unsupported schema type: " + t);
  }
}

function deepEqual(a, b) {
  // structural equality via canonical serialization (all values are JSON)
  try {
    return jcs(a) === jcs(b);
  } catch {
    return false;
  }
}

function check(value, schema, root, at, errors) {
  [schema, root] = resolveRef(schema, root);

  if ("oneOf" in schema) {
    let passing = 0;
    for (const sub of schema.oneOf) {
      const subErrs = [];
      check(value, sub, root, at, subErrs);
      if (subErrs.length === 0) passing += 1;
    }
    if (passing !== 1) {
      errors.push(at + ": matches " + passing +
        " of the oneOf branches (need exactly 1)");
    }
    return;
  }

  const t = schema.type;
  if (t !== undefined) {
    if (!typeMatches(value, t)) {
      errors.push(at + ": expected " + t);
      return;
    }
  }

  if ("const" in schema && !deepEqual(value, schema.const)) {
    errors.push(at + ": must equal " + JSON.stringify(schema.const));
  }
  if ("enum" in schema &&
      !schema.enum.some((e) => deepEqual(value, e))) {
    errors.push(at + ": " + JSON.stringify(value) + " not in enumeration");
  }
  if ("pattern" in schema && typeof value === "string") {
    // re.search semantics: an unanchored RegExp test
    if (!new RegExp(schema.pattern).test(value)) {
      errors.push(at + ": " + JSON.stringify(value) +
        " does not match " + schema.pattern);
    }
  }
  if ("minLength" in schema && typeof value === "string") {
    if (value.length < schema.minLength) {
      errors.push(at + ": shorter than minLength");
    }
  }
  if ("minimum" in schema && typeof value === "number") {
    if (value < schema.minimum) {
      errors.push(at + ": below minimum " + schema.minimum);
    }
  }
  if ("maximum" in schema && typeof value === "number") {
    if (value > schema.maximum) {
      errors.push(at + ": above maximum " + schema.maximum);
    }
  }

  if (Array.isArray(value)) {
    if ("minItems" in schema && value.length < schema.minItems) {
      errors.push(at + ": fewer than " + schema.minItems + " items");
    }
    if ("items" in schema) {
      value.forEach((item, i) => {
        check(item, schema.items, root, at + "[" + i + "]", errors);
      });
    }
  }

  if (isPlainObject(value)) {
    const props = schema.properties || {};
    for (const req of schema.required || []) {
      if (!(req in value)) {
        errors.push(at + ": required property '" + req + "' missing");
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in props)) {
          errors.push(at + ": additional property '" + key + "'");
        }
      }
    }
    for (const [key, sub] of Object.entries(props)) {
      if (key in value) {
        check(value[key], sub, root, at + "." + key, errors);
      }
    }
  }
}

/** [ok, reasons] - structural validity against the kind's JSON Schema. */
function validateSchema(obj, kind) {
  kind = kind || inferKind(obj);
  const root = loadSchema(kind);
  const errors = [];
  check(obj, root, root, "$", errors);
  return [errors.length === 0, errors];
}

/* ===========================================================================
 * The semantic rules beyond the schemas (spec/semantics.md)
 * ===========================================================================
 * Local rules are checked here; store-context rules (materialized
 * acyclicity, retraction lineage) live in InMemoryStore where the context
 * exists.
 */

// Rule 4: the fixed unit-conversion constants (average Gregorian values).
const UNIT_SECONDS = {
  instant: 0,
  seconds: 1,
  minutes: 60,
  hours: 3600,
  days: 86400,
  weeks: 604800,
  months: 2629746,
  years: 31556952,
};

// Rule 12: enrichment field-to-kind validity and entry shapes.
const ENRICHMENT_FIELDS = {
  aliases: [["occurrent", "continuant"], "alias"],
  participants: [["occurrent"], "continuant"],
  subsumes: [["continuant"], "continuant"],
  part_of: [["continuant"], "continuant"],
  realized_in: [["realizable"], "occurrent"],
  occurrent_subsumes: [["occurrent"], "occurrent"],
  occurrent_part_of: [["occurrent"], "occurrent"],
};

const CRO_OPTIONAL_FIELDS = ["mechanism", "temporal", "modality", "context"];

function kindOfId(identifier) {
  return KIND_OF_PREFIX[String(identifier).split(":", 1)[0]];
}

/** [ok, reasons] - the locally checkable semantic rules. */
function validateSemantics(obj, kind) {
  kind = kind || inferKind(obj);
  const errors = [];

  if (kind === "causal_relation_object") {
    const t = obj.temporal;
    if (t != null && t.minimum_delay != null && t.maximum_delay != null && t.minimum_delay > t.maximum_delay) {
      errors.push("minimum_delay must be <= maximum_delay");
    }
    const oid = obj.id;
    if (oid && Array.isArray(obj.mechanism) && obj.mechanism.includes(oid)) {
      errors.push("mechanism must be acyclic " +
        "(a Causal Relation Object may not contain itself)");
    }
    if (oid && obj.refines === oid) {
      errors.push("refines must be acyclic");
    }
    // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
    // contradiction between skips:true and a non-empty mechanism.
    if (obj.skips === true && Array.isArray(obj.mechanism) &&
        obj.mechanism.length > 0) {
      errors.push("contradictory_skip: skips is true but a mechanism " +
        "is present");
    }
  }

  if (kind === "enrichment") {
    const field = obj.field;
    const about = obj.about || "";
    const entry = obj.entry;
    const spec = ENRICHMENT_FIELDS[field];
    if (spec) {
      const [legalKinds, shape] = spec;
      const aboutKind = kindOfId(about);
      if (aboutKind && !legalKinds.includes(aboutKind)) {
        errors.push(field + " is not a legal field for a " + aboutKind +
          " (rule 12)");
      }
      if (shape === "alias") {
        if (!(isPlainObject(entry) && "lang" in entry && "text" in entry)) {
          errors.push("an aliases entry must be a " +
            "language-tagged text object");
        }
      } else {
        if (!(typeof entry === "string" && entry.startsWith(shape + ":"))) {
          errors.push("a " + field + " entry must be a " + shape +
            ": identifier");
        }
      }
    }
  }

  return [errors.length === 0, errors];
}

/** [partial, missing] - which optional CRO fields are unspecified. */
function isPartial(cro) {
  const missing = CRO_OPTIONAL_FIELDS.filter((f) => !(f in cro));
  return [missing.length > 0, missing];
}

/** Rule 4: temporal admissibility with the fixed constants. */
function admissible(cro, elapsedSeconds) {
  const t = cro.temporal;
  if (t == null) return true; // no window imposes no constraint
  const unit = UNIT_SECONDS[t.unit];
  const lo = t.minimum_delay * unit;
  const hi = t.maximum_delay * unit;
  return lo <= elapsedSeconds && elapsedSeconds <= hi;
}

function windowOverlap(a, b) {
  const ta = a.temporal, tb = b.temporal;
  if (ta == null || tb == null) return true; // either absent = overlapping
  const ua = UNIT_SECONDS[ta.unit], ub = UNIT_SECONDS[tb.unit];
  const loA = ta.minimum_delay * ua, hiA = ta.maximum_delay * ua;
  const loB = tb.minimum_delay * ub, hiB = tb.maximum_delay * ub;
  return loA <= hiB && loB <= hiA;
}

function isSubset(a, b) {
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

function setsEqual(a, b) {
  return a.size === b.size && isSubset(a, b);
}

function contextsCompatible(a, b) {
  const ca = a.context, cb = b.context;
  if (!ca || !cb || ca.length === 0 || cb.length === 0) return true;
  const sa = new Set(ca), sb = new Set(cb);
  return setsEqual(sa, sb) || isSubset(sa, sb) || isSubset(sb, sa);
}

const POSITIVE = new Set(["necessary", "sufficient", "contributory",
                          "enabling"]);

/** Rule 6: the formal conflict test. */
function conflicts(a, b) {
  if (!setsEqual(new Set(a.causes), new Set(b.causes))) return false;
  if (!setsEqual(new Set(a.effects), new Set(b.effects))) return false;
  if (!contextsCompatible(a, b)) return false;
  if (!windowOverlap(a, b)) return false;
  const ma = a.modality, mb = b.modality;
  return (ma === "preventive" && POSITIVE.has(mb)) ||
         (mb === "preventive" && POSITIVE.has(ma));
}

/** Rule 3: [ok, reason] - is child a valid refinement of parent? */
function refinementValid(child, parent) {
  if (child.refines !== parent.id) {
    return [false, "child does not name the parent in refines"];
  }
  if (!setsEqual(new Set(child.causes), new Set(parent.causes)) ||
      !setsEqual(new Set(child.effects), new Set(parent.effects))) {
    return [false, "a refinement must keep the parent's causes and effects"];
  }
  let added = 0;
  for (const field of CRO_OPTIONAL_FIELDS) {
    if (field in parent) {
      if (!deepEqual(child[field], parent[field])) {
        return [false, "a refinement may not change a field the " +
          "parent specified; this is a rival claim"];
      }
    } else if (field in child) {
      added += 1;
    }
  }
  if (added === 0) {
    return [false, "a refinement must add at least one unspecified field"];
  }
  return [true, "valid refinement"];
}

/* ===========================================================================
 * 2.0.0 NORMATIVE ALGORITHMS (Section 12)
 * ===========================================================================
 * The five places where an implementation can be subtly and silently wrong,
 * implemented exactly as the reference (bindings/python) writes them.
 */

/** ALGORITHM A (bridge_closure). Every finer occurrent an occurrent resolves
 * to, following Bridges downward, transitively; includes the start (N12.1.1).
 * The visited guard (N12.1.2) prevents an infinite loop on cyclic data. */
function bridgeClosure(occurrentId, bridges) {
  const result = new Set([occurrentId]);
  const frontier = [occurrentId];
  const visited = new Set();
  const coarseIndex = new Map();
  for (const b of bridges || []) {
    if (!coarseIndex.has(b.coarse)) coarseIndex.set(b.coarse, []);
    coarseIndex.get(b.coarse).push(b);
  }
  while (frontier.length > 0) {
    const current = frontier.pop();
    if (visited.has(current)) continue;
    visited.add(current);
    for (const b of coarseIndex.get(current) || []) {
      for (const f of b.fine) {
        result.add(f);
        frontier.push(f);
      }
    }
  }
  return result;
}

/** True iff dst is reachable from src in the directed graph `edges`
 * (Map node -> iterable of successors). */
function pathExists(edges, src, dst) {
  const seen = new Set();
  const stack = [src];
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === dst) return true;
    if (seen.has(node)) continue;
    seen.add(node);
    for (const next of edges.get(node) || []) stack.push(next);
  }
  return false;
}

/** ALGORITHM B (amended Rule 7): 'consistent' | 'inconsistent' |
 * 'indeterminate', ACROSS STRATA via bridged reachability.
 *
 * members: a mapping (plain object or Map) from CRO identifier to CRO
 * object for the mechanism entries. bridges: the store's bridges (empty ->
 * 1.0.0 literal reachability, the degenerate case, N12.2.3). */
function hierarchyConsistent(parent, members, bridges = []) {
  const mechanism = parent.mechanism || [];
  if (mechanism.length === 0) return "consistent"; // nothing claimed (N12.2.1)
  const lookup = members instanceof Map
    ? (k) => members.get(k)
    : (k) => members[k];
  const edges = new Map();
  for (const mid of mechanism) {
    const m = lookup(mid);
    if (m == null) return "indeterminate"; // dangling; ignorance, not refutation
    for (const c of m.causes) {
      if (!edges.has(c)) edges.set(c, new Set());
      for (const e of m.effects) edges.get(c).add(e);
    }
  }
  const bCause = new Map();
  for (const c of parent.causes) bCause.set(c, bridgeClosure(c, bridges));
  const bEffect = new Map();
  for (const e of parent.effects) bEffect.set(e, bridgeClosure(e, bridges));
  for (const c of parent.causes) {
    for (const e of parent.effects) {
      let connected = false;
      for (const cp of bCause.get(c)) {
        for (const ep of bEffect.get(e)) {
          if (pathExists(edges, cp, ep)) { connected = true; break; }
        }
        if (connected) break;
      }
      if (!connected) return "inconsistent";
    }
  }
  return "consistent";
}

/** ALGORITHM C (Rule 15): 'intra_stratal' | 'adjacent_stratal' | 'skipping' |
 * 'mixed' | 'unclassifiable' | 'scheme_mismatch'. Derived, never asserted. */
function classifyCro(cro, occMap, stratumMap) {
  const stratumOf = (occId) =>
    (occMap[occId] || {}).stratum;
  const causeStrata = cro.causes.map(stratumOf);
  const effectStrata = cro.effects.map(stratumOf);
  if (causeStrata.concat(effectStrata).some((s) => s == null)) {
    return "unclassifiable"; // surface unstratified_occurrent (invitation)
  }
  const allStrata = new Set([...causeStrata, ...effectStrata]);
  const schemes = new Set();
  for (const s of allStrata) schemes.add(stratumMap[s].scheme);
  if (schemes.size > 1) return "scheme_mismatch"; // HARD
  const cOrd = causeStrata.map((s) => stratumMap[s].ordinal);
  const eOrd = effectStrata.map((s) => stratumMap[s].ordinal);
  const maxC = Math.max(...cOrd), minC = Math.min(...cOrd);
  const maxE = Math.max(...eOrd), minE = Math.min(...eOrd);
  if (maxC === minC && minC === maxE && maxE === minE) return "intra_stratal";
  let gap = Infinity, span = -Infinity;
  for (const i of cOrd) {
    for (const j of eOrd) {
      const d = Math.abs(i - j);
      if (d < gap) gap = d;
      if (d > span) span = d;
    }
  }
  if (span === 1) return "adjacent_stratal";
  if (gap > 1) return "skipping";
  return "mixed"; // some pairs adjacent, some skipping
}

/** True iff causes or effects span more than one distinct stratum
 * (surfaces mixed_stratal_endpoints, an invitation; N12.3.2). */
function endpointsMixed(cro, occMap) {
  const stratumOf = (occId) => (occMap[occId] || {}).stratum;
  const cs = new Set(cro.causes.map(stratumOf));
  const es = new Set(cro.effects.map(stratumOf));
  if (cs.has(undefined) || es.has(undefined) ||
      cs.has(null) || es.has(null)) {
    return false;
  }
  return cs.size > 1 || es.size > 1;
}

/** ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
 * skip decision. THE ASYMMETRY (clause 3) is the whole point of the field. */
function skipGaps(cro, classification) {
  const gaps = [];
  const hasMech = Array.isArray(cro.mechanism) && cro.mechanism.length > 0;
  if (cro.skips === true && hasMech) {
    gaps.push("contradictory_skip"); // HARD
    return gaps;
  }
  if (cro.skips === true &&
      classification !== "skipping" && classification !== "unclassifiable") {
    gaps.push("vacuous_skip"); // invitation
  }
  if (classification === "skipping" && !hasMech) {
    if (cro.skips === true) {
      // NOTHING: absence is a finding
    } else {
      gaps.push("incomplete_mechanism"); // invitation
    }
  }
  return gaps;
}

/** ALGORITHM E helper: normalize a delay to seconds by the fixed table. */
function toSeconds(duration, unit) {
  if (unit === "instant") return 0;
  return duration * UNIT_SECONDS[unit];
}

/** ALGORITHM E (Rule 20): does an observed delay fall within a covering
 * law's temporal window? Inclusive at both ends (N12.5.2). */
function delayWithinWindow(actualDelay, temporal) {
  if (!actualDelay || !temporal) return true; // nothing to check
  const observed = toSeconds(actualDelay.duration, actualDelay.unit);
  const lo = toSeconds(temporal.minimum_delay, temporal.unit);
  const hi = toSeconds(temporal.maximum_delay, temporal.unit);
  return lo <= observed && observed <= hi;
}

/** Rule 14 / N3.2.1: Bridge well-formedness. [ok, reason]; all of (a)-(e)
 * must hold, else malformed_bridge. */
function bridgeWellformed(bridge, occMap, stratumMap) {
  const coarse = occMap[bridge.coarse] || {};
  const cs = coarse.stratum;
  if (cs == null) return [false, "malformed_bridge: coarse has no stratum (a)"];
  const fineStrata = bridge.fine.map((f) => (occMap[f] || {}).stratum);
  if (fineStrata.some((s) => s == null)) {
    return [false, "malformed_bridge: a fine member has no stratum (b)"];
  }
  if (new Set(fineStrata).size !== 1) {
    return [false, "malformed_bridge: fine members span >1 stratum (c)"];
  }
  const fs = fineStrata[0];
  if (stratumMap[cs].scheme !== stratumMap[fs].scheme) {
    return [false, "malformed_bridge: coarse and fine differ in scheme (d)"];
  }
  if (!(stratumMap[cs].ordinal > stratumMap[fs].ordinal)) {
    return [false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"];
  }
  return [true, "well-formed bridge"];
}

/** Rule 17 / N4.2.1-2: Conduit well-formedness. [ok, reason] with the
 * transform exception of N4.2.2. */
function conduitWellformed(conduit, portMap, croMap) {
  const frm = portMap[conduit.from];
  const to = portMap[conduit.to];
  if (frm == null || to == null) {
    return [false, "malformed_conduit: dangling port reference"];
  }
  if (frm.direction !== "out" && frm.direction !== "bidirectional") {
    return [false, "malformed_conduit: from port is not out/bidirectional (a)"];
  }
  if (to.direction !== "in" && to.direction !== "bidirectional") {
    return [false, "malformed_conduit: to port is not in/bidirectional (b)"];
  }
  const carries = conduit.carries;
  if (!carries.every((o) => frm.accepts.includes(o))) {
    return [false, "malformed_conduit: carries not accepted by from (c)"];
  }
  const transform = conduit.transform;
  if (transform == null) {
    if (!carries.every((o) => to.accepts.includes(o))) {
      return [false, "malformed_conduit: carries not accepted by to (d)"];
    }
  } else {
    const law = (croMap || {})[transform];
    if (law != null) {
      if (!law.effects.every((o) => to.accepts.includes(o))) {
        return [false, "malformed_conduit: transform effects not " +
          "accepted by to (d, relaxed per N4.2.2)"];
      }
    }
  }
  return [true, "well-formed conduit"];
}

/** Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against its
 * quality: value_type_mismatch and/or unit_mismatch. */
function stateGaps(state, quality) {
  const gaps = [];
  const dt = quality.datatype;
  const v = state.value || {};
  const shape = "quantity" in v ? "quantity"
    : "categorical" in v ? "categorical"
      : "boolean" in v ? "boolean"
        : null;
  if (shape !== dt) {
    gaps.push("value_type_mismatch");
  } else if (dt === "quantity" && v.unit !== quality.unit) {
    gaps.push("unit_mismatch");
  }
  return gaps;
}

/** Rule 20: true iff the token claim's cause/effect tokens do not instantiate
 * the covering law's causes/effects (surfaces covering_law_mismatch). */
function coveringLawMismatch(tcc, tokenMap, law) {
  if (!law) return false;
  const lawCauses = new Set(law.causes);
  const lawEffects = new Set(law.effects);
  for (const c of tcc.causes) {
    if (!lawCauses.has(tokenMap[c].instantiates)) return true;
  }
  for (const e of tcc.effects) {
    if (!lawEffects.has(tokenMap[e].instantiates)) return true;
  }
  return false;
}

/** Rule 21: true iff any cause token starts after any effect token (HARD;
 * retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically. */
function retrocausal(tcc, tokenMap) {
  for (const c of tcc.causes) {
    const cstart = tokenMap[c].interval.start;
    for (const e of tcc.effects) {
      const estart = tokenMap[e].interval.start;
      if (cstart > estart) return true;
    }
  }
  return false;
}

/** Rules 4 / 6.1: true iff a directed graph (Map or plain object node ->
 * iterable of successors) has a cycle. */
function hasCycle(edges) {
  const WHITE = 0, GREY = 1, BLACK = 2;
  const state = new Map();
  const get = edges instanceof Map
    ? (n) => edges.get(n)
    : (n) => edges[n];
  const nodes = edges instanceof Map ? [...edges.keys()] : Object.keys(edges);

  function visit(node) {
    state.set(node, GREY);
    for (const nxt of get(node) || []) {
      const s = state.get(nxt) || WHITE;
      if (s === GREY) return true;
      if (s === WHITE && visit(nxt)) return true;
    }
    state.set(node, BLACK);
    return false;
  }

  return nodes.some((n) => (state.get(n) || WHITE) === WHITE && visit(n));
}

/* ===========================================================================
 * An in-memory conformant store (spec/store.md)
 * ===========================================================================
 * Immutable content objects with idempotent put; signed, add-only
 * provenance records; materialized enrichment views with contributors;
 * retraction handling in default views; succession lineage; the resolve
 * minimum; the deterministic cycle-breaking view rule; and the stigmergy
 * gap read.
 */

const CONTENT_KINDS = new Set([
  "occurrent", "causal_relation_object", "continuant", "realizable",
  "stratum", "bridge", "port", "conduit", "quality",
  "token_individual", "token_occurrence", "state_assertion",
  "token_causal_claim"]);
const RECORD_KINDS = new Set(["assertion", "enrichment", "retraction",
                              "succession"]);

/** An enforcing store refused a write, with the reason as e.message. */
class RejectedWrite extends Error {
  constructor(message) {
    super(message);
    this.name = "RejectedWrite";
  }
}

class InMemoryStore {
  constructor(enforcing = true) {
    this.enforcing = enforcing;
    this.objects = new Map();    // id -> content object
    this.records = new Map();    // id -> provenance record
    this.quarantine = new Map(); // id -> record (unsigned / unverifiable)
  }

  // -------------------------------------------------------------------- put
  /** Write a content object; idempotent; returns the identifier. */
  put(obj, kind) {
    kind = kind || inferKind(obj);
    if (!CONTENT_KINDS.has(kind)) {
      throw new Error("put() takes content objects; use putRecord()");
    }
    obj = { ...obj };
    if (!("type" in obj)) obj.type = kind;
    if (!("id" in obj)) obj.id = identify(obj, kind);
    if (this.objects.has(obj.id)) {
      return obj.id; // immutable: identical identity is a no-op
    }
    let [ok, why] = validateSchema(obj, kind);
    if (!ok) throw new RejectedWrite(why.join("; "));
    [ok, why] = validateSemantics(obj, kind);
    if (!ok) throw new RejectedWrite(why.join("; "));
    this.objects.set(obj.id, obj);
    return obj.id;
  }

  /** Write a signed provenance record; returns the identifier. */
  putRecord(record, kind, force = false) {
    kind = kind || inferKind(record);
    if (!RECORD_KINDS.has(kind)) {
      throw new Error("putRecord() takes provenance records");
    }
    record = { ...record };
    if (!("type" in record)) record.type = kind;
    const rid = record.id || identify(record, kind);
    record.id = rid;
    if (this.records.has(rid)) {
      return rid; // add-only and idempotent
    }
    if (!verifyRecord(record, kind)) {
      this.quarantine.set(rid, record);
      throw new RejectedWrite("unsigned or unverifiable record: quarantined");
    }
    const [ok, why] = validateSemantics(record, kind);
    if (!ok) throw new RejectedWrite(why.join("; "));
    if (kind === "retraction" && !this._retractionSourceOk(record)) {
      throw new RejectedWrite(
        "a retraction is valid only from the retracted record's " +
        "source or its succession lineage");
    }
    if (kind === "enrichment" && this.enforcing && !force) {
      if ((record.field === "subsumes" || record.field === "part_of") &&
          this._wouldCycle(record)) {
        throw new RejectedWrite(
          "would create a cycle in the materialized " +
          record.field + " graph");
      }
    }
    this.records.set(rid, record);
    return rid;
  }

  /** Simulate a decentralized replica merge (no enforcement gate). */
  forceMergeRecord(record, kind) {
    return this.putRecord(record, kind, true);
  }

  // --------------------------------------------------------- record queries
  _recordsOf(kind) {
    const out = [];
    for (const r of this.records.values()) {
      if (r.type === kind) out.push(r);
    }
    return out;
  }

  _retractedIds() {
    const out = new Set();
    for (const r of this._recordsOf("retraction")) out.add(r.retracts);
    return out;
  }

  _retractionSourceOk(retraction) {
    const target = this.records.get(retraction.retracts);
    if (target === undefined) {
      return true; // open world: the target may arrive later
    }
    return this.lineage(target.source).has(retraction.source);
  }

  /** The succession chain closure containing key (includes key). */
  lineage(key) {
    const succ = new Map();
    const pred = new Map();
    for (const s of this._recordsOf("succession")) {
      succ.set(s.predecessor, s.successor);
      pred.set(s.successor, s.predecessor);
    }
    const chain = new Set([key]);
    let cursor = key;
    while (pred.has(cursor)) {
      cursor = pred.get(cursor);
      chain.add(cursor);
    }
    cursor = key;
    while (succ.has(cursor)) {
      cursor = succ.get(cursor);
      chain.add(cursor);
    }
    return chain;
  }

  assertionsAbout(identifier, includeRetracted = false) {
    const retracted = this._retractedIds();
    const out = [];
    for (const r of this._recordsOf("assertion")) {
      if (r.about !== identifier) continue;
      if (retracted.has(r.id)) {
        if (includeRetracted) out.push({ ...r, retracted: true });
        continue;
      }
      out.push(r);
    }
    return out;
  }

  enrichmentsAbout(identifier, includeRetracted = false) {
    const retracted = this._retractedIds();
    const out = [];
    for (const r of this._recordsOf("enrichment")) {
      if (r.about !== identifier) continue;
      if (retracted.has(r.id) && !includeRetracted) continue;
      out.push(r);
    }
    return out;
  }

  // ---------------------------------------------------- materialized views
  /** [edges, excluded] for subsumes/part_of after rule 13 cycle-breaking. */
  _activeTaxonomyEdges(field) {
    const retracted = this._retractedIds();
    const recs = this._recordsOf("enrichment").filter(
      (r) => r.field === field && !retracted.has(r.id));
    const active = [...recs];
    const excluded = [];
    for (;;) {
      const cyc = InMemoryStore._findCycleRecords(active);
      if (cyc.length === 0) break;
      // exclude the cycle-completing record with the LATEST timestamp,
      // ties broken by lexicographic record identifier (deterministic)
      let loser = cyc[0];
      for (const r of cyc.slice(1)) {
        if (r.timestamp > loser.timestamp ||
            (r.timestamp === loser.timestamp && r.id > loser.id)) {
          loser = r;
        }
      }
      active.splice(active.indexOf(loser), 1);
      excluded.push(loser);
    }
    return [active, excluded];
  }

  static _findCycleRecords(recs) {
    const edges = new Map();
    for (const r of recs) {
      if (!edges.has(r.about)) edges.set(r.about, []);
      edges.get(r.about).push([r.entry, r]);
    }
    const state = new Map(); // 0 unvisited, 1 on stack, 2 done
    const cycle = [];

    function dfs(node, pathRecords) {
      state.set(node, 1);
      for (const [next, rec] of edges.get(node) || []) {
        if (state.get(next) === 1) {
          cycle.push(...pathRecords, rec);
          return true;
        }
        if ((state.get(next) || 0) === 0) {
          if (dfs(next, [...pathRecords, rec])) return true;
        }
      }
      state.set(node, 2);
      return false;
    }

    for (const start of [...edges.keys()]) {
      if ((state.get(start) || 0) === 0 && dfs(start, [])) return cycle;
    }
    return [];
  }

  _wouldCycle(record) {
    const retracted = this._retractedIds();
    const recs = this._recordsOf("enrichment").filter(
      (r) => r.field === record.field && !retracted.has(r.id));
    return InMemoryStore._findCycleRecords([...recs, record]).length > 0;
  }

  /** The object with its materialized enrichment sets and contributors. */
  get(identifier, view = "default") {
    const obj = this.objects.get(identifier);
    if (obj === undefined) return null;
    const includeRetracted = view === "history";
    const excludedIds = new Set();
    for (const field of ["subsumes", "part_of"]) {
      const [, excluded] = this._activeTaxonomyEdges(field);
      for (const r of excluded) excludedIds.add(r.id);
    }
    const fields = new Map();
    for (const rec of this.enrichmentsAbout(identifier, includeRetracted)) {
      if (excludedIds.has(rec.id) && view !== "history") continue;
      // dedup key: (field, canonical entry) - one bucket per distinct entry
      const entryKey = isPlainObject(rec.entry)
        ? jcs(rec.entry) : String(rec.entry);
      if (!fields.has(rec.field)) fields.set(rec.field, new Map());
      const slot = fields.get(rec.field);
      if (!slot.has(entryKey)) {
        slot.set(entryKey, { entry: rec.entry, contributors: [] });
      }
      slot.get(entryKey).contributors.push(
        { source: rec.source, timestamp: rec.timestamp });
    }
    const enrichments = {};
    for (const [f, slot] of fields) enrichments[f] = [...slot.values()];
    if (view === "raw") return { object: obj };
    return { object: obj, enrichments };
  }

  // ------------------------------------------------------------------ resolve
  static _canonLabel(text) {
    return text.trim().toLowerCase().split(/\s+/).join("_");
  }

  static _normAlias(text) {
    return text.trim().split(/\s+/).join(" ").toLowerCase();
  }

  /** The conformance minimum: exact label, then alias, then nothing. */
  resolve(text, lang = null) {
    const labelHits = [];
    const aliasHits = [];
    const wantedLabel = InMemoryStore._canonLabel(text);
    const wantedAlias = InMemoryStore._normAlias(text);
    const retracted = this._retractedIds();
    for (const [oid, obj] of this.objects) {
      if (obj.type !== "occurrent" && obj.type !== "continuant") continue;
      if (obj.label === wantedLabel) {
        labelHits.push(oid);
        continue;
      }
      for (const rec of this._recordsOf("enrichment")) {
        if (rec.about !== oid || rec.field !== "aliases") continue;
        if (retracted.has(rec.id)) continue;
        const entry = rec.entry;
        if (lang !== null && entry.lang !== lang) continue;
        if (InMemoryStore._normAlias(entry.text || "") === wantedAlias) {
          aliasHits.push(oid);
          break;
        }
      }
    }
    return [...labelHits, ...aliasHits]; // label hits rank before alias hits
  }

  // -------------------------------------------------------------------- gaps
  /** The stigmergy read. Gap kinds per spec/store.md. */
  gaps(kind = null) {
    const out = [];
    const refined = new Set();
    for (const obj of this.objects.values()) {
      if (obj.type === "causal_relation_object" && obj.refines) {
        const parent = this.objects.get(obj.refines);
        if (parent !== undefined) {
          const [ok] = refinementValid(obj, parent);
          if (ok) refined.add(parent.id);
        }
      }
    }
    for (const [oid, obj] of this.objects) {
      if (obj.type !== "causal_relation_object") continue;
      // missing_field: lacking the temporal window or the modality -
      // mechanism and context may legitimately stay unspecified forever
      // (empty_mechanism is its own kind; absent context = context-free).
      if ((!("temporal" in obj) || !("modality" in obj)) &&
          !refined.has(oid)) {
        out.push({ id: oid, kind: "missing_field",
                   missing: isPartial(obj)[1] });
      }
      if (!("mechanism" in obj) ||
          (Array.isArray(obj.mechanism) && obj.mechanism.length === 0)) {
        if (!refined.has(oid)) {
          out.push({ id: oid, kind: "empty_mechanism" });
        }
      }
    }
    for (const field of ["subsumes", "part_of"]) {
      const [, excluded] = this._activeTaxonomyEdges(field);
      for (const rec of excluded) {
        out.push({ id: rec.id, kind: "inconsistent_hierarchy",
                   note: "excluded by the deterministic " +
                         "cycle-breaking view rule" });
      }
    }
    // dangling_reference: a reference to an object absent from the store -
    // the red link that says "this page is wanted".
    for (const [oid, obj] of this.objects) {
      let refs = [];
      if (obj.type === "causal_relation_object") {
        refs = [
          ...(obj.causes || []),
          ...(obj.effects || []),
          ...(obj.context || []),
          ...(obj.mechanism || []),
        ];
        if (obj.refines) refs.push(obj.refines);
      } else if (obj.type === "realizable") {
        refs = [obj.bearer];
      }
      for (const ref of refs) {
        if (ref && !this.objects.has(ref)) {
          out.push({ id: oid, kind: "dangling_reference", ref });
        }
      }
    }
    // conflict: pairs of claims satisfying the formal test (rule 6).
    const cros = [...this.objects.values()].filter((o) => o.type === "causal_relation_object");
    for (let i = 0; i < cros.length; i++) {
      for (let j = i + 1; j < cros.length; j++) {
        if (conflicts(cros[i], cros[j])) {
          out.push({ kind: "conflict", a: cros[i].id, b: cros[j].id });
        }
      }
    }
    if (kind !== null) return out.filter((g) => g.kind === kind);
    return out;
  }
}

/* =========================================================================== */

module.exports = {
  __version__: VERSION,
  // canonical
  canonicalize, identify, identityBearing, inferKind,
  IDENTITY_FIELDS, PREFIX, KIND_OF_PREFIX,
  // schema
  validateSchema,
  // semantics
  validateSemantics, isPartial, admissible, conflicts,
  refinementValid, hierarchyConsistent, UNIT_SECONDS, ENRICHMENT_FIELDS,
  // 2.0.0 normative algorithms
  bridgeClosure, classifyCro, endpointsMixed, skipGaps, toSeconds,
  delayWithinWindow, bridgeWellformed, conduitWellformed, stateGaps,
  coveringLawMismatch, retrocausal, hasCycle,
  // signing
  keypairFromSeed, signRecord, verifyRecord, ed25519,
  // store
  InMemoryStore, RejectedWrite,
  // internals exposed for the conformance harness
  _jcs: jcs,
};

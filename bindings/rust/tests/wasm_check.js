#!/usr/bin/env node
// Cross-implementation check of the WebAssembly core: instantiate the
// wasm32 build in Node's native WASM runtime and verify its answers are
// byte-identical to the (independently conformant) JavaScript binding.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const js = require("../../javascript/causalontology.js");

const WASM = path.join(__dirname,
  "../target/wasm32-unknown-unknown/release/causalontology.wasm");

function call(instance, name, payload) {
  const { memory, co_alloc, co_free } = instance.exports;
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  const inPtr = co_alloc(bytes.length);
  Buffer.from(memory.buffer, inPtr, bytes.length).set(bytes);
  const outPtr = instance.exports[name](inPtr, bytes.length);
  const outLen = Buffer.from(memory.buffer, outPtr, 4).readUInt32LE(0);
  const text = Buffer.from(memory.buffer, outPtr + 4, outLen)
    .toString("utf8");
  co_free(inPtr, bytes.length);
  co_free(outPtr, outLen + 4);
  return JSON.parse(text);
}

async function main() {
  const module = await WebAssembly.instantiate(fs.readFileSync(WASM), {});
  const wasm = module.instance;
  let failures = 0;
  const check = (name, ok) => {
    console.log((ok ? "PASS" : "FAIL") + "  " + name);
    if (!ok) failures += 1;
  };

  // identity agreement: WASM core vs the verified JavaScript binding
  const press = { type: "occurrent", label: "press_button",
                  category: "action" };
  const wasmId = call(wasm, "co_identify", press).id;
  check("identify agrees with the JS binding (occurrent)",
        wasmId === js.identify(press));

  const claim = { type: "cro", causes: [wasmId],
                  effects: [js.identify({ type: "occurrent",
                    label: "light_on", category: "state_change" })],
                  modality: "sufficient" };
  check("identify agrees with the JS binding (cro)",
        call(wasm, "co_identify", claim).id === js.identify(claim));

  // canonicalization agreement (RFC 8785 bytes)
  check("canonical bytes agree",
        call(wasm, "co_canonicalize", claim).jcs ===
        Buffer.from(js.canonicalize(claim)).toString("utf8"));

  // validation agreement: embedded schemas + semantics inside the WASM
  const bad = { type: "cro", causes: [], effects: [wasmId] };
  const verdict = call(wasm, "co_validate", bad);
  check("embedded schema validation works in WASM (empty causes rejected)",
        verdict.schema_valid === false &&
        verdict.reasons.some((r) => r.includes("causes")));

  // Ed25519 verification inside the WASM, of a record signed by JS
  const crypto = require("node:crypto");
  const seed = crypto.createHash("sha256").update("wasm-check").digest();
  const [sk, source] = js.keypairFromSeed(seed);
  const rec = js.signRecord({ type: "assertion", about: claim.causes[0],
    source, evidence_type: "intervention", strength: 0.9,
    confidence: 0.9, timestamp: "2026-07-13T07:00:00Z" }, sk);
  check("WASM verifies a JS-signed Ed25519 record",
        call(wasm, "co_verify_record", rec).verified === true);
  const tampered = Object.assign({}, rec, { confidence: 0.1 });
  check("WASM rejects the tampered record",
        call(wasm, "co_verify_record", tampered).verified === false);

  console.log("-".repeat(60));
  const total = 6;
  console.log(`${total - failures}/${total} WASM cross-checks passed`);
  if (failures) process.exit(1);
  console.log("One audited core, every host: the WASM build agrees with " +
              "the JavaScript binding byte for byte.");
}

main().catch((e) => { console.error(e); process.exit(1); });

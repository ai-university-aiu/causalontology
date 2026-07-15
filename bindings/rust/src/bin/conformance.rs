//! The Causalontology conformance runner for the Rust binding.
//! Mirrors bindings/python/tests/run_conformance.py exactly, including
//! the pre-freeze symbolic-identifier normalization.

use causalontology::canonical::jcs;
use causalontology::{admissible, conflicts, hierarchy_consistent, identify,
                     is_partial, keypair_from_seed, refinement_valid,
                     sign_record, validate_schema, validate_semantics,
                     verify_record, InMemoryStore};
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors")
}

fn vec_json(n: u32) -> (String, Value) {
    let prefix = format!("v{:02}_", n);
    for entry in std::fs::read_dir(vectors_dir()).expect("vectors dir") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&prefix) && name.ends_with(".json") {
            let text = std::fs::read_to_string(entry.path()).unwrap();
            return (name.trim_end_matches(".json").to_string(),
                    serde_json::from_str(&text).unwrap());
        }
    }
    panic!("vector {} not found", n);
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{:02x}", b)).collect()
}

fn key(name: &str) -> (SigningKey, String) {
    let seed_input = format!("key:{}", name);
    let digest = Sha256::digest(seed_input.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    keypair_from_seed(&seed)
}

const SCHEMES: [&str; 9] =
    ["occurrent", "causal_relation_object", "continuant", "realizable", "assertion", "enrichment", "retraction", "succession", "ed25519"];

fn sym(s: &str) -> String {
    let (scheme, name) = match s.split_once(':') {
        Some(pair) => pair,
        None => return s.to_string(),
    };
    if scheme == "ed25519" {
        let frozen = name.len() == 64
            && name.chars().all(|c| c.is_ascii_hexdigit()
                                && !c.is_ascii_uppercase());
        if frozen {
            return s.to_string(); // frozen: a real key passes through
        }
        return key(name).1;
    }
    let is_hex64 = name.len() == 64
        && name.chars().all(|c| c.is_ascii_hexdigit()
                            && !c.is_ascii_uppercase());
    if is_hex64 {
        return s.to_string();
    }
    format!("{}:{}", scheme, sha256_hex(name.as_bytes()))
}

fn normalize(v: &Value) -> Value {
    match v {
        Value::String(s) => {
            if s == "<128 hex>" {
                return Value::String("ab".repeat(64));
            }
            if let Some((scheme, _)) = s.split_once(':') {
                if SCHEMES.contains(&scheme) {
                    return Value::String(sym(s));
                }
            }
            v.clone()
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize)
                                            .collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                out.insert(k.clone(), normalize(val));
            }
            Value::Object(out)
        }
        _ => v.clone(),
    }
}

fn obj(v: &Value) -> Map<String, Value> {
    v.as_object().expect("expected an object").clone()
}

fn signed(kind: &str, body: Value, who: &str, ts_i: u32)
          -> Map<String, Value> {
    let (secret, public) = key(who);
    let mut rec = obj(&body);
    rec.insert("type".into(), Value::String(kind.into()));
    rec.entry("timestamp".to_string()).or_insert_with(
        || Value::String(format!("2026-07-13T0{}:00:00Z", ts_i)));
    if kind == "succession" {
        rec.entry("predecessor".to_string())
            .or_insert_with(|| Value::String(public.clone()));
    } else {
        rec.insert("source".into(), Value::String(public.clone()));
    }
    sign_record(&rec, &secret, Some(kind)).expect("sign_record")
}

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

type R = Result<(), String>;

fn internal_checks() -> R {
    // RFC 8032, TEST 1 known-answer
    let mut seed = [0u8; 32];
    let seed_hex =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    for i in 0..32 {
        seed[i] = u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).unwrap();
    }
    let (sk, public) = keypair_from_seed(&seed);
    ensure!(public == "ed25519:d75a980182b10ab7d54bfed3c964073a\
                       0ee172f3daa62325af021a68f707511a"
            .replace([' ', '\n'], "").replace("ed25519:", "ed25519:"),
            "RFC 8032 TEST 1 public key mismatch: {}", public);
    use ed25519_dalek::Signer;
    let sig = sk.sign(b"");
    use ed25519_dalek::Verifier;
    ensure!(sk.verifying_key().verify(b"", &sig).is_ok(), "KAT verify");
    // JCS basics
    ensure!(jcs(&json!({"b": 2, "a": 1}))? == r#"{"a":1,"b":2}"#, "JCS sort");
    ensure!(jcs(&json!(1.0))? == "1", "JCS 1.0");
    ensure!(jcs(&json!(0.7))? == "0.7", "JCS 0.7");
    Ok(())
}

fn schema_fails(n: u32, must_mention: &str) -> R {
    let (_, v) = vec_json(n);
    let input = obj(&normalize(&v["input"]));
    let (ok, why) = validate_schema(&input, None);
    ensure!(!ok, "expected schema-invalid");
    ensure!(why.iter().any(|w| w.contains(must_mention)), "{:?}", why);
    Ok(())
}

fn semantics_fails(n: u32, must_mention: &str) -> R {
    let (_, v) = vec_json(n);
    let input = obj(&normalize(&v["input"]));
    let (ok, why) = validate_semantics(&input, None);
    ensure!(!ok, "expected semantically-invalid");
    ensure!(why.iter().any(|w| w.contains(must_mention)), "{:?}", why);
    Ok(())
}

fn schema_and_semantics_ok(n: u32) -> R {
    let (_, v) = vec_json(n);
    let input = obj(&normalize(&v["input"]));
    let (ok, why) = validate_schema(&input, None);
    ensure!(ok, "schema: {:?}", why);
    let (ok, why) = validate_semantics(&input, None);
    ensure!(ok, "semantics: {:?}", why);
    Ok(())
}

fn adm(n: u32) -> Result<bool, String> {
    let (_, v) = vec_json(n);
    let given = obj(&v["given"]);
    let cro = obj(&json!({
        "causes": [sym("occurrent:c")], "effects": [sym("occurrent:e")],
        "temporal": given["temporal"]
    }));
    let elapsed = given["elapsed_seconds"].as_f64()
        .ok_or("elapsed_seconds")?;
    Ok(admissible(&cro, elapsed))
}

fn run_vector(n: u32) -> R {
    match n {
        1 => schema_and_semantics_ok(1),
        2 => {
            schema_and_semantics_ok(2)?;
            let (_, v) = vec_json(2);
            let input = obj(&normalize(&v["input"]));
            let (partial, missing) = is_partial(&input);
            ensure!(partial, "expected partial");
            let expected: Vec<String> = v["expect"]["missing"]
                .as_array().unwrap().iter()
                .map(|x| x.as_str().unwrap().to_string()).collect();
            ensure!(missing == expected, "missing = {:?}", missing);
            Ok(())
        }
        3 => schema_fails(3, "effects"),
        4 => schema_fails(4, "causes"),
        5 => schema_fails(5, "modality"),
        6 => schema_fails(6, "colour"),
        7 => schema_fails(7, "causes"),
        8 => {
            let (_, v) = vec_json(8);
            let input = obj(&normalize(&v["input"]));
            let (ok, why) = validate_schema(&input, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        9 => schema_fails(9, "label"),
        10 => schema_fails(10, "category"),
        11 => {
            let (_, v) = vec_json(11);
            let input = obj(&normalize(&v["input"]));
            let (ok, why) = validate_schema(&input, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        12 => schema_fails(12, "confidence"),
        13 => schema_and_semantics_ok(13),
        14 => {
            let (_, v) = vec_json(14);
            let input = obj(&normalize(&v["input"]));
            let (ok, _) = validate_schema(&input, None);
            ensure!(ok, "schema should pass");
            semantics_fails(14, "minimum_delay")
        }
        15 => semantics_fails(15, "acyclic"),
        16 => semantics_fails(16, "acyclic"),
        17 => {
            let (_, v) = vec_json(17);
            let parent = obj(&normalize(&v["given"]["parent"]));
            let child = obj(&normalize(&v["input"]));
            let (ok, reason) = refinement_valid(&child, &parent);
            ensure!(!ok && reason.contains("rival"), "{}", reason);
            Ok(())
        }
        18 => semantics_fails(18, "not a legal field"),
        19 => semantics_fails(19, "language-tagged"),
        20 => {
            let (dog, mam, ani) =
                (sym("continuant:dog"), sym("continuant:mammal"), sym("continuant:animal"));
            let enrich = |about: &str, entry: &str, i: u32| {
                signed("enrichment",
                       json!({"about": about, "field": "subsumes",
                              "entry": entry}), "taxo", i)
            };
            let mut store = InMemoryStore::new(true);
            store.put_record(&enrich(&dog, &mam, 1), None)
                .map_err(|e| e.0)?;
            store.put_record(&enrich(&mam, &ani, 2), None)
                .map_err(|e| e.0)?;
            match store.put_record(&enrich(&ani, &dog, 3), None) {
                Ok(_) => return Err("enforcing store accepted a cycle".into()),
                Err(e) => ensure!(e.0.contains("cycle"), "{}", e.0),
            }
            let mut replica = InMemoryStore::new(true);
            replica.put_record(&enrich(&dog, &mam, 1), None)
                .map_err(|e| e.0)?;
            replica.put_record(&enrich(&mam, &ani, 2), None)
                .map_err(|e| e.0)?;
            let bad = enrich(&ani, &dog, 3);
            replica.force_merge_record(&bad, None).map_err(|e| e.0)?;
            let (_, excluded) = replica.active_taxonomy_edges("subsumes");
            ensure!(excluded.len() == 1
                    && excluded[0].get("id") == bad.get("id"),
                    "wrong exclusion");
            let repair = replica.gaps(Some("inconsistent_hierarchy"));
            ensure!(repair.iter().any(|g| g.get("id") == bad.get("id")),
                    "no repair gap");
            Ok(())
        }
        21 => { ensure!(adm(21)?, "expected admissible"); Ok(()) }
        22 => { ensure!(!adm(22)?, "expected inadmissible"); Ok(()) }
        23 => { ensure!(adm(23)?, "expected admissible"); Ok(()) }
        24 | 25 => {
            let (_, v) = vec_json(n);
            let a = identify(&obj(&normalize(&v["inputA"])), None)?;
            let b = identify(&obj(&normalize(&v["inputB"])), None)?;
            ensure!(a == b, "{} != {}", a, b);
            Ok(())
        }
        26 => {
            let mut store = InMemoryStore::new(true);
            let o = obj(&json!({"type": "occurrent",
                                "label": "press_button",
                                "category": "action"}));
            let a = store.put(&o, None).map_err(|e| e.0)?;
            let b = store.put(&o, None).map_err(|e| e.0)?;
            ensure!(a == b && store.objects.len() == 1, "not idempotent");
            Ok(())
        }
        27 => {
            let mut store = InMemoryStore::new(true);
            let occ = store.put(&obj(&json!({
                "type": "occurrent", "label": "press_button",
                "category": "action"})), None).map_err(|e| e.0)?;
            let entry = json!({"lang": "en", "text": "press the button"});
            let r1 = signed("enrichment", json!({
                "about": occ, "field": "aliases", "entry": entry}),
                "alice", 1);
            let r2 = signed("enrichment", json!({
                "about": occ, "field": "aliases", "entry": entry}),
                "bob", 2);
            let id1 = store.put_record(&r1, None).map_err(|e| e.0)?;
            let id2 = store.put_record(&r2, None).map_err(|e| e.0)?;
            ensure!(id1 != id2, "expected two records");
            let view = store.get(&occ, "default").unwrap();
            let aliases = view["enrichments"]["aliases"].as_array().unwrap();
            ensure!(aliases.len() == 1, "expected one entry");
            ensure!(aliases[0]["contributors"].as_array().unwrap().len() == 2,
                    "expected two contributors");
            Ok(())
        }
        28 => {
            let mut store = InMemoryStore::new(true);
            let claim = obj(&json!({
                "type": "causal_relation_object", "causes": [sym("occurrent:A")],
                "effects": [sym("occurrent:B")], "modality": "sufficient"}));
            let i1 = store.put(&claim, None).map_err(|e| e.0)?;
            let i2 = store.put(&claim, None).map_err(|e| e.0)?;
            ensure!(i1 == i2 && store.objects.len() == 1, "not one object");
            for (who, ts) in [("lab1", 1), ("lab2", 2)] {
                store.put_record(&signed("assertion", json!({
                    "about": i1, "evidence_type": "observation",
                    "strength": 0.8, "confidence": 0.8}), who, ts), None)
                    .map_err(|e| e.0)?;
            }
            ensure!(store.assertions_about(&i1, false).len() == 2,
                    "expected two assertions");
            Ok(())
        }
        29 => {
            let rec = signed("assertion", json!({
                "about": sym("causal_relation_object:demo"), "evidence_type": "intervention",
                "strength": 0.7, "confidence": 0.9}), "signer", 0);
            ensure!(verify_record(&rec, None), "must verify");
            Ok(())
        }
        30 => {
            let rec = signed("assertion", json!({
                "about": sym("causal_relation_object:demo"), "evidence_type": "intervention",
                "strength": 0.7, "confidence": 0.9}), "signer", 0);
            let mut tampered = rec.clone();
            tampered.insert("confidence".into(), json!(0.1));
            ensure!(!verify_record(&tampered, None), "tamper must fail");
            Ok(())
        }
        31 => {
            let mut store = InMemoryStore::new(true);
            let x = store.put(&obj(&json!({
                "type": "causal_relation_object", "causes": [sym("occurrent:A")],
                "effects": [sym("occurrent:B")]})), None).map_err(|e| e.0)?;
            let a = signed("assertion", json!({
                "about": x, "evidence_type": "observation",
                "confidence": 0.8}), "lab1", 1);
            store.put_record(&a, None).map_err(|e| e.0)?;
            store.put_record(&signed("retraction", json!({
                "retracts": a["id"]}), "lab1", 2), None).map_err(|e| e.0)?;
            ensure!(store.assertions_about(&x, false).is_empty(),
                    "default view must exclude");
            let hist = store.assertions_about(&x, true);
            ensure!(hist.len() == 1
                    && hist[0].get("retracted") == Some(&json!(true)),
                    "history must flag");
            let foreign = signed("retraction", json!({
                "retracts": a["id"]}), "mallory", 3);
            ensure!(store.put_record(&foreign, None).is_err(),
                    "foreign retraction accepted");
            ensure!(store.assertions_about(&x, false).is_empty()
                    && store.assertions_about(&x, true).len() == 1,
                    "state changed by foreign retraction");
            Ok(())
        }
        32 => {
            let mut store = InMemoryStore::new(true);
            let occ = store.put(&obj(&json!({
                "type": "occurrent", "label": "press_button",
                "category": "action"})), None).map_err(|e| e.0)?;
            let e = signed("enrichment", json!({
                "about": occ, "field": "aliases",
                "entry": {"lang": "ja", "text": "botan"}}), "bob", 1);
            store.put_record(&e, None).map_err(|e| e.0)?;
            let n_before = store.get(&occ, "default").unwrap()
                ["enrichments"]["aliases"].as_array()
                .map(|a| a.len()).unwrap_or(0);
            ensure!(n_before == 1, "expected one alias");
            store.put_record(&signed("retraction", json!({
                "retracts": e["id"]}), "bob", 2), None).map_err(|e| e.0)?;
            let after = store.get(&occ, "default").unwrap();
            let n_after = after["enrichments"].get("aliases")
                .and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0);
            ensure!(n_after == 0, "retracted alias still visible");
            let hist = store.get(&occ, "history").unwrap();
            let n_hist = hist["enrichments"]["aliases"].as_array()
                .map(|a| a.len()).unwrap_or(0);
            ensure!(n_hist == 1, "history must keep it");
            Ok(())
        }
        33 => {
            let mut store = InMemoryStore::new(true);
            let (_, k1) = key("K1");
            let (_, k2) = key("K2");
            let a = signed("assertion", json!({
                "about": sym("causal_relation_object:claim"), "evidence_type": "observation",
                "confidence": 0.9}), "K1", 1);
            store.put_record(&a, None).map_err(|e| e.0)?;
            store.put_record(&signed("succession", json!({
                "successor": k2}), "K1", 2), None).map_err(|e| e.0)?;
            ensure!(store.lineage(&k2).contains(&k1), "lineage broken");
            store.put_record(&signed("retraction", json!({
                "retracts": a["id"]}), "K2", 3), None).map_err(|e| e.0)?;
            ensure!(store.assertions_about(&sym("causal_relation_object:claim"), false)
                    .is_empty(), "successor retraction not honored");
            Ok(())
        }
        34 => {
            let (_, v) = vec_json(34);
            let g = normalize(&v["given"]);
            ensure!(conflicts(&obj(&g["A"]), &obj(&g["B"])),
                    "expected conflict");
            Ok(())
        }
        35 => {
            let (_, v) = vec_json(35);
            let g = normalize(&v["given"]);
            ensure!(!conflicts(&obj(&g["A"]), &obj(&g["B"])),
                    "expected no conflict");
            Ok(())
        }
        36 => {
            let (a, b, c, d) = (sym("occurrent:A"), sym("occurrent:B"),
                                sym("occurrent:C"), sym("occurrent:D"));
            let m1 = obj(&json!({"id": sym("causal_relation_object:m1"),
                                 "causes": [a], "effects": [b]}));
            let m2 = obj(&json!({"id": sym("causal_relation_object:m2"),
                                 "causes": [b], "effects": [c]}));
            let m3 = obj(&json!({"id": sym("causal_relation_object:m3"),
                                 "causes": [d], "effects": [c]}));
            let parent = obj(&json!({
                "causes": [a], "effects": [c],
                "mechanism": [m1["id"], m2["id"]]}));
            let mut members = HashMap::new();
            members.insert(m1["id"].as_str().unwrap().to_string(), m1.clone());
            members.insert(m2["id"].as_str().unwrap().to_string(), m2.clone());
            ensure!(hierarchy_consistent(&parent, &members) == "consistent",
                    "expected consistent");
            let parent2 = obj(&json!({
                "causes": [a], "effects": [c],
                "mechanism": [m1["id"], m3["id"]]}));
            let mut members2 = HashMap::new();
            members2.insert(m1["id"].as_str().unwrap().to_string(), m1.clone());
            members2.insert(m3["id"].as_str().unwrap().to_string(), m3);
            ensure!(hierarchy_consistent(&parent2, &members2)
                    == "inconsistent", "expected inconsistent");
            let mut partial = HashMap::new();
            partial.insert(m1["id"].as_str().unwrap().to_string(), m1);
            ensure!(hierarchy_consistent(&parent, &partial)
                    == "indeterminate", "expected indeterminate");
            Ok(())
        }
        37 => {
            let mut store = InMemoryStore::new(true);
            let occ = store.put(&obj(&json!({
                "type": "occurrent", "label": "press_button",
                "category": "action"})), None).map_err(|e| e.0)?;
            store.put_record(&signed("enrichment", json!({
                "about": occ, "field": "aliases",
                "entry": {"lang": "en", "text": "Press the Button"}}),
                "alice", 1), None).map_err(|e| e.0)?;
            ensure!(store.resolve("Press  The   Button", Some("en"))
                    == vec![occ.clone()], "alias match failed");
            let by_label = store.resolve("press_button", Some("en"));
            ensure!(by_label.first() == Some(&occ), "label must rank first");
            Ok(())
        }
        38 => {
            let mut store = InMemoryStore::new(true);
            let p = store.put(&obj(&json!({
                "type": "causal_relation_object", "causes": [sym("occurrent:A")],
                "effects": [sym("occurrent:B")]})), None).map_err(|e| e.0)?;
            let has = |store: &InMemoryStore, id: &str| {
                store.gaps(Some("missing_field")).iter()
                    .any(|g| g.get("id").and_then(Value::as_str) == Some(id))
            };
            ensure!(has(&store, &p), "gap must be open");
            let r = store.put(&obj(&json!({
                "type": "causal_relation_object", "causes": [sym("occurrent:A")],
                "effects": [sym("occurrent:B")],
                "temporal": {"minimum_delay": 0, "maximum_delay": 1, "unit": "seconds"},
                "modality": "sufficient", "refines": p})), None)
                .map_err(|e| e.0)?;
            ensure!(!has(&store, &p), "the gap did not close");
            ensure!(!has(&store, &r), "the refinement must be complete");
            Ok(())
        }
        _ => Err(format!("no vector {}", n)),
    }
}

fn main() {
    println!("causalontology-rust conformance run");
    print!("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ");
    if let Err(e) = internal_checks() {
        println!("FAILED: {}", e);
        std::process::exit(1);
    }
    println!("ok");
    let mut failures = 0;
    for n in 1..=38 {
        let (name, _) = vec_json(n);
        match run_vector(n) {
            Ok(()) => println!("PASS  {}", name),
            Err(e) => {
                failures += 1;
                println!("FAIL  {} :: {}", name, e);
            }
        }
    }
    println!("{}", "-".repeat(60));
    println!("{}/38 vectors passed", 38 - failures);
    if failures > 0 {
        std::process::exit(1);
    }
    println!("causalontology-rust is CONFORMANT to the suite \
              (vectors frozen at specification 1.0.0).");
}

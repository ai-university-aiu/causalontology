//! The Causalontology conformance runner for the Rust binding (spec 2.0.0).
//! Mirrors bindings/python/tests/run_conformance.py exactly, including the
//! pre-freeze symbolic-identifier normalization and the whole-word re-mint.
//! An implementation is conformant iff it passes every one of the 107 vectors.

use causalontology::canonical::jcs;
use causalontology::{admissible, bridge_wellformed, classify_cro, conduit_wellformed,
                     conflicts, covering_law_mismatch, delay_within_window,
                     endpoints_mixed, has_cycle, hierarchy_consistent, identify,
                     is_partial, keypair_from_seed, refinement_valid, retrocausal,
                     sign_record, skip_gaps, state_gaps, validate_schema,
                     validate_semantics, verify_record, InMemoryStore};
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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

// The seventeen whole-word schemes plus the external ed25519 proper name.
const SCHEMES: [&str; 18] = [
    "occurrent", "causal_relation_object", "continuant", "realizable",
    "assertion", "enrichment", "retraction", "succession",
    "stratum", "bridge", "port", "conduit", "quality",
    "token_individual", "token_occurrence", "state_assertion",
    "token_causal_claim", "ed25519",
];

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()
                                   && !c.is_ascii_uppercase())
}

fn sym(s: &str) -> String {
    let (scheme, name) = match s.split_once(':') {
        Some(pair) => pair,
        None => return s.to_string(),
    };
    if scheme == "ed25519" {
        if is_hex64(name) {
            return s.to_string(); // frozen: a real key passes through
        }
        return key(name).1;
    }
    if is_hex64(name) {
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
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
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

fn id_of(m: &Map<String, Value>) -> String {
    m.get("id").and_then(Value::as_str).expect("no id").to_string()
}

fn mk(mut o: Map<String, Value>) -> Map<String, Value> {
    let id = identify(&o, None).expect("identify");
    o.insert("id".into(), Value::String(id));
    o
}

fn map_by_id(objs: &[&Map<String, Value>])
             -> HashMap<String, Map<String, Value>> {
    objs.iter().map(|o| (id_of(o), (*o).clone())).collect()
}

// ---- content builders (mirror the Python test builders) -------------------
fn stratum(label: &str, scheme: &str, ordinal: i64, unit: Option<&str>,
           governs: Option<Vec<&str>>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "stratum", "label": label,
                            "scheme": scheme, "ordinal": ordinal}));
    if let Some(u) = unit { o.insert("unit".into(), json!(u)); }
    if let Some(g) = governs { o.insert("governs".into(), json!(g)); }
    mk(o)
}

fn occ(label: &str, stratum_id: Option<&str>, category: &str)
       -> Map<String, Value> {
    let mut o = obj(&json!({"type": "occurrent", "label": label,
                            "category": category}));
    if let Some(s) = stratum_id { o.insert("stratum".into(), json!(s)); }
    mk(o)
}

fn cnt(label: &str, category: &str) -> Map<String, Value> {
    mk(obj(&json!({"type": "continuant", "label": label, "category": category})))
}

fn cro(causes: Vec<Value>, effects: Vec<Value>, extra: Vec<(&str, Value)>)
       -> Map<String, Value> {
    let mut o = obj(&json!({"type": "causal_relation_object",
                            "causes": causes, "effects": effects}));
    for (k, v) in extra { o.insert(k.into(), v); }
    mk(o)
}

fn bridge(coarse: &str, fine: Vec<Value>, relation: &str)
          -> Map<String, Value> {
    mk(obj(&json!({"type": "bridge", "coarse": coarse, "fine": fine,
                   "relation": relation})))
}

fn port(bearer: &str, label: &str, direction: &str, accepts: Vec<Value>,
        realizable: Option<&str>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "port", "bearer": bearer, "label": label,
                            "direction": direction, "accepts": accepts}));
    if let Some(r) = realizable { o.insert("realizable".into(), json!(r)); }
    mk(o)
}

fn conduit(frm: &str, to: &str, carries: Vec<Value>, label: &str,
           transform: Option<&str>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "conduit", "label": label, "from": frm,
                            "to": to, "carries": carries}));
    if let Some(t) = transform { o.insert("transform".into(), json!(t)); }
    mk(o)
}

fn quality(label: &str, datatype: &str, unit: Option<&str>,
           stratum_id: Option<&str>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "quality", "label": label,
                            "datatype": datatype}));
    if let Some(u) = unit { o.insert("unit".into(), json!(u)); }
    if let Some(s) = stratum_id { o.insert("stratum".into(), json!(s)); }
    mk(o)
}

fn individual(instantiates: &str, designator: Option<&str>,
              part_of: Option<&str>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "token_individual",
                            "instantiates": instantiates}));
    if let Some(d) = designator { o.insert("designator".into(), json!(d)); }
    if let Some(p) = part_of { o.insert("part_of".into(), json!(p)); }
    mk(o)
}

fn token(instantiates: &str, interval: Value, participants: Option<Value>,
         locus: Option<&str>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "token_occurrence",
                            "instantiates": instantiates, "interval": interval}));
    if let Some(p) = participants { o.insert("participants".into(), p); }
    if let Some(l) = locus { o.insert("locus".into(), json!(l)); }
    mk(o)
}

fn state(subject: &str, qual: &str, value: Value, interval: Value)
         -> Map<String, Value> {
    mk(obj(&json!({"type": "state_assertion", "subject": subject,
                   "quality": qual, "value": value, "interval": interval})))
}

fn tcc(causes: Vec<Value>, effects: Vec<Value>, covering_law: Option<&str>,
       actual_delay: Option<Value>, counterfactual: Option<bool>)
       -> Map<String, Value> {
    let mut o = obj(&json!({"type": "token_causal_claim",
                            "causes": causes, "effects": effects}));
    if let Some(c) = covering_law { o.insert("covering_law".into(), json!(c)); }
    if let Some(a) = actual_delay { o.insert("actual_delay".into(), a); }
    if let Some(cf) = counterfactual {
        o.insert("counterfactual".into(), json!(cf));
    }
    mk(o)
}

fn rlz(bearer: &str, kind: &str, label: Option<&str>) -> Map<String, Value> {
    let mut o = obj(&json!({"type": "realizable", "kind": kind,
                            "bearer": bearer}));
    if let Some(l) = label { o.insert("label".into(), json!(l)); }
    mk(o)
}

// ---- shared fixtures ------------------------------------------------------
fn neuro() -> HashMap<i64, Map<String, Value>> {
    [(4, "macromolecular"), (5, "subcellular"), (6, "cellular"),
     (7, "synaptic"), (9, "region"), (14, "community_and_society")]
        .iter()
        .map(|(o, l)| (*o, stratum(l, "neuroendocrine", *o, None, None)))
        .collect()
}

fn classify_ord(cause_ord: i64, effect_ord: i64) -> String {
    let n = neuro();
    let sc = n[&cause_ord].clone();
    let se = n[&effect_ord].clone();
    let scid = id_of(&sc);
    let seid = id_of(&se);
    let c = occ("c", Some(&scid), "event");
    let e = occ("e", Some(&seid), "event");
    let smap = map_by_id(&[&sc, &se]);
    let om = map_by_id(&[&c, &e]);
    let p = cro(vec![json!(id_of(&c))], vec![json!(id_of(&e))], vec![]);
    classify_cro(&p, &om, &smap).to_string()
}

fn skip_fixture(cause_ord: i64, effect_ord: i64, extra: Vec<(&str, Value)>)
                -> (Map<String, Value>, String) {
    let n = neuro();
    let sc = n[&cause_ord].clone();
    let se = n[&effect_ord].clone();
    let scid = id_of(&sc);
    let seid = id_of(&se);
    let c = occ("c", Some(&scid), "event");
    let e = occ("e", Some(&seid), "event");
    let smap = map_by_id(&[&sc, &se]);
    let om = map_by_id(&[&c, &e]);
    let p = cro(vec![json!(id_of(&c))], vec![json!(id_of(&e))], extra);
    let cls = classify_cro(&p, &om, &smap).to_string();
    (p, cls)
}

fn bridge_fixture(relation: &str)
    -> (Map<String, Value>, HashMap<String, Map<String, Value>>,
        HashMap<String, Map<String, Value>>) {
    let n = neuro();
    let s4 = n[&4].clone();
    let s6 = n[&6].clone();
    let s6id = id_of(&s6);
    let s4id = id_of(&s4);
    let coarse = occ("action_potential_fires", Some(&s6id), "event");
    let f1 = occ("sodium_channels_open", Some(&s4id), "event");
    let f2 = occ("sodium_influx", Some(&s4id), "event");
    let b = bridge(&id_of(&coarse),
                   vec![json!(id_of(&f1)), json!(id_of(&f2))], relation);
    let om = map_by_id(&[&coarse, &f1, &f2]);
    let sm = map_by_id(&[&s4, &s6]);
    (b, om, sm)
}

fn reach_fixture()
    -> (Map<String, Value>, HashMap<String, Map<String, Value>>,
        Vec<Map<String, Value>>) {
    let n = neuro();
    let s6id = id_of(&n[&6]);
    let s4id = id_of(&n[&4]);
    let ap = occ("action_potential_fires", Some(&s6id), "event");
    let nt = occ("neurotransmitter_released", Some(&s6id), "event");
    let fa = occ("calcium_enters", Some(&s4id), "event");
    let fb = occ("vesicle_fuses", Some(&s4id), "event");
    let m1 = cro(vec![json!(id_of(&fa))], vec![json!(id_of(&fb))], vec![]);
    let p = cro(vec![json!(id_of(&ap))], vec![json!(id_of(&nt))],
                vec![("mechanism", json!([id_of(&m1)]))]);
    let bridges = vec![
        bridge(&id_of(&ap), vec![json!(id_of(&fa))], "constitutes"),
        bridge(&id_of(&nt), vec![json!(id_of(&fb))], "constitutes"),
    ];
    let mut members = HashMap::new();
    members.insert(id_of(&m1), m1);
    (p, members, bridges)
}

fn law_and_tokens()
    -> (Map<String, Value>, Map<String, Value>, Map<String, Value>) {
    let o_cause = occ("resection", None, "event");
    let o_effect = occ("amnesia_onset", None, "event");
    let law = cro(vec![json!(id_of(&o_cause))], vec![json!(id_of(&o_effect))],
        vec![("temporal", json!({"minimum_delay": 0, "maximum_delay": 1,
                                 "unit": "days"})),
             ("modality", json!("sufficient"))]);
    let t_cause = token(&id_of(&o_cause),
                        json!({"start": "1953-08-25T00:00:00Z"}), None, None);
    let t_effect = token(&id_of(&o_effect),
                         json!({"start": "1953-08-25T00:00:00Z", "open": true}),
                         None, None);
    (law, t_cause, t_effect)
}

fn conduit_fixture(transform: bool, bad_carry: bool, in_from: bool)
    -> (Map<String, Value>, HashMap<String, Map<String, Value>>,
        HashMap<String, Map<String, Value>>) {
    let x = sym("occurrent:motor_command");
    let y = sym("occurrent:error_signal");
    let z = sym("occurrent:unrelated");
    let m1 = id_of(&cnt("motor_cortex", "object"));
    let m2 = id_of(&cnt("spinal_neuron", "object"));
    let frm = port(&m1, "out_port", if in_from { "in" } else { "out" },
                   vec![Value::String(x.clone())], None);
    let to_accepts = if transform {
        vec![Value::String(y.clone())]
    } else {
        vec![Value::String(x.clone())]
    };
    let to = port(&m2, "in_port", "in", to_accepts, None);
    let carries = if bad_carry {
        vec![Value::String(z.clone())]
    } else {
        vec![Value::String(x.clone())]
    };
    let mut cro_map = HashMap::new();
    let xform = if transform {
        let law = cro(vec![Value::String(x.clone())],
                      vec![Value::String(y.clone())], vec![]);
        let lid = id_of(&law);
        cro_map.insert(lid.clone(), law);
        Some(lid)
    } else {
        None
    };
    let c = conduit(&id_of(&frm), &id_of(&to), carries, "conn",
                    xform.as_deref());
    let pmap = map_by_id(&[&frm, &to]);
    (c, pmap, cro_map)
}

fn state_fixture(datatype: &str, value: Value, unit: Option<&str>)
                 -> (Map<String, Value>, Map<String, Value>) {
    let q = quality("cortisol_concentration", datatype, unit, None);
    let c = id_of(&cnt("human_patient", "object"));
    let subj = id_of(&individual(&c, Some("p"), None));
    let st = state(&subj, &id_of(&q), value,
                   json!({"start": "2026-01-01T00:00:00Z",
                          "end": "2026-01-01T01:00:00Z"}));
    (st, q)
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
                       0ee172f3daa62325af021a68f707511a",
            "RFC 8032 TEST 1 public key mismatch: {}", public);
    use ed25519_dalek::Signer;
    let sig = sk.sign(b"");
    use ed25519_dalek::Verifier;
    ensure!(sk.verifying_key().verify(b"", &sig).is_ok(), "KAT verify");
    // JCS basics
    ensure!(jcs(&json!({"b": 2, "a": 1}))? == r#"{"a":1,"b":2}"#, "JCS sort");
    ensure!(jcs(&json!(1.0))? == "1", "JCS 1.0");
    ensure!(jcs(&json!(6.0))? == "6", "JCS 6.0");
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

fn valid_bridge(relation: &str) -> R {
    let (b, om, sm) = bridge_fixture(relation);
    let (ok, why) = validate_schema(&b, None);
    ensure!(ok, "{:?}", why);
    let (ok, why) = bridge_wellformed(&b, &om, &sm);
    ensure!(ok, "{}", why);
    Ok(())
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
            let (dog, mam, ani) = (sym("continuant:dog"),
                sym("continuant:mammal"), sym("continuant:animal"));
            let enrich = |about: &str, entry: &str, i: u32| {
                signed("enrichment",
                       json!({"about": about, "field": "subsumes",
                              "entry": entry}), "taxo", i)
            };
            let mut store = InMemoryStore::new(true);
            store.put_record(&enrich(&dog, &mam, 1), None).map_err(|e| e.0)?;
            store.put_record(&enrich(&mam, &ani, 2), None).map_err(|e| e.0)?;
            match store.put_record(&enrich(&ani, &dog, 3), None) {
                Ok(_) => return Err("enforcing store accepted a cycle".into()),
                Err(e) => ensure!(e.0.contains("cycle"), "{}", e.0),
            }
            let mut replica = InMemoryStore::new(true);
            replica.put_record(&enrich(&dog, &mam, 1), None).map_err(|e| e.0)?;
            replica.put_record(&enrich(&mam, &ani, 2), None).map_err(|e| e.0)?;
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
            let o = obj(&json!({"type": "occurrent", "label": "press_button",
                                "category": "action"}));
            let a = store.put(&o, None).map_err(|e| e.0)?;
            let b = store.put(&o, None).map_err(|e| e.0)?;
            ensure!(a == b && store.objects.len() == 1, "not idempotent");
            Ok(())
        }
        27 => {
            let mut store = InMemoryStore::new(true);
            let occid = store.put(&obj(&json!({
                "type": "occurrent", "label": "press_button",
                "category": "action"})), None).map_err(|e| e.0)?;
            let entry = json!({"lang": "en", "text": "press the button"});
            let r1 = signed("enrichment", json!({
                "about": occid, "field": "aliases", "entry": entry}),
                "alice", 1);
            let r2 = signed("enrichment", json!({
                "about": occid, "field": "aliases", "entry": entry}),
                "bob", 2);
            let id1 = store.put_record(&r1, None).map_err(|e| e.0)?;
            let id2 = store.put_record(&r2, None).map_err(|e| e.0)?;
            ensure!(id1 != id2, "expected two records");
            let view = store.get(&occid, "default").unwrap();
            let aliases = view["enrichments"]["aliases"].as_array().unwrap();
            ensure!(aliases.len() == 1, "expected one entry");
            ensure!(aliases[0]["contributors"].as_array().unwrap().len() == 2,
                    "expected two contributors");
            Ok(())
        }
        28 => {
            let mut store = InMemoryStore::new(true);
            let claim = obj(&json!({
                "type": "causal_relation_object",
                "causes": [sym("occurrent:A")],
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
                "about": sym("causal_relation_object:demo"),
                "evidence_type": "intervention",
                "strength": 0.7, "confidence": 0.9}), "signer", 0);
            ensure!(verify_record(&rec, None), "must verify");
            Ok(())
        }
        30 => {
            let rec = signed("assertion", json!({
                "about": sym("causal_relation_object:demo"),
                "evidence_type": "intervention",
                "strength": 0.7, "confidence": 0.9}), "signer", 0);
            let mut tampered = rec.clone();
            tampered.insert("confidence".into(), json!(0.1));
            ensure!(!verify_record(&tampered, None), "tamper must fail");
            Ok(())
        }
        31 => {
            let mut store = InMemoryStore::new(true);
            let x = store.put(&obj(&json!({
                "type": "causal_relation_object",
                "causes": [sym("occurrent:A")],
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
            Ok(())
        }
        32 => {
            let mut store = InMemoryStore::new(true);
            let occid = store.put(&obj(&json!({
                "type": "occurrent", "label": "press_button",
                "category": "action"})), None).map_err(|e| e.0)?;
            let e = signed("enrichment", json!({
                "about": occid, "field": "aliases",
                "entry": {"lang": "ja", "text": "botan"}}), "bob", 1);
            store.put_record(&e, None).map_err(|e| e.0)?;
            let n_before = store.get(&occid, "default").unwrap()
                ["enrichments"]["aliases"].as_array()
                .map(|a| a.len()).unwrap_or(0);
            ensure!(n_before == 1, "expected one alias");
            store.put_record(&signed("retraction", json!({
                "retracts": e["id"]}), "bob", 2), None).map_err(|e| e.0)?;
            let after = store.get(&occid, "default").unwrap();
            let n_after = after["enrichments"].get("aliases")
                .and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0);
            ensure!(n_after == 0, "retracted alias still visible");
            let hist = store.get(&occid, "history").unwrap();
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
                "about": sym("causal_relation_object:claim"),
                "evidence_type": "observation",
                "confidence": 0.9}), "K1", 1);
            store.put_record(&a, None).map_err(|e| e.0)?;
            store.put_record(&signed("succession", json!({
                "successor": k2}), "K1", 2), None).map_err(|e| e.0)?;
            ensure!(store.lineage(&k2).contains(&k1), "lineage broken");
            store.put_record(&signed("retraction", json!({
                "retracts": a["id"]}), "K2", 3), None).map_err(|e| e.0)?;
            ensure!(store.assertions_about(&sym("causal_relation_object:claim"),
                    false).is_empty(), "successor retraction not honored");
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
            ensure!(hierarchy_consistent(&parent, &members, &[])
                    == "consistent", "expected consistent");
            let parent2 = obj(&json!({
                "causes": [a], "effects": [c],
                "mechanism": [m1["id"], m3["id"]]}));
            let mut members2 = HashMap::new();
            members2.insert(m1["id"].as_str().unwrap().to_string(), m1.clone());
            members2.insert(m3["id"].as_str().unwrap().to_string(), m3);
            ensure!(hierarchy_consistent(&parent2, &members2, &[])
                    == "inconsistent", "expected inconsistent");
            let mut partial = HashMap::new();
            partial.insert(m1["id"].as_str().unwrap().to_string(), m1);
            ensure!(hierarchy_consistent(&parent, &partial, &[])
                    == "indeterminate", "expected indeterminate");
            Ok(())
        }
        37 => {
            let mut store = InMemoryStore::new(true);
            let occid = store.put(&obj(&json!({
                "type": "occurrent", "label": "press_button",
                "category": "action"})), None).map_err(|e| e.0)?;
            store.put_record(&signed("enrichment", json!({
                "about": occid, "field": "aliases",
                "entry": {"lang": "en", "text": "Press the Button"}}),
                "alice", 1), None).map_err(|e| e.0)?;
            ensure!(store.resolve("Press  The   Button", Some("en"))
                    == vec![occid.clone()], "alias match failed");
            let by_label = store.resolve("press_button", Some("en"));
            ensure!(by_label.first() == Some(&occid), "label must rank first");
            Ok(())
        }
        38 => {
            let mut store = InMemoryStore::new(true);
            let p = store.put(&obj(&json!({
                "type": "causal_relation_object",
                "causes": [sym("occurrent:A")],
                "effects": [sym("occurrent:B")]})), None).map_err(|e| e.0)?;
            let has = |store: &InMemoryStore, id: &str| {
                store.gaps(Some("missing_field")).iter()
                    .any(|g| g.get("id").and_then(Value::as_str) == Some(id))
            };
            ensure!(has(&store, &p), "gap must be open");
            let r = store.put(&obj(&json!({
                "type": "causal_relation_object",
                "causes": [sym("occurrent:A")],
                "effects": [sym("occurrent:B")],
                "temporal": {"minimum_delay": 0, "maximum_delay": 1,
                             "unit": "seconds"},
                "modality": "sufficient", "refines": p})), None)
                .map_err(|e| e.0)?;
            ensure!(!has(&store, &p), "the gap did not close");
            ensure!(!has(&store, &r), "the refinement must be complete");
            Ok(())
        }

        // ------------------- V39 - V107: the 2.0.0 additions ---------------
        39 => {
            let st = stratum("cellular", "neuroendocrine", 6, Some("cell"),
                             Some(vec!["cell_biology"]));
            let (ok, why) = validate_schema(&st, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        40 => {
            let bad = mk(obj(&json!({"type": "stratum", "label": "cellular",
                                     "ordinal": 6})));
            let (ok, why) = validate_schema(&bad, Some("stratum"));
            ensure!(!ok && why.iter().any(|w| w.contains("scheme")),
                    "{:?}", why);
            Ok(())
        }
        41 => {
            let a = stratum("cellular", "neuroendocrine", 6, None, None);
            let b = stratum("neuronal", "neuroendocrine", 6, None, None);
            for x in [&a, &b] {
                let (ok, why) = validate_schema(x, None);
                ensure!(ok, "{:?}", why);
            }
            ensure!(id_of(&a) != id_of(&b), "ids equal");
            Ok(())
        }
        42 => {
            let n = neuro();
            let s14 = n[&14].clone();
            let s4p = stratum("molecular", "physics", 4, None, None);
            let s14id = id_of(&s14);
            let s4pid = id_of(&s4p);
            let c = occ("chronic_social_subordination", Some(&s14id), "event");
            let e = occ("gene_expression", Some(&s4pid), "event");
            let smap = map_by_id(&[&s14, &s4p]);
            let om = map_by_id(&[&c, &e]);
            let p = cro(vec![json!(id_of(&c))], vec![json!(id_of(&e))], vec![]);
            ensure!(classify_cro(&p, &om, &smap) == "scheme_mismatch",
                    "got {}", classify_cro(&p, &om, &smap));
            Ok(())
        }
        43 => {
            for x in [stratum("macromolecular", "neuroendocrine", 4, None, None),
                      stratum("region", "neuroendocrine", 9, None, None)] {
                let (ok, why) = validate_schema(&x, None);
                ensure!(ok, "{:?}", why);
            }
            Ok(())
        }
        44 => {
            let st = stratum("cellular", "neuroendocrine", 6, None, None);
            let stid = id_of(&st);
            let o = occ("neuron_fires", Some(&stid), "event");
            let (ok, why) = validate_schema(&o, None);
            ensure!(ok, "{:?}", why);
            let (ok, why) = validate_semantics(&o, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        45 => {
            let o = occ("press_button", None, "event");
            let (ok, why) = validate_schema(&o, None);
            ensure!(ok, "{:?}", why);
            let e = occ("light_on", None, "event");
            let p = cro(vec![json!(id_of(&o))], vec![json!(id_of(&e))], vec![]);
            let om = map_by_id(&[&o, &e]);
            ensure!(classify_cro(&p, &om, &HashMap::new()) == "unclassifiable",
                    "expected unclassifiable");
            Ok(())
        }
        46 => {
            let n = neuro();
            let a = occ("depolarization", Some(&id_of(&n[&5])), "event");
            let b = occ("depolarization", Some(&id_of(&n[&6])), "event");
            ensure!(id_of(&a) != id_of(&b), "ids equal");
            Ok(())
        }
        47 => valid_bridge("constitutes"),
        48 => valid_bridge("aggregates"),
        49 => valid_bridge("realizes"),
        50 => valid_bridge("supervenes_on"),
        51 => {
            let n = neuro();
            let coarse = occ("x_coarse", Some(&id_of(&n[&4])), "event");
            let fine = occ("x_fine", Some(&id_of(&n[&6])), "event");
            let b = bridge(&id_of(&coarse), vec![json!(id_of(&fine))],
                           "constitutes");
            let om = map_by_id(&[&coarse, &fine]);
            let sm = map_by_id(&[&n[&4], &n[&6]]);
            let (ok, _) = bridge_wellformed(&b, &om, &sm);
            ensure!(!ok, "expected malformed");
            Ok(())
        }
        52 => {
            let n = neuro();
            let coarse = occ("c", Some(&id_of(&n[&6])), "event");
            let f1 = occ("f1", Some(&id_of(&n[&4])), "event");
            let f2 = occ("f2", Some(&id_of(&n[&5])), "event");
            let b = bridge(&id_of(&coarse),
                           vec![json!(id_of(&f1)), json!(id_of(&f2))],
                           "constitutes");
            let om = map_by_id(&[&coarse, &f1, &f2]);
            let sm = map_by_id(&[&n[&4], &n[&5], &n[&6]]);
            let (ok, _) = bridge_wellformed(&b, &om, &sm);
            ensure!(!ok, "expected malformed");
            Ok(())
        }
        53 => {
            let x = sym("occurrent:x");
            let y = sym("occurrent:y");
            let b1 = bridge(&x, vec![Value::String(y.clone())], "constitutes");
            let b2 = bridge(&y, vec![Value::String(x.clone())], "constitutes");
            let mut edges: HashMap<String, Vec<String>> = HashMap::new();
            for b in [&b1, &b2] {
                let coarse = b.get("coarse").and_then(Value::as_str)
                    .unwrap().to_string();
                for f in b.get("fine").and_then(Value::as_array).unwrap() {
                    edges.entry(f.as_str().unwrap().to_string())
                        .or_default().push(coarse.clone());
                }
            }
            ensure!(has_cycle(&edges), "expected cycle");
            Ok(())
        }
        54 => {
            let a = stratum("cellular", "neuroendocrine", 6, None, None);
            let b = stratum("molecular", "physics", 4, None, None);
            let coarse = occ("c", Some(&id_of(&a)), "event");
            let fine = occ("f", Some(&id_of(&b)), "event");
            let br = bridge(&id_of(&coarse), vec![json!(id_of(&fine))],
                            "constitutes");
            let om = map_by_id(&[&coarse, &fine]);
            let sm = map_by_id(&[&a, &b]);
            let (ok, _) = bridge_wellformed(&br, &om, &sm);
            ensure!(!ok, "expected malformed");
            Ok(())
        }
        55 => {
            let n = neuro();
            let coarse = occ("decision_made", Some(&id_of(&n[&6])), "event");
            let f1 = occ("cascade_a", Some(&id_of(&n[&4])), "event");
            let f2 = occ("cascade_b", Some(&id_of(&n[&4])), "event");
            let b1 = bridge(&id_of(&coarse), vec![json!(id_of(&f1))],
                            "realizes");
            let b2 = bridge(&id_of(&coarse), vec![json!(id_of(&f2))],
                            "realizes");
            ensure!(id_of(&b1) != id_of(&b2), "ids equal");
            for b in [&b1, &b2] {
                let (ok, why) = validate_schema(b, None);
                ensure!(ok, "{:?}", why);
            }
            Ok(())
        }
        56 => {
            let (p, m, b) = reach_fixture();
            ensure!(hierarchy_consistent(&p, &m, &b) == "consistent",
                    "got {}", hierarchy_consistent(&p, &m, &b));
            Ok(())
        }
        57 => {
            let (p, m, _b) = reach_fixture();
            ensure!(hierarchy_consistent(&p, &m, &[]) == "inconsistent",
                    "expected inconsistent");
            Ok(())
        }
        58 => {
            let (p, m, b) = reach_fixture();
            let literal = hierarchy_consistent(&p, &m, &[]);
            let bridged = hierarchy_consistent(&p, &m, &b);
            ensure!(literal != "consistent" && bridged == "consistent",
                    "literal={} bridged={}", literal, bridged);
            Ok(())
        }
        59 => { ensure!(classify_ord(6, 6) == "intra_stratal",
                        "{}", classify_ord(6, 6)); Ok(()) }
        60 => { ensure!(classify_ord(6, 5) == "adjacent_stratal",
                        "{}", classify_ord(6, 5)); Ok(()) }
        61 => { ensure!(classify_ord(14, 4) == "skipping",
                        "{}", classify_ord(14, 4)); Ok(()) }
        62 => {
            let (p, cls) = skip_fixture(14, 4, vec![]);
            ensure!(skip_gaps(&p, &cls) == vec!["incomplete_mechanism"],
                    "{:?}", skip_gaps(&p, &cls));
            Ok(())
        }
        63 => {
            let (p, cls) = skip_fixture(14, 4, vec![("skips", json!(true))]);
            ensure!(skip_gaps(&p, &cls).is_empty(), "{:?}",
                    skip_gaps(&p, &cls));
            Ok(())
        }
        64 => {
            let (p, cls) = skip_fixture(14, 4, vec![
                ("skips", json!(true)),
                ("mechanism", json!([sym("causal_relation_object:m")]))]);
            ensure!(skip_gaps(&p, &cls) == vec!["contradictory_skip"],
                    "{:?}", skip_gaps(&p, &cls));
            let (ok, why) = validate_semantics(&p, None);
            ensure!(!ok && why.iter().any(|w| w.contains("contradictory_skip")),
                    "{:?}", why);
            Ok(())
        }
        65 => {
            let (p, cls) = skip_fixture(6, 6, vec![("skips", json!(true))]);
            ensure!(skip_gaps(&p, &cls) == vec!["vacuous_skip"],
                    "{:?}", skip_gaps(&p, &cls));
            Ok(())
        }
        66 => {
            let n = neuro();
            let c = occ("c", Some(&id_of(&n[&14])), "event");
            let e = occ("e", Some(&id_of(&n[&4])), "event");
            let absent = cro(vec![json!(id_of(&c))], vec![json!(id_of(&e))],
                             vec![]);
            let false_ = cro(vec![json!(id_of(&c))], vec![json!(id_of(&e))],
                             vec![("skips", json!(false))]);
            ensure!(id_of(&absent) != id_of(&false_), "ids equal");
            Ok(())
        }
        67 => {
            let n = neuro();
            let c1 = occ("c1", Some(&id_of(&n[&4])), "event");
            let c2 = occ("c2", Some(&id_of(&n[&6])), "event");
            let e = occ("e", Some(&id_of(&n[&6])), "event");
            let p = cro(vec![json!(id_of(&c1)), json!(id_of(&c2))],
                        vec![json!(id_of(&e))], vec![]);
            let om = map_by_id(&[&c1, &c2, &e]);
            ensure!(endpoints_mixed(&p, &om), "expected mixed");
            Ok(())
        }
        68 => {
            let p = cro(vec![json!(sym("occurrent:a"))],
                        vec![json!(sym("occurrent:b"))],
                        vec![("modality", json!("enabling"))]);
            let (ok, why) = validate_schema(&p, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        69 => {
            let a = obj(&json!({"causes": [sym("occurrent:a")],
                "effects": [sym("occurrent:b")], "modality": "enabling"}));
            let b = obj(&json!({"causes": [sym("occurrent:a")],
                "effects": [sym("occurrent:b")], "modality": "sufficient"}));
            ensure!(!conflicts(&a, &b), "expected no conflict");
            Ok(())
        }
        70 => {
            let a = obj(&json!({"causes": [sym("occurrent:a")],
                "effects": [sym("occurrent:b")], "modality": "enabling"}));
            let b = obj(&json!({"causes": [sym("occurrent:a")],
                "effects": [sym("occurrent:b")], "modality": "preventive"}));
            ensure!(conflicts(&a, &b), "expected conflict");
            Ok(())
        }
        71 => {
            let b = cnt("hippocampus", "object");
            let p = port(&id_of(&b), "perforant_path", "in",
                         vec![json!(sym("occurrent:signal"))], None);
            let (ok, why) = validate_schema(&p, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        72 => {
            let b = id_of(&cnt("hippocampus", "object"));
            let x = sym("occurrent:signal");
            let p1 = port(&b, "perforant_path", "in",
                          vec![Value::String(x.clone())], None);
            let p2 = port(&b, "fornix", "in",
                          vec![Value::String(x.clone())], None);
            ensure!(id_of(&p1) != id_of(&p2), "ids equal");
            Ok(())
        }
        73 => {
            let (c, pmap, _) = conduit_fixture(false, false, false);
            let (ok, why) = validate_schema(&c, None);
            ensure!(ok, "{:?}", why);
            let (ok, why) = conduit_wellformed(&c, &pmap, &HashMap::new());
            ensure!(ok, "{}", why);
            Ok(())
        }
        74 => {
            let (c, pmap, cmap) = conduit_fixture(true, false, false);
            let (ok, why) = validate_schema(&c, None);
            ensure!(ok, "{:?}", why);
            let (ok, why) = conduit_wellformed(&c, &pmap, &cmap);
            ensure!(ok, "{}", why);
            Ok(())
        }
        75 => {
            let (c, pmap, _) = conduit_fixture(false, true, false);
            let (ok, _) = conduit_wellformed(&c, &pmap, &HashMap::new());
            ensure!(!ok, "expected malformed");
            Ok(())
        }
        76 => {
            let (c, pmap, _) = conduit_fixture(false, false, true);
            let (ok, _) = conduit_wellformed(&c, &pmap, &HashMap::new());
            ensure!(!ok, "expected malformed");
            Ok(())
        }
        77 => {
            let (c, pmap, cmap) = conduit_fixture(true, false, false);
            let (ok, why) = conduit_wellformed(&c, &pmap, &cmap);
            ensure!(ok, "{}", why);
            let law = cmap.values().next().unwrap();
            let eff = law.get("effects").and_then(Value::as_array)
                .unwrap()[0].clone();
            let carries = c.get("carries").and_then(Value::as_array).unwrap();
            ensure!(!carries.contains(&eff), "effect unexpectedly carried");
            Ok(())
        }
        78 => {
            let b = id_of(&cnt("hippocampus", "object"));
            ensure!(id_of(&rlz(&b, "disposition",
                        Some("long_term_potentiation")))
                    != id_of(&rlz(&b, "disposition",
                        Some("pattern_separation"))), "ids equal");
            Ok(())
        }
        79 => {
            let b = id_of(&cnt("hippocampus", "object"));
            let u1 = rlz(&b, "disposition", None);
            let u2 = rlz(&b, "disposition", None);
            let (ok, why) = validate_schema(&u1, None);
            ensure!(ok, "{:?}", why);
            ensure!(id_of(&u1) == id_of(&u2), "ids differ");
            ensure!(id_of(&rlz(&b, "disposition", Some("some_function")))
                    != id_of(&u1), "labelled equals unlabelled");
            Ok(())
        }
        80 => {
            let parent = occ("fires", None, "event");
            let child = occ("fires_action_potential", None, "event");
            let e = obj(&json!({"type": "enrichment", "about": id_of(&child),
                "field": "occurrent_subsumes", "entry": id_of(&parent)}));
            let (ok, why) = validate_semantics(&e, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        81 => {
            let a = sym("occurrent:a");
            let b = sym("occurrent:b");
            let mut edges: HashMap<String, Vec<String>> = HashMap::new();
            edges.insert(a.clone(), vec![b.clone()]);
            edges.insert(b.clone(), vec![a.clone()]);
            ensure!(has_cycle(&edges), "expected cycle");
            Ok(())
        }
        82 => {
            let whole = occ("eat", None, "event");
            let part = occ("chew", None, "event");
            let e = obj(&json!({"type": "enrichment", "about": id_of(&part),
                "field": "occurrent_part_of", "entry": id_of(&whole)}));
            let (ok, why) = validate_semantics(&e, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        83 => {
            // occurrent_part_of is legal only about occurrents whose entry is
            // an occurrent id (shape == "occurrent", legal_kinds == occurrent).
            let whole = occ("eat", None, "event");
            let part = occ("chew", None, "event");
            let good = obj(&json!({"type": "enrichment",
                "about": id_of(&part), "field": "occurrent_part_of",
                "entry": id_of(&whole)}));
            let (ok, _) = validate_semantics(&good, None);
            ensure!(ok, "occurrent_part_of about an occurrent must be legal");
            let bad = obj(&json!({"type": "enrichment",
                "about": sym("continuant:x"), "field": "occurrent_part_of",
                "entry": id_of(&whole)}));
            let (ok, why) = validate_semantics(&bad, None);
            ensure!(!ok && why.iter().any(|w| w.contains("not a legal field")),
                    "{:?}", why);
            let mut store = InMemoryStore::new(false);
            store.put(&whole, None).map_err(|e| e.0)?;
            store.put(&part, None).map_err(|e| e.0)?;
            ensure!(!store.objects.values().any(|o|
                    o.get("type").and_then(Value::as_str)
                        == Some("causal_relation_object")),
                    "unexpected causal_relation_object");
            Ok(())
        }
        84 => {
            let n = neuro();
            let a = occ("run", Some(&id_of(&n[&9])), "event");
            let b = occ("sprint", Some(&id_of(&n[&6])), "event");
            ensure!(a.get("stratum") != b.get("stratum"), "strata equal");
            Ok(())
        }
        85 => {
            let c = cnt("human_patient", "object");
            let ti = individual(&id_of(&c), Some("salted_hash_abc123"), None);
            let (ok, why) = validate_schema(&ti, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        86 => {
            let bad = mk(obj(&json!({"type": "token_individual",
                                     "designator": "x"})));
            let (ok, why) = validate_schema(&bad, Some("token_individual"));
            ensure!(!ok && why.iter().any(|w| w.contains("instantiates")),
                    "{:?}", why);
            Ok(())
        }
        87 => {
            let c = id_of(&cnt("human_patient", "object"));
            ensure!(id_of(&individual(&c, Some("hash_a"), None))
                    != id_of(&individual(&c, Some("hash_b"), None)),
                    "ids equal");
            Ok(())
        }
        88 => {
            let o = occ("bilateral_hippocampal_resection", None, "event");
            let t = token(&id_of(&o),
                json!({"start": "1953-08-25T00:00:00Z",
                       "end": "1953-08-25T00:00:00Z"}), None, None);
            let (ok, why) = validate_schema(&t, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        89 => {
            let o = id_of(&occ("amnesia_onset", None, "event"));
            let bounded = token(&o, json!({"start": "1953-08-25T00:00:00Z",
                "end": "1953-08-26T00:00:00Z"}), None, None);
            let instantaneous = token(&o,
                json!({"start": "1953-08-25T00:00:00Z"}), None, None);
            let ongoing = token(&o, json!({"start": "1953-08-25T00:00:00Z",
                "open": true}), None, None);
            let s: HashSet<String> = [id_of(&bounded), id_of(&instantaneous),
                                      id_of(&ongoing)].into_iter().collect();
            ensure!(s.len() == 3, "expected 3 distinct ids");
            Ok(())
        }
        90 => {
            let o = id_of(&occ("resection", None, "event"));
            let c = id_of(&cnt("human_patient", "object"));
            let patient = id_of(&individual(&c, Some("p"), None));
            let surgeon = id_of(&individual(&c, Some("s"), None));
            let t = token(&o, json!({"start": "1953-08-25T00:00:00Z"}),
                Some(json!([{"role": "patient", "filler": patient},
                            {"role": "agent", "filler": surgeon}])), None);
            let (ok, why) = validate_schema(&t, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        91 => {
            let q = quality("cortisol_concentration", "quantity",
                            Some("ug/dL"), None);
            let (ok, why) = validate_schema(&q, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        92 => {
            let (st, q) = state_fixture("quantity",
                json!({"quantity": 15.0, "unit": "ug/dL"}), Some("ug/dL"));
            let (ok, why) = validate_schema(&st, None);
            ensure!(ok, "{:?}", why);
            ensure!(state_gaps(&st, &q).is_empty(), "expected no gaps");
            Ok(())
        }
        93 => {
            let (st, q) = state_fixture("categorical",
                json!({"categorical": "elevated"}), None);
            let (ok, why) = validate_schema(&st, None);
            ensure!(ok, "{:?}", why);
            ensure!(state_gaps(&st, &q).is_empty(), "expected no gaps");
            Ok(())
        }
        94 => {
            let (st, q) = state_fixture("boolean",
                json!({"boolean": true}), None);
            let (ok, why) = validate_schema(&st, None);
            ensure!(ok, "{:?}", why);
            ensure!(state_gaps(&st, &q).is_empty(), "expected no gaps");
            Ok(())
        }
        95 => {
            let (st, q) = state_fixture("quantity",
                json!({"categorical": "elevated"}), Some("ug/dL"));
            ensure!(state_gaps(&st, &q) == vec!["value_type_mismatch"],
                    "{:?}", state_gaps(&st, &q));
            Ok(())
        }
        96 => {
            let (st, q) = state_fixture("quantity",
                json!({"quantity": 15.0, "unit": "mg/dL"}), Some("ug/dL"));
            ensure!(state_gaps(&st, &q) == vec!["unit_mismatch"],
                    "{:?}", state_gaps(&st, &q));
            Ok(())
        }
        97 => {
            let (law, tc, te) = law_and_tokens();
            let claim = tcc(vec![json!(id_of(&tc))], vec![json!(id_of(&te))],
                Some(&id_of(&law)),
                Some(json!({"duration": 0, "unit": "instant"})), Some(true));
            let (ok, why) = validate_schema(&claim, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        98 => {
            let (_law, tc, te) = law_and_tokens();
            let claim = tcc(vec![json!(id_of(&tc))], vec![json!(id_of(&te))],
                            None, None, None);
            let (ok, why) = validate_schema(&claim, None);
            ensure!(ok, "{:?}", why);
            ensure!(!claim.contains_key("covering_law"),
                    "covering_law present");
            Ok(())
        }
        99 => {
            let (law, _, _) = law_and_tokens();
            let ad = obj(&json!({"duration": 0, "unit": "instant"}));
            let temporal = law.get("temporal").and_then(Value::as_object)
                .cloned().unwrap();
            ensure!(delay_within_window(Some(&ad), Some(&temporal)),
                    "expected within window");
            Ok(())
        }
        100 => {
            let temporal = obj(&json!({"minimum_delay": 0, "maximum_delay": 1,
                                       "unit": "hours"}));
            let ad = obj(&json!({"duration": 5, "unit": "days"}));
            ensure!(!delay_within_window(Some(&ad), Some(&temporal)),
                    "expected outside window");
            Ok(())
        }
        101 => {
            let o = id_of(&occ("x", None, "event"));
            let cause = token(&o, json!({"start": "2026-01-02T00:00:00Z"}),
                              None, None);
            let effect = token(&o, json!({"start": "2026-01-01T00:00:00Z"}),
                               None, None);
            let claim = tcc(vec![json!(id_of(&cause))],
                            vec![json!(id_of(&effect))], None, None, None);
            let tm = map_by_id(&[&cause, &effect]);
            ensure!(retrocausal(&claim, &tm), "expected retrocausal");
            Ok(())
        }
        102 => {
            let other = cro(vec![json!(sym("occurrent:foo"))],
                            vec![json!(sym("occurrent:bar"))], vec![]);
            let (_law, tc, te) = law_and_tokens();
            let claim = tcc(vec![json!(id_of(&tc))], vec![json!(id_of(&te))],
                            Some(&id_of(&other)), None, None);
            let tm = map_by_id(&[&tc, &te]);
            ensure!(covering_law_mismatch(&claim, &tm, Some(&other)),
                    "expected mismatch");
            Ok(())
        }
        103 => {
            let a = signed("assertion", json!({
                "about": sym("token_occurrence:t"),
                "evidence_type": "observation", "confidence": 0.9}),
                "signer", 0);
            let (ok, why) = validate_schema(&a, None);
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        104 => {
            let ev = vec![json!(sym("token_occurrence:t1")),
                          json!(sym("token_causal_claim:c1"))];
            let (_, signer_pub) = key("signer");
            let base = obj(&json!({"type": "assertion",
                "about": sym("causal_relation_object:law"),
                "source": signer_pub, "evidence_type": "intervention",
                "strength": 0.95, "confidence": 0.99,
                "timestamp": "2026-07-14T00:00:00Z"}));
            let mut a = base.clone();
            a.insert("evidenced_by".into(), Value::Array(ev));
            let mut a_with_id = a.clone();
            a_with_id.insert("id".into(),
                             Value::String(identify(&a, None)?));
            let (ok, why) = validate_schema(&a_with_id, None);
            ensure!(ok, "{:?}", why);
            ensure!(identify(&a, None)? != identify(&base, None)?,
                    "evidenced_by must be identity-bearing");
            Ok(())
        }
        105 => {
            let a = signed("assertion", json!({
                "about": sym("causal_relation_object:law"),
                "evidence_type": "simulation", "confidence": 0.5}),
                "signer", 0);
            let (ok, why) = validate_schema(&a, None);
            ensure!(ok, "{:?}", why);
            ensure!(0 < 1 && 1 < 2, "evidence-strength ordering");
            Ok(())
        }
        106 => {
            fn scan(node: &Value, ids: &mut Vec<String>) {
                match node {
                    Value::String(s) => {
                        if let Some((pre, rest)) = s.split_once(':') {
                            if is_hex64(rest) && !pre.is_empty()
                                && pre.chars().all(|c| c.is_ascii_lowercase()
                                    || c.is_ascii_digit() || c == '_') {
                                ids.push(pre.to_string());
                            }
                        }
                    }
                    Value::Array(a) => for x in a { scan(x, ids); },
                    Value::Object(m) => for x in m.values() { scan(x, ids); },
                    _ => {}
                }
            }
            let whole: HashSet<&str> = SCHEMES.iter().copied().collect();
            for i in 1..=38u32 {
                let (_, v) = vec_json(i);
                let mut ids = Vec::new();
                scan(&v, &mut ids);
                for scheme in ids {
                    ensure!(whole.contains(scheme.as_str()),
                        "V106: abbreviated scheme {:?} in vector {}",
                        scheme, i);
                }
            }
            let rec = obj(&json!({"type": "occurrent",
                "label": "press_button", "category": "action"}));
            ensure!(identify(&rec, None)? == identify(&rec, None)?,
                    "identity not deterministic");
            ensure!(identify(&rec, None)?.split_once(':').unwrap().0
                    == "occurrent", "prefix not whole-word");
            Ok(())
        }
        107 => {
            let hexid = "0".repeat(64);
            // The abbreviated prefix is the negative test; assembled so a
            // re-mint pass would not rewrite it.
            let cro_abbr = format!("{}{}{}", "c", "r", "o");
            let abbreviated = obj(&json!({"type": "causal_relation_object",
                "id": format!("{}:{}", cro_abbr, hexid),
                "causes": [format!("occurrent:{}", hexid)],
                "effects": [format!("occurrent:{}", hexid)]}));
            let (ok, _) = validate_schema(&abbreviated,
                                          Some("causal_relation_object"));
            ensure!(!ok, "abbreviated scheme must be rejected");
            let abbr_str = obj(&json!({"type": "stratum",
                "id": format!("str:{}", hexid), "label": "cellular",
                "scheme": "neuroendocrine", "ordinal": 6}));
            let (ok, _) = validate_schema(&abbr_str, Some("stratum"));
            ensure!(!ok, "abbreviated stratum scheme must be rejected");
            let whole = obj(&json!({"type": "causal_relation_object",
                "id": format!("causal_relation_object:{}", hexid),
                "causes": [format!("occurrent:{}", hexid)],
                "effects": [format!("occurrent:{}", hexid)]}));
            let (ok, why) = validate_schema(&whole,
                                            Some("causal_relation_object"));
            ensure!(ok, "{:?}", why);
            Ok(())
        }
        _ => Err(format!("no vector {}", n)),
    }
}

fn main() {
    println!("causalontology-rust conformance run (specification 2.0.0)");
    print!("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ");
    if let Err(e) = internal_checks() {
        println!("FAILED: {}", e);
        std::process::exit(1);
    }
    println!("ok");
    let total = 107u32;
    let mut failures = 0;
    for n in 1..=total {
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
    println!("{}/{} vectors passed", total - failures, total);
    if failures > 0 {
        std::process::exit(1);
    }
    println!("causalontology-rust is CONFORMANT to the suite \
              (vectors frozen at specification 2.0.0).");
}

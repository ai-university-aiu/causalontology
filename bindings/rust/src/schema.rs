//! Schema validation against the twenty-one embedded JSON Schemas.
//! The schema files are compiled into the library (include_str!), which
//! keeps the crate pure - no filesystem at run time - and therefore
//! WebAssembly-ready with zero changes.

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::canonical::infer_kind;

const BASE: &str = "https://causalontology.org/schema/";

/// kind -> schema file. Three token kinds keep their original 1.0.0-reserved
/// file names (individual/token/state); the id scheme is the whole word.
fn schema_file(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "occurrent" => "occurrent.schema.json",
        "causal_relation_object" => "causal_relation_object.schema.json",
        "continuant" => "continuant.schema.json",
        "realizable" => "realizable.schema.json",
        "stratum" => "stratum.schema.json",
        "bridge" => "bridge.schema.json",
        "cross_stratal_seam" => "cross_stratal_seam.schema.json",
        "port" => "port.schema.json",
        "conduit" => "conduit.schema.json",
        "quality" => "quality.schema.json",
        "token_individual" => "individual.schema.json",
        "token_occurrence" => "token.schema.json",
        "state_assertion" => "state.schema.json",
        "token_causal_claim" => "token_causal_claim.schema.json",
        "attitude" => "attitude.schema.json",
        "predicted_occurrence" => "predicted_occurrence.schema.json",
        "prediction_error" => "prediction_error.schema.json",
        "assertion" => "assertion.schema.json",
        "enrichment" => "enrichment.schema.json",
        "retraction" => "retraction.schema.json",
        "succession" => "succession.schema.json",
        _ => return None,
    })
}

// The twenty-one whole-word schemas, embedded at compile time and keyed by
// their file name so cross-file $ref resolution is a simple lookup.
static SCHEMAS: OnceLock<HashMap<&'static str, Value>> = OnceLock::new();

macro_rules! embed {
    ($m:ident, $file:literal) => {
        $m.insert($file, serde_json::from_str(include_str!(
            concat!("../spec_schema/", $file))).unwrap());
    };
}

fn schemas() -> &'static HashMap<&'static str, Value> {
    SCHEMAS.get_or_init(|| {
        let mut m: HashMap<&'static str, Value> = HashMap::new();
        embed!(m, "occurrent.schema.json");
        embed!(m, "causal_relation_object.schema.json");
        embed!(m, "continuant.schema.json");
        embed!(m, "realizable.schema.json");
        embed!(m, "stratum.schema.json");
        embed!(m, "bridge.schema.json");
        embed!(m, "cross_stratal_seam.schema.json");
        embed!(m, "port.schema.json");
        embed!(m, "conduit.schema.json");
        embed!(m, "quality.schema.json");
        embed!(m, "individual.schema.json");
        embed!(m, "token.schema.json");
        embed!(m, "state.schema.json");
        embed!(m, "token_causal_claim.schema.json");
        embed!(m, "attitude.schema.json");
        embed!(m, "predicted_occurrence.schema.json");
        embed!(m, "prediction_error.schema.json");
        embed!(m, "assertion.schema.json");
        embed!(m, "enrichment.schema.json");
        embed!(m, "retraction.schema.json");
        embed!(m, "succession.schema.json");
        m
    })
}

fn schema_by_file(file: &str) -> &'static Value {
    schemas().get(file).unwrap_or_else(|| panic!("unknown schema file: {}", file))
}

fn navigate<'a>(mut node: &'a Value, pointer: &str) -> &'a Value {
    for part in pointer.split('/') {
        if part.is_empty() {
            continue;
        }
        node = node.get(part).expect("unresolvable $ref pointer");
    }
    node
}

/// Resolve local (`#/...`) and cross-file
/// (`https://causalontology.org/schema/<file>#/...`) $refs to a concrete
/// schema node and the root document it belongs to.
fn resolve<'a>(mut schema: &'a Value, mut root: &'a Value)
               -> (&'a Value, &'a Value) {
    while let Some(Value::String(r)) = schema.get("$ref") {
        if let Some(rest) = r.strip_prefix("#/") {
            schema = navigate(root, rest);
        } else if let Some(rest) = r.strip_prefix(BASE) {
            let (file, pointer) = match rest.split_once("#/") {
                Some((f, p)) => (f, Some(p)),
                None => (rest, None),
            };
            root = schema_by_file(file);
            schema = match pointer {
                Some(p) => navigate(root, p),
                None => root,
            };
        } else {
            panic!("unsupported $ref: {}", r);
        }
    }
    (schema, root)
}

fn type_matches(t: &str, value: &Value) -> bool {
    match t {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        // serde keeps booleans distinct from numbers, so integer/number
        // naturally reject a JSON boolean (as RFC 8785 / the Python ref do).
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        _ => false,
    }
}

fn check(value: &Value, schema: &Value, root: &Value, path: &str,
         errors: &mut Vec<String>) {
    let (schema, root) = resolve(schema, root);

    if let Some(Value::Array(branches)) = schema.get("oneOf") {
        let mut passing = 0;
        for branch in branches {
            let mut sub = Vec::new();
            check(value, branch, root, path, &mut sub);
            if sub.is_empty() {
                passing += 1;
            }
        }
        if passing != 1 {
            errors.push(format!(
                "{}: matches {} of the oneOf branches (need exactly 1)",
                path, passing));
        }
        return;
    }

    if let Some(Value::String(t)) = schema.get("type") {
        if !type_matches(t, value) {
            errors.push(format!("{}: expected {}", path, t));
            return;
        }
    }

    if let Some(c) = schema.get("const") {
        if value != c {
            errors.push(format!("{}: must equal {}", path, c));
        }
    }
    if let Some(Value::Array(options)) = schema.get("enum") {
        if !options.contains(value) {
            errors.push(format!("{}: {} not in enumeration", path, value));
        }
    }
    if let (Some(Value::String(p)), Some(s)) =
        (schema.get("pattern"), value.as_str()) {
        let re = Regex::new(p).expect("invalid schema pattern");
        if !re.is_match(s) {
            errors.push(format!("{}: {:?} does not match {}", path, s, p));
        }
    }
    if let (Some(min), Some(s)) =
        (schema.get("minLength").and_then(Value::as_u64), value.as_str()) {
        if (s.chars().count() as u64) < min {
            errors.push(format!("{}: shorter than minLength", path));
        }
    }
    if let (Some(min), Some(x)) =
        (schema.get("minimum").and_then(Value::as_f64), value.as_f64()) {
        if x < min {
            errors.push(format!("{}: below minimum {}", path, min));
        }
    }
    if let (Some(max), Some(x)) =
        (schema.get("maximum").and_then(Value::as_f64), value.as_f64()) {
        if x > max {
            errors.push(format!("{}: above maximum {}", path, max));
        }
    }

    if let Value::Array(items) = value {
        if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
            if (items.len() as u64) < min {
                errors.push(format!("{}: fewer than {} items", path, min));
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (i, item) in items.iter().enumerate() {
                check(item, item_schema, root,
                      &format!("{}[{}]", path, i), errors);
            }
        }
    }

    if let Value::Object(map) = value {
        let empty = Map::new();
        let props = schema.get("properties")
            .and_then(Value::as_object).unwrap_or(&empty);
        if let Some(Value::Array(required)) = schema.get("required") {
            for req in required {
                if let Some(name) = req.as_str() {
                    if !map.contains_key(name) {
                        errors.push(format!(
                            "{}: required property '{}' missing", path, name));
                    }
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for key in map.keys() {
                if !props.contains_key(key) {
                    errors.push(format!(
                        "{}: additional property '{}'", path, key));
                }
            }
        }
        for (key, sub) in props {
            if let Some(v) = map.get(key) {
                check(v, sub, root, &format!("{}.{}", path, key), errors);
            }
        }
    }
}

/// (ok, reasons) - structural validity against the kind's JSON Schema.
pub fn validate_schema(obj: &Map<String, Value>, kind: Option<&str>)
                       -> (bool, Vec<String>) {
    let kind = match kind {
        Some(k) => k.to_string(),
        None => match infer_kind(obj) {
            Ok(k) => k,
            Err(e) => return (false, vec![e]),
        },
    };
    let root = match schema_file(&kind) {
        Some(file) => schema_by_file(file),
        None => return (false, vec![format!("unknown kind: {}", kind)]),
    };
    let mut errors = Vec::new();
    check(&Value::Object(obj.clone()), root, root, "$", &mut errors);
    (errors.is_empty(), errors)
}

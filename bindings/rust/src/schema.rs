//! Schema validation against the eight embedded JSON Schemas.
//! The schema files are compiled into the library (include_str!), which
//! keeps the crate pure - no filesystem at run time - and therefore
//! WebAssembly-ready with zero changes.

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::canonical::infer_kind;

static SCHEMAS: OnceLock<HashMap<&'static str, Value>> = OnceLock::new();

fn schemas() -> &'static HashMap<&'static str, Value> {
    SCHEMAS.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("cro", serde_json::from_str(include_str!(
            "../../../spec/schema/cro.schema.json")).unwrap());
        m.insert("occurrent", serde_json::from_str(include_str!(
            "../../../spec/schema/occurrent.schema.json")).unwrap());
        m.insert("continuant", serde_json::from_str(include_str!(
            "../../../spec/schema/continuant.schema.json")).unwrap());
        m.insert("realizable", serde_json::from_str(include_str!(
            "../../../spec/schema/realizable.schema.json")).unwrap());
        m.insert("assertion", serde_json::from_str(include_str!(
            "../../../spec/schema/assertion.schema.json")).unwrap());
        m.insert("enrichment", serde_json::from_str(include_str!(
            "../../../spec/schema/enrichment.schema.json")).unwrap());
        m.insert("retraction", serde_json::from_str(include_str!(
            "../../../spec/schema/retraction.schema.json")).unwrap());
        m.insert("succession", serde_json::from_str(include_str!(
            "../../../spec/schema/succession.schema.json")).unwrap());
        m
    })
}

fn resolve<'a>(mut schema: &'a Value, root: &'a Value) -> &'a Value {
    while let Some(Value::String(r)) = schema.get("$ref") {
        let mut node = root;
        for part in r.trim_start_matches("#/").split('/') {
            node = node.get(part).expect("unresolvable local $ref");
        }
        schema = node;
    }
    schema
}

fn type_matches(t: &str, value: &Value) -> bool {
    match t {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        _ => false,
    }
}

fn check(value: &Value, schema: &Value, root: &Value, path: &str,
         errors: &mut Vec<String>) {
    let schema = resolve(schema, root);

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
    let root = match schemas().get(kind.as_str()) {
        Some(s) => s,
        None => return (false, vec![format!("unknown kind: {}", kind)]),
    };
    let mut errors = Vec::new();
    check(&Value::Object(obj.clone()), root, root, "$", &mut errors);
    (errors.is_empty(), errors)
}

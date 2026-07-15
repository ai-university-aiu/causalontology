//! The semantic rules beyond the schemas (spec/semantics.md) - the same
//! 13-rule module as the Python reference, including the fixed temporal
//! constants that make admissibility identical in every implementation.

use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

use crate::canonical::{infer_kind, kind_of_prefix};

/// Rule 4: the fixed unit-conversion constants (average Gregorian values).
pub fn unit_seconds(unit: &str) -> Option<f64> {
    match unit {
        "instant" => Some(0.0),
        "seconds" => Some(1.0),
        "minutes" => Some(60.0),
        "hours" => Some(3600.0),
        "days" => Some(86400.0),
        "weeks" => Some(604800.0),
        "months" => Some(2_629_746.0),
        "years" => Some(31_556_952.0),
        _ => None,
    }
}

pub const CRO_OPTIONAL_FIELDS: [&str; 4] =
    ["mechanism", "temporal", "modality", "context"];

fn kind_of_id(identifier: &str) -> Option<&'static str> {
    identifier.split_once(':').and_then(|(p, _)| kind_of_prefix(p))
}

fn f64_of(v: &Value) -> Option<f64> {
    v.as_f64()
}

/// (ok, reasons) - the locally checkable semantic rules.
pub fn validate_semantics(obj: &Map<String, Value>, kind: Option<&str>)
                          -> (bool, Vec<String>) {
    let kind = match kind {
        Some(k) => k.to_string(),
        None => match infer_kind(obj) {
            Ok(k) => k,
            Err(e) => return (false, vec![e]),
        },
    };
    let mut errors = Vec::new();

    if kind == "causal_relation_object" {
        if let Some(Value::Object(t)) = obj.get("temporal") {
            if let (Some(minimum_delay), Some(maximum_delay)) =
                (t.get("minimum_delay").and_then(f64_of), t.get("maximum_delay").and_then(f64_of)) {
                if minimum_delay > maximum_delay {
                    errors.push("minimum_delay must be <= maximum_delay".to_string());
                }
            }
        }
        if let Some(Value::String(oid)) = obj.get("id") {
            if let Some(Value::Array(mech)) = obj.get("mechanism") {
                if mech.iter().any(|m| m.as_str() == Some(oid)) {
                    errors.push("mechanism must be acyclic (a Causal \
                        Relation Object may not contain itself)".to_string());
                }
            }
            if obj.get("refines").and_then(Value::as_str) == Some(oid) {
                errors.push("refines must be acyclic".to_string());
            }
        }
    }

    if kind == "enrichment" {
        let field = obj.get("field").and_then(Value::as_str).unwrap_or("");
        let about = obj.get("about").and_then(Value::as_str).unwrap_or("");
        let entry = obj.get("entry");
        let spec: Option<(&[&str], &str)> = match field {
            "aliases" => Some((&["occurrent", "continuant"], "alias")),
            "participants" => Some((&["occurrent"], "continuant")),
            "subsumes" => Some((&["continuant"], "continuant")),
            "part_of" => Some((&["continuant"], "continuant")),
            "realized_in" => Some((&["realizable"], "occurrent")),
            _ => None,
        };
        if let Some((legal_kinds, shape)) = spec {
            if let Some(about_kind) = kind_of_id(about) {
                if !legal_kinds.contains(&about_kind) {
                    errors.push(format!(
                        "{} is not a legal field for a {} (rule 12)",
                        field, about_kind));
                }
            }
            if shape == "alias" {
                let ok = matches!(entry, Some(Value::Object(e))
                    if e.contains_key("lang") && e.contains_key("text"));
                if !ok {
                    errors.push("an aliases entry must be a \
                        language-tagged text object".to_string());
                }
            } else {
                let ok = matches!(entry, Some(Value::String(s))
                    if s.starts_with(&format!("{}:", shape)));
                if !ok {
                    errors.push(format!(
                        "a {} entry must be a {}: identifier", field, shape));
                }
            }
        }
    }

    (errors.is_empty(), errors)
}

/// (partial, missing) - which optional CRO fields are unspecified.
pub fn is_partial(cro: &Map<String, Value>) -> (bool, Vec<String>) {
    let missing: Vec<String> = CRO_OPTIONAL_FIELDS.iter()
        .filter(|f| !cro.contains_key(**f))
        .map(|f| f.to_string())
        .collect();
    (!missing.is_empty(), missing)
}

/// Rule 4: temporal admissibility with the fixed constants.
pub fn admissible(cro: &Map<String, Value>, elapsed_seconds: f64) -> bool {
    let t = match cro.get("temporal") {
        Some(Value::Object(t)) => t,
        _ => return true, // no window imposes no constraint
    };
    let unit = t.get("unit").and_then(Value::as_str)
        .and_then(unit_seconds).unwrap_or(1.0);
    let lo = t.get("minimum_delay").and_then(f64_of).unwrap_or(0.0) * unit;
    let hi = t.get("maximum_delay").and_then(f64_of).unwrap_or(f64::MAX) * unit;
    lo <= elapsed_seconds && elapsed_seconds <= hi
}

fn id_set(v: Option<&Value>) -> HashSet<String> {
    match v {
        Some(Value::Array(items)) => items.iter()
            .filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => HashSet::new(),
    }
}

fn window_overlap(a: &Map<String, Value>, b: &Map<String, Value>) -> bool {
    let (ta, tb) = (a.get("temporal"), b.get("temporal"));
    let (ta, tb) = match (ta, tb) {
        (Some(Value::Object(x)), Some(Value::Object(y))) => (x, y),
        _ => return true, // either absent counts as overlapping
    };
    let ua = ta.get("unit").and_then(Value::as_str)
        .and_then(unit_seconds).unwrap_or(1.0);
    let ub = tb.get("unit").and_then(Value::as_str)
        .and_then(unit_seconds).unwrap_or(1.0);
    let lo_a = ta.get("minimum_delay").and_then(f64_of).unwrap_or(0.0) * ua;
    let hi_a = ta.get("maximum_delay").and_then(f64_of).unwrap_or(0.0) * ua;
    let lo_b = tb.get("minimum_delay").and_then(f64_of).unwrap_or(0.0) * ub;
    let hi_b = tb.get("maximum_delay").and_then(f64_of).unwrap_or(0.0) * ub;
    lo_a <= hi_b && lo_b <= hi_a
}

fn contexts_compatible(a: &Map<String, Value>, b: &Map<String, Value>) -> bool {
    let ca = id_set(a.get("context"));
    let cb = id_set(b.get("context"));
    if ca.is_empty() || cb.is_empty() {
        return true; // either absent (or empty)
    }
    ca == cb || ca.is_subset(&cb) || cb.is_subset(&ca)
}

/// Rule 6: the formal conflict test.
pub fn conflicts(a: &Map<String, Value>, b: &Map<String, Value>) -> bool {
    if id_set(a.get("causes")) != id_set(b.get("causes")) {
        return false;
    }
    if id_set(a.get("effects")) != id_set(b.get("effects")) {
        return false;
    }
    if !contexts_compatible(a, b) {
        return false;
    }
    if !window_overlap(a, b) {
        return false;
    }
    let positive = ["necessary", "sufficient", "contributory"];
    let ma = a.get("modality").and_then(Value::as_str).unwrap_or("");
    let mb = b.get("modality").and_then(Value::as_str).unwrap_or("");
    (ma == "preventive" && positive.contains(&mb))
        || (mb == "preventive" && positive.contains(&ma))
}

/// Rule 3: (ok, reason) - is child a valid refinement of parent?
pub fn refinement_valid(child: &Map<String, Value>, parent: &Map<String, Value>)
                        -> (bool, String) {
    if child.get("refines") != parent.get("id")
        || child.get("refines").is_none() {
        return (false, "child does not name the parent in refines".into());
    }
    if id_set(child.get("causes")) != id_set(parent.get("causes"))
        || id_set(child.get("effects")) != id_set(parent.get("effects")) {
        return (false,
                "a refinement must keep the parent's causes and effects".into());
    }
    let mut added = 0;
    for field in CRO_OPTIONAL_FIELDS {
        if parent.contains_key(field) {
            if child.get(field) != parent.get(field) {
                return (false, "a refinement may not change a field the \
                    parent specified; this is a rival claim".into());
            }
        } else if child.contains_key(field) {
            added += 1;
        }
    }
    if added == 0 {
        return (false,
                "a refinement must add at least one unspecified field".into());
    }
    (true, "valid refinement".into())
}

/// Rule 7: "consistent" | "inconsistent" | "indeterminate".
pub fn hierarchy_consistent(parent: &Map<String, Value>,
                            members: &HashMap<String, Map<String, Value>>)
                            -> &'static str {
    let mechanism = match parent.get("mechanism") {
        Some(Value::Array(m)) if !m.is_empty() => m,
        _ => return "consistent", // nothing claimed, nothing to check
    };
    let mut edges: HashMap<String, HashSet<String>> = HashMap::new();
    for mid in mechanism {
        let mid = match mid.as_str() {
            Some(s) => s,
            None => return "indeterminate",
        };
        let member = match members.get(mid) {
            Some(m) => m,
            None => return "indeterminate", // dangling_reference, not failure
        };
        for c in id_set(member.get("causes")) {
            edges.entry(c).or_default()
                .extend(id_set(member.get("effects")));
        }
    }
    let reachable = |src: &str, dst: &str| -> bool {
        let mut seen = HashSet::new();
        let mut stack = vec![src.to_string()];
        while let Some(node) = stack.pop() {
            if node == dst {
                return true;
            }
            if !seen.insert(node.clone()) {
                continue;
            }
            if let Some(next) = edges.get(&node) {
                stack.extend(next.iter().cloned());
            }
        }
        false
    };
    for c in id_set(parent.get("causes")) {
        for e in id_set(parent.get("effects")) {
            if !reachable(&c, &e) {
                return "inconsistent";
            }
        }
    }
    "consistent"
}

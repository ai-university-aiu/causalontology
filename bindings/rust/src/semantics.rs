//! The semantic rules beyond the schemas (spec/semantics.md) - the same
//! rule module as the Python reference, including the fixed temporal
//! constants that make admissibility identical in every implementation.
//! 3.0.0 adds the ordinal tick dimension and the Cross Stratal Seam
//! (Algorithm F); 4.0.0 adds Rule 24 (a prediction is not a report) and
//! the prediction-to-observation pairing check.

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

/// 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete
/// step with NO wall-clock mapping; a tick window is ordered by integer
/// comparison, and an ordinal window and a wall-clock window are DIFFERENT
/// DIMENSIONS that do not compare (mixing them is never within-window and
/// never overlapping).
pub fn is_ordinal_unit(unit: &str) -> bool {
    unit == "ticks"
}

/// "ordinal" for a tick-like unit, else "wallclock".
fn dimension(unit: &str) -> &'static str {
    if is_ordinal_unit(unit) { "ordinal" } else { "wallclock" }
}

/// A comparable magnitude within ONE dimension: raw tick count for an
/// ordinal unit, seconds for a wall-clock unit. Never mix dimensions.
fn magnitude(value: f64, unit: &str) -> f64 {
    if is_ordinal_unit(unit) {
        return value; // a dimensionless tick count
    }
    if unit == "instant" {
        return 0.0;
    }
    value * unit_seconds(unit).unwrap_or(1.0)
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
        // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        // contradiction between skips:true and a non-empty mechanism.
        if obj.get("skips") == Some(&Value::Bool(true)) {
            let has_mech = matches!(obj.get("mechanism"),
                Some(Value::Array(m)) if !m.is_empty());
            if has_mech {
                errors.push("contradictory_skip: skips is true but a \
                    mechanism is present".to_string());
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
            "occurrent_subsumes" => Some((&["occurrent"], "occurrent")),
            "occurrent_part_of" => Some((&["occurrent"], "occurrent")),
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

    // 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain
    // has, by drawing it, a modelled intervening mechanism - so
    // mechanism_status "absent" contradicts a present chain (the
    // honest-ignorance distinction must stay honest). The stratal
    // well-formedness (non-adjacency, adjacency of chain steps, scheme, the
    // home rule) needs the strata map and lives in seam_wellformed, exactly
    // as bridge well-formedness does.
    if kind == "cross_stratal_seam"
        && obj.get("chain").is_some()
        && obj.get("mechanism_status").and_then(Value::as_str)
            == Some("absent") {
        errors.push("contradictory_seam: a drawn chain cannot carry \
            mechanism_status 'absent' (a drawn mechanism is not absent)"
            .to_string());
    }

    // 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
    // exactly ONE temporal dimension - a wall-clock start (optional end) or
    // an ordinal start_tick (optional end_tick), never both and never
    // neither. Per Rule 23 the two dimensions never compare. The pairing
    // check of a prediction_error against its predicted_occurrence and its
    // observed token_occurrence needs those objects and lives in
    // prediction_pairing_mismatch, exactly as covering_law_mismatch does.
    if kind == "predicted_occurrence" {
        let empty = Map::new();
        let iv = match obj.get("interval") {
            Some(Value::Object(iv)) => iv,
            _ => &empty,
        };
        let wall = iv.contains_key("start");
        let tick = iv.contains_key("start_tick");
        if wall && tick {
            errors.push("dimension_conflict: a predicted interval must \
                carry exactly one temporal dimension, not a wall-clock \
                start AND an ordinal start_tick".to_string());
        }
        if !wall && !tick {
            errors.push("missing_dimension: a predicted interval must \
                carry a wall-clock start or an ordinal start_tick"
                .to_string());
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

/// Rule 4: temporal admissibility with the fixed constants. For a wall-clock
/// window `elapsed` is in seconds; for an ordinal ("ticks") window `elapsed`
/// is a tick count. Ordering is by magnitude WITHIN the window's own
/// dimension (3.0.0).
pub fn admissible(cro: &Map<String, Value>, elapsed: f64) -> bool {
    let t = match cro.get("temporal") {
        Some(Value::Object(t)) => t,
        _ => return true, // no window imposes no constraint
    };
    let unit = t.get("unit").and_then(Value::as_str).unwrap_or("seconds");
    let lo = magnitude(t.get("minimum_delay").and_then(f64_of)
                       .unwrap_or(0.0), unit);
    let hi = magnitude(t.get("maximum_delay").and_then(f64_of)
                       .unwrap_or(f64::MAX), unit);
    lo <= elapsed && elapsed <= hi
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
    let ua = ta.get("unit").and_then(Value::as_str).unwrap_or("seconds");
    let ub = tb.get("unit").and_then(Value::as_str).unwrap_or("seconds");
    if dimension(ua) != dimension(ub) {
        return false; // 3.0.0: an ordinal window and a wall-clock window never overlap
    }
    let lo_a = magnitude(ta.get("minimum_delay").and_then(f64_of)
                         .unwrap_or(0.0), ua);
    let hi_a = magnitude(ta.get("maximum_delay").and_then(f64_of)
                         .unwrap_or(0.0), ua);
    let lo_b = magnitude(tb.get("minimum_delay").and_then(f64_of)
                         .unwrap_or(0.0), ub);
    let hi_b = magnitude(tb.get("maximum_delay").and_then(f64_of)
                         .unwrap_or(0.0), ub);
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
    let positive = ["necessary", "sufficient", "contributory", "enabling"];
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

// ==========================================================================
// 2.0.0 NORMATIVE ALGORITHMS (Section 12)
// ==========================================================================

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(items)) => items.iter()
            .filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    }
}

/// ALGORITHM A. Every finer occurrent an occurrent resolves to, following
/// Bridges downward, transitively; includes the starting occurrent (N12.1.1).
pub fn bridge_closure(occurrent_id: &str, bridges: &[Map<String, Value>])
                      -> HashSet<String> {
    let mut coarse_index: HashMap<String, Vec<&Map<String, Value>>> =
        HashMap::new();
    for b in bridges {
        if let Some(c) = b.get("coarse").and_then(Value::as_str) {
            coarse_index.entry(c.to_string()).or_default().push(b);
        }
    }
    let mut result: HashSet<String> = HashSet::new();
    result.insert(occurrent_id.to_string());
    let mut frontier = vec![occurrent_id.to_string()];
    let mut visited: HashSet<String> = HashSet::new();
    while let Some(current) = frontier.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if let Some(bs) = coarse_index.get(&current) {
            for b in bs {
                for f in str_list(b.get("fine")) {
                    result.insert(f.clone());
                    frontier.push(f);
                }
            }
        }
    }
    result
}

fn path_exists(edges: &HashMap<String, HashSet<String>>,
               src: &str, dst: &str) -> bool {
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
}

/// ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
/// "indeterminate", ACROSS STRATA via bridged reachability. `bridges` empty
/// -> 1.0.0 literal reachability (the degenerate case, N12.2.3).
pub fn hierarchy_consistent(parent: &Map<String, Value>,
                            members: &HashMap<String, Map<String, Value>>,
                            bridges: &[Map<String, Value>])
                            -> &'static str {
    let mechanism = match parent.get("mechanism") {
        Some(Value::Array(m)) if !m.is_empty() => m,
        _ => return "consistent", // nothing claimed, nothing to check (N12.2.1)
    };
    let mut edges: HashMap<String, HashSet<String>> = HashMap::new();
    for mid in mechanism {
        let mid = match mid.as_str() {
            Some(s) => s,
            None => return "indeterminate",
        };
        let member = match members.get(mid) {
            Some(m) => m,
            None => return "indeterminate", // dangling; ignorance, not refutation
        };
        for c in id_set(member.get("causes")) {
            edges.entry(c).or_default()
                .extend(id_set(member.get("effects")));
        }
    }
    let parent_causes = str_list(parent.get("causes"));
    let parent_effects = str_list(parent.get("effects"));
    let b_cause: HashMap<String, HashSet<String>> = parent_causes.iter()
        .map(|c| (c.clone(), bridge_closure(c, bridges))).collect();
    let b_effect: HashMap<String, HashSet<String>> = parent_effects.iter()
        .map(|e| (e.clone(), bridge_closure(e, bridges))).collect();
    for c in &parent_causes {
        for e in &parent_effects {
            let connected = b_cause[c].iter().any(|cp|
                b_effect[e].iter().any(|ep| path_exists(&edges, cp, ep)));
            if !connected {
                return "inconsistent";
            }
        }
    }
    "consistent"
}

fn stratum_of<'a>(occ_id: &str,
                  occ_map: &'a HashMap<String, Map<String, Value>>)
                  -> Option<&'a str> {
    occ_map.get(occ_id)
        .and_then(|o| o.get("stratum"))
        .and_then(Value::as_str)
}

/// ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping" |
/// "mixed" | "unclassifiable" | "scheme_mismatch". Derived, never asserted.
pub fn classify_cro(cro: &Map<String, Value>,
                    occ_map: &HashMap<String, Map<String, Value>>,
                    stratum_map: &HashMap<String, Map<String, Value>>)
                    -> &'static str {
    let causes = str_list(cro.get("causes"));
    let effects = str_list(cro.get("effects"));
    let cause_strata: Vec<Option<&str>> = causes.iter()
        .map(|c| stratum_of(c, occ_map)).collect();
    let effect_strata: Vec<Option<&str>> = effects.iter()
        .map(|e| stratum_of(e, occ_map)).collect();
    if cause_strata.iter().chain(effect_strata.iter()).any(|s| s.is_none()) {
        return "unclassifiable"; // surface unstratified_occurrent (invitation)
    }
    let cause_strata: Vec<&str> = cause_strata.into_iter().flatten().collect();
    let effect_strata: Vec<&str> = effect_strata.into_iter().flatten().collect();
    let mut all_strata: HashSet<&str> = HashSet::new();
    all_strata.extend(cause_strata.iter().copied());
    all_strata.extend(effect_strata.iter().copied());
    let scheme_of = |s: &str| -> String {
        stratum_map.get(s).and_then(|st| st.get("scheme"))
            .and_then(Value::as_str).unwrap_or("").to_string()
    };
    let schemes: HashSet<String> = all_strata.iter().map(|s| scheme_of(s))
        .collect();
    if schemes.len() > 1 {
        return "scheme_mismatch"; // HARD
    }
    let ord_of = |s: &str| -> i64 {
        stratum_map.get(s).and_then(|st| st.get("ordinal"))
            .and_then(Value::as_i64).unwrap_or(0)
    };
    let c_ord: Vec<i64> = cause_strata.iter().map(|s| ord_of(s)).collect();
    let e_ord: Vec<i64> = effect_strata.iter().map(|s| ord_of(s)).collect();
    let (cmax, cmin) = (*c_ord.iter().max().unwrap(),
                        *c_ord.iter().min().unwrap());
    let (emax, emin) = (*e_ord.iter().max().unwrap(),
                        *e_ord.iter().min().unwrap());
    if cmax == cmin && cmin == emax && emax == emin {
        return "intra_stratal";
    }
    let gap = c_ord.iter().flat_map(|i| e_ord.iter().map(move |j| (i - j).abs()))
        .min().unwrap();
    let span = c_ord.iter().flat_map(|i| e_ord.iter().map(move |j| (i - j).abs()))
        .max().unwrap();
    if span == 1 {
        return "adjacent_stratal";
    }
    if gap > 1 {
        return "skipping";
    }
    "mixed" // some pairs adjacent, some skipping
}

/// True iff causes or effects span more than one distinct stratum (surfaces
/// mixed_stratal_endpoints, an invitation; N12.3.2).
pub fn endpoints_mixed(cro: &Map<String, Value>,
                       occ_map: &HashMap<String, Map<String, Value>>) -> bool {
    let cs: Vec<Option<&str>> = str_list(cro.get("causes")).iter()
        .map(|c| stratum_of(c, occ_map)).collect();
    let es: Vec<Option<&str>> = str_list(cro.get("effects")).iter()
        .map(|e| stratum_of(e, occ_map)).collect();
    if cs.iter().chain(es.iter()).any(|s| s.is_none()) {
        return false;
    }
    let cset: HashSet<&str> = cs.into_iter().flatten().collect();
    let eset: HashSet<&str> = es.into_iter().flatten().collect();
    cset.len() > 1 || eset.len() > 1
}

/// ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
/// skip decision. THE ASYMMETRY (clause 3) is implemented exactly.
pub fn skip_gaps(cro: &Map<String, Value>, classification: &str)
                 -> Vec<String> {
    let mut gaps = Vec::new();
    let has_mech = matches!(cro.get("mechanism"),
        Some(Value::Array(m)) if !m.is_empty());
    let skips_true = cro.get("skips") == Some(&Value::Bool(true));
    if skips_true && has_mech {
        gaps.push("contradictory_skip".to_string()); // HARD
        return gaps;
    }
    if skips_true && classification != "skipping"
        && classification != "unclassifiable" {
        gaps.push("vacuous_skip".to_string()); // invitation
    }
    if classification == "skipping" && !has_mech {
        if skips_true {
            // NOTHING: absence is a finding
        } else {
            gaps.push("incomplete_mechanism".to_string()); // invitation
        }
    }
    gaps
}

/// ALGORITHM E helper: normalize a delay to seconds by the fixed table.
/// 3.0.0: an ordinal ("ticks") unit is dimensionless and has NO wall-clock
/// mapping - converting one to seconds is a category error and is refused.
pub fn to_seconds(duration: f64, unit: &str) -> Result<f64, String> {
    if is_ordinal_unit(unit) {
        return Err(format!("'{}' is an ordinal (dimensionless) unit and has \
            no wall-clock seconds mapping", unit));
    }
    if unit == "instant" {
        return Ok(0.0);
    }
    Ok(duration * unit_seconds(unit).unwrap_or(0.0))
}

/// ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
/// temporal window? Inclusive at both ends (N12.5.2). 3.0.0: an ordinal delay
/// compares to an ordinal window by integer tick count; an ordinal delay and
/// a wall-clock window (or vice versa) are different dimensions and never
/// fall within one another.
pub fn delay_within_window(actual_delay: Option<&Map<String, Value>>,
                           temporal: Option<&Map<String, Value>>) -> bool {
    let (ad, t) = match (actual_delay, temporal) {
        (Some(a), Some(t)) => (a, t),
        _ => return true, // nothing to check
    };
    let ad_unit = ad.get("unit").and_then(Value::as_str).unwrap_or("instant");
    let unit = t.get("unit").and_then(Value::as_str).unwrap_or("instant");
    if dimension(ad_unit) != dimension(unit) {
        return false; // dimension mismatch: a tick delay is not within a wall-clock window
    }
    let observed = magnitude(
        ad.get("duration").and_then(f64_of).unwrap_or(0.0), ad_unit);
    let lo = magnitude(
        t.get("minimum_delay").and_then(f64_of).unwrap_or(0.0), unit);
    let hi = magnitude(
        t.get("maximum_delay").and_then(f64_of).unwrap_or(0.0), unit);
    lo <= observed && observed <= hi
}

/// Rule 14 / N3.2.1: Bridge well-formedness. (ok, reason).
pub fn bridge_wellformed(bridge: &Map<String, Value>,
                         occ_map: &HashMap<String, Map<String, Value>>,
                         stratum_map: &HashMap<String, Map<String, Value>>)
                         -> (bool, String) {
    let coarse_id = bridge.get("coarse").and_then(Value::as_str).unwrap_or("");
    let cs = match stratum_of(coarse_id, occ_map) {
        Some(s) => s.to_string(),
        None => return (false,
            "malformed_bridge: coarse has no stratum (a)".into()),
    };
    let fine_ids = str_list(bridge.get("fine"));
    let fine_strata: Vec<Option<String>> = fine_ids.iter()
        .map(|f| stratum_of(f, occ_map).map(String::from)).collect();
    if fine_strata.iter().any(|s| s.is_none()) {
        return (false,
            "malformed_bridge: a fine member has no stratum (b)".into());
    }
    let fine_strata: Vec<String> = fine_strata.into_iter().flatten().collect();
    let unique: HashSet<&String> = fine_strata.iter().collect();
    if unique.len() != 1 {
        return (false,
            "malformed_bridge: fine members span >1 stratum (c)".into());
    }
    let fs = &fine_strata[0];
    let scheme = |s: &str| stratum_map.get(s).and_then(|x| x.get("scheme"))
        .and_then(Value::as_str).unwrap_or("");
    if scheme(&cs) != scheme(fs) {
        return (false,
            "malformed_bridge: coarse and fine differ in scheme (d)".into());
    }
    let ord = |s: &str| stratum_map.get(s).and_then(|x| x.get("ordinal"))
        .and_then(Value::as_i64).unwrap_or(0);
    if !(ord(&cs) > ord(fs)) {
        return (false,
            "malformed_bridge: coarse ordinal not > fine ordinal (e)".into());
    }
    (true, "well-formed bridge".into())
}

/// 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness.
/// (ok, reason). All of (a)-(g) must hold, else malformed_seam. A seam is a
/// MANAGED jump across NON-ADJACENT strata; when it DRAWS a chain, the chain
/// must be an adjacent-stratum path spanning the two endpoints' strata.
pub fn seam_wellformed(seam: &Map<String, Value>,
                       occ_map: &HashMap<String, Map<String, Value>>,
                       stratum_map: &HashMap<String, Map<String, Value>>)
                       -> (bool, String) {
    let src_id = seam.get("source").and_then(Value::as_str).unwrap_or("");
    let tgt_id = seam.get("target").and_then(Value::as_str).unwrap_or("");
    let (src_s, tgt_s) = match (stratum_of(src_id, occ_map),
                                stratum_of(tgt_id, occ_map)) {
        (Some(s), Some(t)) => (s.to_string(), t.to_string()),
        _ => return (false,
            "malformed_seam: an endpoint has no stratum (a)".into()),
    };
    let scheme = |s: &str| stratum_map.get(s).and_then(|x| x.get("scheme"))
        .and_then(Value::as_str).unwrap_or("");
    if scheme(&src_s) != scheme(&tgt_s) {
        return (false,
            "malformed_seam: endpoints differ in scheme (b)".into());
    }
    let ord = |s: &str| stratum_map.get(s).and_then(|x| x.get("ordinal"))
        .and_then(Value::as_i64).unwrap_or(0);
    let (so, to) = (ord(&src_s), ord(&tgt_s));
    if (so - to).abs() <= 1 {
        return (false, "malformed_seam: endpoints are adjacent or \
            co-stratal; a seam is for NON-adjacent strata (c)".into());
    }
    if let Some(Value::Array(chain)) = seam.get("chain") {
        if seam.get("mechanism_status").and_then(Value::as_str)
            == Some("absent") {
            return (false, "malformed_seam: a drawn chain contradicts \
                mechanism_status 'absent' (d)".into());
        }
        let (lo, hi) = (so.min(to), so.max(to));
        let mut ords = Vec::new();
        for oid in chain {
            let oid = oid.as_str().unwrap_or("");
            let st = match stratum_of(oid, occ_map) {
                Some(s) => s.to_string(),
                None => return (false,
                    "malformed_seam: a chain member has no stratum (e)".into()),
            };
            if scheme(&st) != scheme(&src_s) {
                return (false, "malformed_seam: a chain member differs in \
                    scheme (e)".into());
            }
            ords.push(ord(&st));
        }
        if !ords.iter().all(|o| lo < *o && *o < hi) {
            return (false, "malformed_seam: a chain member is not at an \
                INTERVENING stratum, strictly between the endpoints (f)"
                .into());
        }
        let diffs: Vec<i64> = ords.windows(2).map(|w| w[1] - w[0]).collect();
        if !diffs.is_empty() && !(diffs.iter().all(|d| *d > 0)
                                  || diffs.iter().all(|d| *d < 0)) {
            return (false, "malformed_seam: chain is not strictly monotone \
                from one endpoint toward the other (g)".into());
        }
    }
    (true, "well-formed cross_stratal_seam".into())
}

/// THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST
/// stratum it touches - the endpoint of the greater ordinal. Returns that
/// stratum's identifier (None if an endpoint is unstratified). A layer-to-
/// stratum binding places and checks the seam by this rule.
pub fn seam_home(seam: &Map<String, Value>,
                 occ_map: &HashMap<String, Map<String, Value>>,
                 stratum_map: &HashMap<String, Map<String, Value>>)
                 -> Option<String> {
    let src_id = seam.get("source").and_then(Value::as_str).unwrap_or("");
    let tgt_id = seam.get("target").and_then(Value::as_str).unwrap_or("");
    let src_s = stratum_of(src_id, occ_map)?.to_string();
    let tgt_s = stratum_of(tgt_id, occ_map)?.to_string();
    let ord = |s: &str| stratum_map.get(s).and_then(|x| x.get("ordinal"))
        .and_then(Value::as_i64).unwrap_or(0);
    if ord(&src_s) >= ord(&tgt_s) { Some(src_s) } else { Some(tgt_s) }
}

/// Rule 17 / N4.2.1-2: Conduit well-formedness. (ok, reason).
pub fn conduit_wellformed(conduit: &Map<String, Value>,
                          port_map: &HashMap<String, Map<String, Value>>,
                          cro_map: &HashMap<String, Map<String, Value>>)
                          -> (bool, String) {
    let from_id = conduit.get("from").and_then(Value::as_str).unwrap_or("");
    let to_id = conduit.get("to").and_then(Value::as_str).unwrap_or("");
    let (frm, to) = match (port_map.get(from_id), port_map.get(to_id)) {
        (Some(f), Some(t)) => (f, t),
        _ => return (false,
            "malformed_conduit: dangling port reference".into()),
    };
    let from_dir = frm.get("direction").and_then(Value::as_str).unwrap_or("");
    if from_dir != "out" && from_dir != "bidirectional" {
        return (false,
            "malformed_conduit: from port is not out/bidirectional (a)".into());
    }
    let to_dir = to.get("direction").and_then(Value::as_str).unwrap_or("");
    if to_dir != "in" && to_dir != "bidirectional" {
        return (false,
            "malformed_conduit: to port is not in/bidirectional (b)".into());
    }
    let carries = str_list(conduit.get("carries"));
    let from_accepts: HashSet<String> = str_list(frm.get("accepts"))
        .into_iter().collect();
    if !carries.iter().all(|o| from_accepts.contains(o)) {
        return (false,
            "malformed_conduit: carries not accepted by from (c)".into());
    }
    let to_accepts: HashSet<String> = str_list(to.get("accepts"))
        .into_iter().collect();
    match conduit.get("transform").and_then(Value::as_str) {
        None => {
            if !carries.iter().all(|o| to_accepts.contains(o)) {
                return (false,
                    "malformed_conduit: carries not accepted by to (d)".into());
            }
        }
        Some(transform) => {
            if let Some(law) = cro_map.get(transform) {
                let effects = str_list(law.get("effects"));
                if !effects.iter().all(|o| to_accepts.contains(o)) {
                    return (false, "malformed_conduit: transform effects not \
                        accepted by to (d, relaxed per N4.2.2)".into());
                }
            }
        }
    }
    (true, "well-formed conduit".into())
}

/// Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against its
/// quality: value_type_mismatch and/or unit_mismatch.
pub fn state_gaps(state: &Map<String, Value>, quality: &Map<String, Value>)
                  -> Vec<String> {
    let mut gaps = Vec::new();
    let dt = quality.get("datatype").and_then(Value::as_str).unwrap_or("");
    let empty = Map::new();
    let v = match state.get("value") {
        Some(Value::Object(v)) => v,
        _ => &empty,
    };
    let shape = if v.contains_key("quantity") {
        "quantity"
    } else if v.contains_key("categorical") {
        "categorical"
    } else if v.contains_key("boolean") {
        "boolean"
    } else {
        ""
    };
    if shape != dt {
        gaps.push("value_type_mismatch".to_string());
    } else if dt == "quantity"
        && v.get("unit").and_then(Value::as_str)
            != quality.get("unit").and_then(Value::as_str) {
        gaps.push("unit_mismatch".to_string());
    }
    gaps
}

/// Rule 20: True iff the token claim's cause/effect tokens do not instantiate
/// the covering law's causes/effects (surfaces covering_law_mismatch).
pub fn covering_law_mismatch(tcc: &Map<String, Value>,
                             token_map: &HashMap<String, Map<String, Value>>,
                             law: Option<&Map<String, Value>>) -> bool {
    let law = match law {
        Some(l) => l,
        None => return false,
    };
    let law_causes: HashSet<String> = str_list(law.get("causes"))
        .into_iter().collect();
    let law_effects: HashSet<String> = str_list(law.get("effects"))
        .into_iter().collect();
    for c in str_list(tcc.get("causes")) {
        let inst = token_map.get(&c).and_then(|t| t.get("instantiates"))
            .and_then(Value::as_str).unwrap_or("");
        if !law_causes.contains(inst) {
            return true;
        }
    }
    for e in str_list(tcc.get("effects")) {
        let inst = token_map.get(&e).and_then(|t| t.get("instantiates"))
            .and_then(Value::as_str).unwrap_or("");
        if !law_effects.contains(inst) {
            return true;
        }
    }
    false
}

/// 4.0.0 Rule 24: True iff the prediction error's observed token does not
/// instantiate the occurrent its predicted_occurrence instantiates (surfaces
/// pairing_mismatch). An ABSENT observed is never a mismatch - it means the
/// predicted occurrence was not fulfilled by any recorded occurrence.
pub fn prediction_pairing_mismatch(error: &Map<String, Value>,
                                   predicted: &Map<String, Value>,
                                   observed: Option<&Map<String, Value>>)
                                   -> bool {
    let observed = match observed {
        Some(o) => o,
        None => return false,
    };
    if error.get("observed").is_none() {
        return false;
    }
    observed.get("instantiates").and_then(Value::as_str)
        != predicted.get("instantiates").and_then(Value::as_str)
}

/// Rule 21: True iff any cause token starts after any effect token (HARD;
/// retrocausal_claim). RFC 3339 UTC "Z" strings compare lexicographically.
pub fn retrocausal(tcc: &Map<String, Value>,
                   token_map: &HashMap<String, Map<String, Value>>) -> bool {
    let start_of = |id: &str| -> String {
        token_map.get(id).and_then(|t| t.get("interval"))
            .and_then(|i| i.get("start"))
            .and_then(Value::as_str).unwrap_or("").to_string()
    };
    for c in str_list(tcc.get("causes")) {
        let cstart = start_of(&c);
        for e in str_list(tcc.get("effects")) {
            if cstart > start_of(&e) {
                return true;
            }
        }
    }
    false
}

/// Rules 4 / 6.1: True iff a directed graph (node -> successors) has a cycle.
pub fn has_cycle(edges: &HashMap<String, Vec<String>>) -> bool {
    const WHITE: u8 = 0;
    const GREY: u8 = 1;
    const BLACK: u8 = 2;
    fn visit(node: &str, edges: &HashMap<String, Vec<String>>,
             state: &mut HashMap<String, u8>) -> bool {
        state.insert(node.to_string(), GREY);
        if let Some(succ) = edges.get(node) {
            for nxt in succ {
                match *state.get(nxt).unwrap_or(&WHITE) {
                    GREY => return true,
                    WHITE => {
                        if visit(nxt, edges, state) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        state.insert(node.to_string(), BLACK);
        false
    }
    let mut state: HashMap<String, u8> = HashMap::new();
    let nodes: Vec<String> = edges.keys().cloned().collect();
    nodes.iter().any(|n| *state.get(n).unwrap_or(&WHITE) == WHITE
                     && visit(n, edges, &mut state))
}

//! An in-memory conformant store - the same semantics as the Python
//! reference store, with explicit insertion order (Rust HashMaps are
//! unordered) so cycle attribution and resolve ranking are deterministic.

use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

use crate::canonical::identify;
use crate::canonical::infer_kind;
use crate::schema::validate_schema;
use crate::semantics::{is_partial, refinement_valid, validate_semantics};
use crate::signing::verify_record;

const CONTENT_KINDS: [&str; 4] =
    ["occurrent", "cro", "continuant", "realizable"];
const RECORD_KINDS: [&str; 4] =
    ["assertion", "enrichment", "retraction", "succession"];

#[derive(Debug)]
pub struct RejectedWrite(pub String);

impl std::fmt::Display for RejectedWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for RejectedWrite {}

#[derive(Default)]
pub struct InMemoryStore {
    pub enforcing: bool,
    pub objects: HashMap<String, Map<String, Value>>,
    pub object_order: Vec<String>,
    pub records: HashMap<String, Map<String, Value>>,
    pub record_order: Vec<String>,
    pub quarantine: HashMap<String, Map<String, Value>>,
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

impl InMemoryStore {
    pub fn new(enforcing: bool) -> Self {
        InMemoryStore { enforcing, ..Default::default() }
    }

    // ---------------------------------------------------------------- put
    pub fn put(&mut self, obj: &Map<String, Value>, kind: Option<&str>)
               -> Result<String, RejectedWrite> {
        let kind = match kind {
            Some(k) => k.to_string(),
            None => infer_kind(obj).map_err(RejectedWrite)?,
        };
        if !CONTENT_KINDS.contains(&kind.as_str()) {
            return Err(RejectedWrite(
                "put() takes content objects; use put_record()".into()));
        }
        let mut obj = obj.clone();
        obj.entry("type".to_string())
            .or_insert_with(|| Value::String(kind.clone()));
        let id = match obj.get("id").and_then(Value::as_str) {
            Some(existing) => existing.to_string(),
            None => {
                let computed = identify(&obj, Some(&kind))
                    .map_err(RejectedWrite)?;
                obj.insert("id".to_string(), Value::String(computed.clone()));
                computed
            }
        };
        if self.objects.contains_key(&id) {
            return Ok(id); // immutable: identical identity is a no-op
        }
        let (ok, why) = validate_schema(&obj, Some(&kind));
        if !ok {
            return Err(RejectedWrite(why.join("; ")));
        }
        let (ok, why) = validate_semantics(&obj, Some(&kind));
        if !ok {
            return Err(RejectedWrite(why.join("; ")));
        }
        self.objects.insert(id.clone(), obj);
        self.object_order.push(id.clone());
        Ok(id)
    }

    pub fn put_record(&mut self, record: &Map<String, Value>,
                      kind: Option<&str>) -> Result<String, RejectedWrite> {
        self.put_record_inner(record, kind, false)
    }

    /// Simulate a decentralized replica merge (no enforcement gate).
    pub fn force_merge_record(&mut self, record: &Map<String, Value>,
                              kind: Option<&str>)
                              -> Result<String, RejectedWrite> {
        self.put_record_inner(record, kind, true)
    }

    fn put_record_inner(&mut self, record: &Map<String, Value>,
                        kind: Option<&str>, force: bool)
                        -> Result<String, RejectedWrite> {
        let kind = match kind {
            Some(k) => k.to_string(),
            None => infer_kind(record).map_err(RejectedWrite)?,
        };
        if !RECORD_KINDS.contains(&kind.as_str()) {
            return Err(RejectedWrite(
                "put_record() takes provenance records".into()));
        }
        let mut record = record.clone();
        record.entry("type".to_string())
            .or_insert_with(|| Value::String(kind.clone()));
        let rid = match record.get("id").and_then(Value::as_str) {
            Some(existing) => existing.to_string(),
            None => {
                let computed = identify(&record, Some(&kind))
                    .map_err(RejectedWrite)?;
                record.insert("id".to_string(),
                              Value::String(computed.clone()));
                computed
            }
        };
        if self.records.contains_key(&rid) {
            return Ok(rid); // add-only and idempotent
        }
        if !verify_record(&record, Some(&kind)) {
            self.quarantine.insert(rid.clone(), record);
            return Err(RejectedWrite(
                "unsigned or unverifiable record: quarantined".into()));
        }
        let (ok, why) = validate_semantics(&record, Some(&kind));
        if !ok {
            return Err(RejectedWrite(why.join("; ")));
        }
        if kind == "retraction" && !self.retraction_source_ok(&record) {
            return Err(RejectedWrite(
                "a retraction is valid only from the retracted record's \
                 source or its succession lineage".into()));
        }
        if kind == "enrichment" && self.enforcing && !force {
            let field = record.get("field").and_then(Value::as_str)
                .unwrap_or("");
            if (field == "subsumes" || field == "part_of")
                && self.would_cycle(&record, field) {
                return Err(RejectedWrite(format!(
                    "would create a cycle in the materialized {} graph",
                    field)));
            }
        }
        self.records.insert(rid.clone(), record);
        self.record_order.push(rid.clone());
        Ok(rid)
    }

    // --------------------------------------------------- record queries
    fn records_of(&self, kind: &str) -> Vec<&Map<String, Value>> {
        self.record_order.iter()
            .filter_map(|rid| self.records.get(rid))
            .filter(|r| r.get("type").and_then(Value::as_str) == Some(kind))
            .collect()
    }

    fn retracted_ids(&self) -> HashSet<String> {
        self.records_of("retraction").iter()
            .filter_map(|r| r.get("retracts").and_then(Value::as_str))
            .map(String::from)
            .collect()
    }

    fn retraction_source_ok(&self, retraction: &Map<String, Value>) -> bool {
        let target_id = retraction.get("retracts").and_then(Value::as_str)
            .unwrap_or("");
        let target = match self.records.get(target_id) {
            Some(t) => t,
            None => return true, // open world: the target may arrive later
        };
        let source = retraction.get("source").and_then(Value::as_str)
            .unwrap_or("");
        self.lineage(&s(target.get("source").unwrap_or(&Value::Null)))
            .contains(source)
    }

    /// The succession chain closure containing key (includes key).
    pub fn lineage(&self, key: &str) -> HashSet<String> {
        let mut succ = HashMap::new();
        let mut pred = HashMap::new();
        for r in self.records_of("succession") {
            let p = s(r.get("predecessor").unwrap_or(&Value::Null));
            let q = s(r.get("successor").unwrap_or(&Value::Null));
            succ.insert(p.clone(), q.clone());
            pred.insert(q, p);
        }
        let mut chain = HashSet::new();
        chain.insert(key.to_string());
        let mut cursor = key.to_string();
        while let Some(prev) = pred.get(&cursor) {
            if !chain.insert(prev.clone()) {
                break; // guard against succession cycles
            }
            cursor = prev.clone();
        }
        cursor = key.to_string();
        while let Some(next) = succ.get(&cursor) {
            if !chain.insert(next.clone()) {
                break;
            }
            cursor = next.clone();
        }
        chain
    }

    pub fn assertions_about(&self, identifier: &str, include_retracted: bool)
                            -> Vec<Map<String, Value>> {
        let retracted = self.retracted_ids();
        let mut out = Vec::new();
        for r in self.records_of("assertion") {
            if r.get("about").and_then(Value::as_str) != Some(identifier) {
                continue;
            }
            let rid = s(r.get("id").unwrap_or(&Value::Null));
            if retracted.contains(&rid) {
                if include_retracted {
                    let mut flagged = (*r).clone();
                    flagged.insert("retracted".into(), Value::Bool(true));
                    out.push(flagged);
                }
                continue;
            }
            out.push((*r).clone());
        }
        out
    }

    pub fn enrichments_about(&self, identifier: &str, include_retracted: bool)
                             -> Vec<Map<String, Value>> {
        let retracted = self.retracted_ids();
        self.records_of("enrichment").iter()
            .filter(|r| r.get("about").and_then(Value::as_str)
                    == Some(identifier))
            .filter(|r| {
                let rid = s(r.get("id").unwrap_or(&Value::Null));
                include_retracted || !retracted.contains(&rid)
            })
            .map(|r| (*r).clone())
            .collect()
    }

    // ------------------------------------------------- materialized views
    /// (active, excluded) for subsumes/part_of after rule 13 cycle-breaking.
    pub fn active_taxonomy_edges(&self, field: &str)
        -> (Vec<Map<String, Value>>, Vec<Map<String, Value>>) {
        let retracted = self.retracted_ids();
        let mut active: Vec<Map<String, Value>> = self
            .records_of("enrichment").iter()
            .filter(|r| r.get("field").and_then(Value::as_str) == Some(field))
            .filter(|r| !retracted.contains(
                &s(r.get("id").unwrap_or(&Value::Null))))
            .map(|r| (*r).clone())
            .collect();
        let mut excluded = Vec::new();
        loop {
            let cycle = Self::find_cycle_records(&active);
            if cycle.is_empty() {
                break;
            }
            // exclude the cycle record with the LATEST timestamp,
            // ties broken by lexicographic record identifier
            let loser_key = cycle.iter()
                .map(|r| (s(r.get("timestamp").unwrap_or(&Value::Null)),
                          s(r.get("id").unwrap_or(&Value::Null))))
                .max()
                .unwrap();
            let pos = active.iter().position(|r|
                (s(r.get("timestamp").unwrap_or(&Value::Null)),
                 s(r.get("id").unwrap_or(&Value::Null))) == loser_key)
                .unwrap();
            excluded.push(active.remove(pos));
        }
        (active, excluded)
    }

    fn find_cycle_records(recs: &[Map<String, Value>])
                          -> Vec<Map<String, Value>> {
        // edges: about -> [(entry, record)] in insertion order
        let mut edges: HashMap<String, Vec<(String, &Map<String, Value>)>> =
            HashMap::new();
        let mut node_order: Vec<String> = Vec::new();
        for r in recs {
            let about = s(r.get("about").unwrap_or(&Value::Null));
            let entry = s(r.get("entry").unwrap_or(&Value::Null));
            if !edges.contains_key(&about) {
                node_order.push(about.clone());
            }
            edges.entry(about).or_default().push((entry, r));
        }
        // iterative DFS with gray-node detection, mirroring the Python
        fn dfs<'a>(node: &str,
                   path: &mut Vec<&'a Map<String, Value>>,
                   state: &mut HashMap<String, u8>,
                   edges: &HashMap<String, Vec<(String, &'a Map<String, Value>)>>,
                   cycle: &mut Vec<Map<String, Value>>) -> bool {
            state.insert(node.to_string(), 1);
            if let Some(next) = edges.get(node) {
                for (target, record) in next {
                    let st = *state.get(target).unwrap_or(&0);
                    if st == 1 {
                        for r in path.iter() {
                            cycle.push((*r).clone());
                        }
                        cycle.push((*record).clone());
                        return true;
                    }
                    if st == 0 {
                        path.push(record);
                        if dfs(target, path, state, edges, cycle) {
                            return true;
                        }
                        path.pop();
                    }
                }
            }
            state.insert(node.to_string(), 2);
            false
        }
        let mut state: HashMap<String, u8> = HashMap::new();
        let mut cycle = Vec::new();
        for start in &node_order {
            if *state.get(start).unwrap_or(&0) == 0 {
                let mut path = Vec::new();
                if dfs(start, &mut path, &mut state, &edges, &mut cycle) {
                    return cycle;
                }
            }
        }
        Vec::new()
    }

    fn would_cycle(&self, record: &Map<String, Value>, field: &str) -> bool {
        let retracted = self.retracted_ids();
        let mut recs: Vec<Map<String, Value>> = self
            .records_of("enrichment").iter()
            .filter(|r| r.get("field").and_then(Value::as_str) == Some(field))
            .filter(|r| !retracted.contains(
                &s(r.get("id").unwrap_or(&Value::Null))))
            .map(|r| (*r).clone())
            .collect();
        recs.push(record.clone());
        !Self::find_cycle_records(&recs).is_empty()
    }

    /// The object with its materialized enrichment sets and contributors.
    pub fn get(&self, identifier: &str, view: &str) -> Option<Value> {
        let obj = self.objects.get(identifier)?;
        let include_retracted = view == "history";
        let mut excluded_ids = HashSet::new();
        for field in ["subsumes", "part_of"] {
            let (_, excluded) = self.active_taxonomy_edges(field);
            for r in excluded {
                excluded_ids.insert(s(r.get("id").unwrap_or(&Value::Null)));
            }
        }
        // field -> entry-canonical-key -> (entry, contributors)
        let mut fields: Vec<(String, Vec<(String, Value, Vec<Value>)>)> =
            Vec::new();
        for rec in self.enrichments_about(identifier, include_retracted) {
            let rid = s(rec.get("id").unwrap_or(&Value::Null));
            if excluded_ids.contains(&rid) && view != "history" {
                continue;
            }
            let field = s(rec.get("field").unwrap_or(&Value::Null));
            let entry = rec.get("entry").cloned().unwrap_or(Value::Null);
            let entry_key = crate::canonical::jcs(&entry)
                .unwrap_or_default();
            let mut contributor = Map::new();
            contributor.insert("source".into(),
                               rec.get("source").cloned()
                               .unwrap_or(Value::Null));
            contributor.insert("timestamp".into(),
                               rec.get("timestamp").cloned()
                               .unwrap_or(Value::Null));
            let slot = match fields.iter_mut().find(|(f, _)| *f == field) {
                Some((_, slot)) => slot,
                None => {
                    fields.push((field.clone(), Vec::new()));
                    &mut fields.last_mut().unwrap().1
                }
            };
            match slot.iter_mut().find(|(k, _, _)| *k == entry_key) {
                Some((_, _, contributors)) => {
                    contributors.push(Value::Object(contributor));
                }
                None => {
                    slot.push((entry_key, entry,
                               vec![Value::Object(contributor)]));
                }
            }
        }
        let mut enrichments = Map::new();
        for (field, slot) in fields {
            let entries: Vec<Value> = slot.into_iter()
                .map(|(_, entry, contributors)| {
                    let mut e = Map::new();
                    e.insert("entry".into(), entry);
                    e.insert("contributors".into(), Value::Array(contributors));
                    Value::Object(e)
                })
                .collect();
            enrichments.insert(field, Value::Array(entries));
        }
        let mut out = Map::new();
        out.insert("object".into(), Value::Object(obj.clone()));
        if view != "raw" {
            out.insert("enrichments".into(), Value::Object(enrichments));
        }
        Some(Value::Object(out))
    }

    // -------------------------------------------------------------- resolve
    fn canon_label(text: &str) -> String {
        text.trim().to_lowercase().split_whitespace()
            .collect::<Vec<_>>().join("_")
    }

    fn norm_alias(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
    }

    /// The conformance minimum: exact label, then alias, then nothing.
    pub fn resolve(&self, text: &str, lang: Option<&str>) -> Vec<String> {
        let mut label_hits = Vec::new();
        let mut alias_hits = Vec::new();
        let wanted_label = Self::canon_label(text);
        let wanted_alias = Self::norm_alias(text);
        let retracted = self.retracted_ids();
        for oid in &self.object_order {
            let obj = &self.objects[oid];
            let kind = obj.get("type").and_then(Value::as_str).unwrap_or("");
            if kind != "occurrent" && kind != "continuant" {
                continue;
            }
            if obj.get("label").and_then(Value::as_str)
                == Some(wanted_label.as_str()) {
                label_hits.push(oid.clone());
                continue;
            }
            for rec in self.records_of("enrichment") {
                if rec.get("about").and_then(Value::as_str)
                    != Some(oid.as_str())
                    || rec.get("field").and_then(Value::as_str)
                        != Some("aliases") {
                    continue;
                }
                if retracted.contains(
                    &s(rec.get("id").unwrap_or(&Value::Null))) {
                    continue;
                }
                let entry = match rec.get("entry") {
                    Some(Value::Object(e)) => e,
                    _ => continue,
                };
                if let Some(want_lang) = lang {
                    if entry.get("lang").and_then(Value::as_str)
                        != Some(want_lang) {
                        continue;
                    }
                }
                let alias = entry.get("text").and_then(Value::as_str)
                    .unwrap_or("");
                if Self::norm_alias(alias) == wanted_alias {
                    alias_hits.push(oid.clone());
                    break;
                }
            }
        }
        label_hits.extend(alias_hits);
        label_hits
    }

    // ---------------------------------------------------------------- gaps
    /// The stigmergy read - the store-computable gap kinds.
    pub fn gaps(&self, kind: Option<&str>) -> Vec<Map<String, Value>> {
        let mut out: Vec<Map<String, Value>> = Vec::new();
        let mut refined: HashSet<String> = HashSet::new();
        for oid in &self.object_order {
            let obj = &self.objects[oid];
            if obj.get("type").and_then(Value::as_str) == Some("cro") {
                if let Some(parent_id) =
                    obj.get("refines").and_then(Value::as_str) {
                    if let Some(parent) = self.objects.get(parent_id) {
                        let (ok, _) = refinement_valid(obj, parent);
                        if ok {
                            refined.insert(parent_id.to_string());
                        }
                    }
                }
            }
        }
        for oid in &self.object_order {
            let obj = &self.objects[oid];
            if obj.get("type").and_then(Value::as_str) != Some("cro") {
                continue;
            }
            // missing_field: lacking the temporal window or the modality
            if (!obj.contains_key("temporal") || !obj.contains_key("modality"))
                && !refined.contains(oid) {
                let mut g = Map::new();
                g.insert("id".into(), Value::String(oid.clone()));
                g.insert("kind".into(), Value::String("missing_field".into()));
                let (_, missing) = is_partial(obj);
                g.insert("missing".into(), Value::Array(
                    missing.into_iter().map(Value::String).collect()));
                out.push(g);
            }
            let empty_mech = match obj.get("mechanism") {
                None => true,
                Some(Value::Array(m)) => m.is_empty(),
                _ => false,
            };
            if empty_mech && !refined.contains(oid) {
                let mut g = Map::new();
                g.insert("id".into(), Value::String(oid.clone()));
                g.insert("kind".into(),
                         Value::String("empty_mechanism".into()));
                out.push(g);
            }
        }
        for field in ["subsumes", "part_of"] {
            let (_, excluded) = self.active_taxonomy_edges(field);
            for rec in excluded {
                let mut g = Map::new();
                g.insert("id".into(),
                         rec.get("id").cloned().unwrap_or(Value::Null));
                g.insert("kind".into(),
                         Value::String("inconsistent_hierarchy".into()));
                g.insert("note".into(), Value::String(
                    "excluded by the deterministic cycle-breaking view rule"
                        .into()));
                out.push(g);
            }
        }
        // dangling_reference
        for oid in &self.object_order {
            let obj = &self.objects[oid];
            let mut refs: Vec<String> = Vec::new();
            match obj.get("type").and_then(Value::as_str) {
                Some("cro") => {
                    for f in ["causes", "effects", "context", "mechanism"] {
                        if let Some(Value::Array(items)) = obj.get(f) {
                            refs.extend(items.iter()
                                .filter_map(|x| x.as_str().map(String::from)));
                        }
                    }
                    if let Some(r) = obj.get("refines").and_then(Value::as_str) {
                        refs.push(r.to_string());
                    }
                }
                Some("realizable") => {
                    if let Some(b) = obj.get("bearer").and_then(Value::as_str) {
                        refs.push(b.to_string());
                    }
                }
                _ => {}
            }
            for r in refs {
                if !self.objects.contains_key(&r) {
                    let mut g = Map::new();
                    g.insert("id".into(), Value::String(oid.clone()));
                    g.insert("kind".into(),
                             Value::String("dangling_reference".into()));
                    g.insert("ref".into(), Value::String(r));
                    out.push(g);
                }
            }
        }
        // conflict pairs
        let cros: Vec<&String> = self.object_order.iter()
            .filter(|oid| self.objects[*oid].get("type")
                    .and_then(Value::as_str) == Some("cro"))
            .collect();
        for i in 0..cros.len() {
            for j in (i + 1)..cros.len() {
                let a = &self.objects[cros[i]];
                let b = &self.objects[cros[j]];
                if crate::semantics::conflicts(a, b) {
                    let mut g = Map::new();
                    g.insert("kind".into(), Value::String("conflict".into()));
                    g.insert("a".into(), Value::String(cros[i].clone()));
                    g.insert("b".into(), Value::String(cros[j].clone()));
                    out.push(g);
                }
            }
        }
        if let Some(k) = kind {
            out.retain(|g| g.get("kind").and_then(Value::as_str) == Some(k));
        }
        out
    }
}

// conformance.cpp - the Causalontology conformance runner for
// causalontology-cpp.
//
// Runs every vector in conformance/vectors/ against the C++ binding. An
// implementation is conformant if and only if it passes every vector; this
// runner exits nonzero on any failure. It mirrors
// bindings/python/tests/run_conformance.py exactly.
//
// The vectors are frozen at specification 2.0.0: they carry concrete
// 64-hex identifiers and real Ed25519 keys, which pass through the
// normalizer unchanged. Behavioral vectors derive deterministic keypairs
// from the seed sha256("key:" + name).

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "src/canonical.hpp"
#include "src/ed25519.hpp"
#include "src/jcs.hpp"
#include "src/json.hpp"
#include "src/schema.hpp"
#include "src/semantics.hpp"
#include "src/sha2.hpp"
#include "src/signing.hpp"
#include "src/store.hpp"

namespace fs = std::filesystem;
using namespace co;

namespace {

// ---------------------------------------------------------------- helpers

std::string g_vecdir;

[[noreturn]] void failCheck(const std::string& why) {
    throw std::runtime_error(why);
}

void check(bool ok, const std::string& why) {
    if (!ok) failCheck(why);
}

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path);
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

// Locate the repository root: $CAUSALONTOLOGY_ROOT, else walk upward from
// the current directory until conformance/vectors appears.
std::string findRoot() {
    const char* env = std::getenv("CAUSALONTOLOGY_ROOT");
    if (env && *env) return env;
    fs::path cursor = fs::current_path();
    while (true) {
        if (fs::is_directory(cursor / "conformance" / "vectors"))
            return cursor.string();
        if (cursor == cursor.parent_path()) break;
        cursor = cursor.parent_path();
    }
    throw std::runtime_error(
        "repository root not found; set CAUSALONTOLOGY_ROOT");
}

// The vector file (path, stem) for vector n.
std::pair<std::string, std::string> vectorFile(int n) {
    char prefix[8];
    std::snprintf(prefix, sizeof prefix, "v%02d_", n);
    for (const auto& entry : fs::directory_iterator(g_vecdir)) {
        std::string name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0 &&
            name.size() > 5 && name.substr(name.size() - 5) == ".json")
            return {entry.path().string(), entry.path().stem().string()};
    }
    throw std::runtime_error(std::string("vector not found: ") + prefix);
}

JValue vec(int n) { return json_parse(readFile(vectorFile(n).first)); }

// ------------------------------------- symbolic-identifier normalization

std::map<std::string, std::pair<std::string, std::string>> g_keys;

// A real, deterministic Ed25519 keypair for a symbolic key name.
const std::pair<std::string, std::string>& key(const std::string& name) {
    auto hit = g_keys.find(name);
    if (hit != g_keys.end()) return hit->second;
    std::string seed = sha256("key:" + name);
    return g_keys.emplace(name, keypair_from_seed(seed)).first->second;
}

bool is64hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool isScheme(const std::string& s) {
    static const std::vector<std::string> schemes = {
        "occurrent", "causal_relation_object", "continuant", "realizable",
        "assertion", "enrichment", "retraction", "succession",
        "stratum", "bridge", "port", "conduit", "quality",
        "token_individual", "token_occurrence", "state_assertion",
        "token_causal_claim", "ed25519"};
    for (const auto& scheme : schemes)
        if (s == scheme) return true;
    return false;
}

// Normalize one symbolic identifier to a well-formed one.
std::string sym(const std::string& s) {
    size_t colon = s.find(':');
    std::string scheme = s.substr(0, colon);
    std::string name = s.substr(colon + 1);
    if (scheme == "ed25519") {
        if (is64hex(name)) return s;  // frozen: a real key passes through
        return key(name).second;
    }
    if (is64hex(name)) return s;
    return scheme + ":" + sha256_hex(name);
}

// Recursively normalize symbolic identifiers and placeholders.
JValue normalize(const JValue& x) {
    if (x.isString()) {
        if (x.str == "<128 hex>") {
            std::string out;
            for (int i = 0; i < 64; ++i) out += "ab";
            return JValue::of(out);
        }
        size_t colon = x.str.find(':');
        if (colon != std::string::npos && isScheme(x.str.substr(0, colon)))
            return JValue::of(sym(x.str));
        return x;
    }
    if (x.isArray()) {
        JValue out = JValue::makeArray();
        for (const JValue& v : x.array) out.array.push_back(normalize(v));
        return out;
    }
    if (x.isObject()) {
        JValue out = JValue::makeObject();
        for (const auto& kv : x.object)
            out.object.emplace_back(kv.first, normalize(kv.second));
        return out;
    }
    return x;
}

std::string ts(int i) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "2026-07-13T0%d:00:00Z", i);
    return buf;
}

// Build, timestamp, and sign a provenance record.
JValue makeSigned(const std::string& kind, JValue body,
                  const std::string& who, int tsIndex = 0) {
    const auto& [secret, pub] = key(who);
    body.set("type", JValue::of(kind));
    body.setDefault("timestamp", JValue::of(ts(tsIndex)));
    if (kind == "succession")
        body.setDefault("predecessor", JValue::of(pub));
    else
        body.set("source", JValue::of(pub));
    return sign_record(body, secret, kind);
}

bool contains(const std::vector<std::string>& reasons,
              const std::string& needle) {
    for (const auto& r : reasons)
        if (r.find(needle) != std::string::npos) return true;
    return false;
}

// -------------------------------------------------------- internal checks

void internalChecks() {
    // SHA-2 empty-string known answers.
    check(sha256_hex("") ==
              "e3b0c44298fc1c149afbf4c8996fb924"
              "27ae41e4649b934ca495991b7852b855",
          "sha256 empty-string known answer");
    check(to_hex(sha512("")).substr(0, 8) == "cf83e135",
          "sha512 empty-string known answer");
    // RFC 8032, TEST 1 known-answer.
    std::string sk;
    check(from_hex("9d61b19deffd5a60ba844af492ec2cc4"
                   "4449c5697b326919703bac031cae7f60", sk),
          "hex decode");
    std::string pk = ed25519::secret_to_public(sk);
    check(to_hex(pk) ==
              "d75a980182b10ab7d54bfed3c964073a"
              "0ee172f3daa62325af021a68f707511a",
          "RFC 8032 TEST 1 public key: got " + to_hex(pk));
    std::string sig = ed25519::sign(sk, "");
    check(to_hex(sig) ==
              "e5564300c360ac729086e2cc806e828a"
              "84877f1eb8e5d974d873e06522490155"
              "5fb8821590a33bacc61e39701cf9b46b"
              "d25bf5f0595bbe24655141438e7a100b",
          "RFC 8032 TEST 1 signature: got " + to_hex(sig));
    check(ed25519::verify(pk, "", sig), "TEST 1 signature must verify");
    check(!ed25519::verify(pk, "x", sig), "wrong message must not verify");
    // JCS basics.
    JValue o = JValue::makeObject();
    o.set("b", JValue::of(2));
    o.set("a", JValue::of(1));
    check(jcs(o) == "{\"a\":1,\"b\":2}", "JCS key ordering");
    check(jcs(JValue::of(1.0)) == "1", "JCS 1.0 -> 1");
    check(jcs(JValue::of(6.000)) == "6", "JCS 6.000 -> 6");
    check(jcs(JValue::of(0.7)) == "0.7", "JCS 0.7 stays 0.7");
    check(to_seconds(1, "months") == 2629746, "months constant");
    check(to_seconds(1, "years") == 31556952, "years constant");
}

// ----------------------------------------------------------- object builders

// A content object completed with its real content-addressed id.
JValue mk(JValue o) {
    o.set("id", JValue::of(identify(o)));
    return o;
}

JValue strv(const std::vector<std::string>& items) {
    JValue a = JValue::makeArray();
    for (const std::string& s : items) a.array.push_back(JValue::of(s));
    return a;
}

JValue buildStratum(const std::string& label, const std::string& scheme,
                    int ordinal, const std::string& unit = "",
                    const std::vector<std::string>& governs = {}) {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("stratum"));
    o.set("label", JValue::of(label));
    o.set("scheme", JValue::of(scheme));
    o.set("ordinal", JValue::of(ordinal));
    if (!unit.empty()) o.set("unit", JValue::of(unit));
    if (!governs.empty()) o.set("governs", strv(governs));
    return mk(std::move(o));
}

JValue buildOcc(const std::string& label, const std::string& stratumId = "",
                const std::string& category = "event") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("occurrent"));
    o.set("label", JValue::of(label));
    o.set("category", JValue::of(category));
    if (!stratumId.empty()) o.set("stratum", JValue::of(stratumId));
    return mk(std::move(o));
}

JValue buildCnt(const std::string& label, const std::string& category = "object") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("continuant"));
    o.set("label", JValue::of(label));
    o.set("category", JValue::of(category));
    return mk(std::move(o));
}

// A CRO from cause/effect id lists, with optional extra fields patched in.
JValue buildCro(const std::vector<std::string>& causes,
                const std::vector<std::string>& effects,
                const std::function<void(JValue&)>& patch = nullptr) {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("causal_relation_object"));
    o.set("causes", strv(causes));
    o.set("effects", strv(effects));
    if (patch) patch(o);
    return mk(std::move(o));
}

JValue buildBridge(const std::string& coarse,
                   const std::vector<std::string>& fine,
                   const std::string& relation) {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("bridge"));
    o.set("coarse", JValue::of(coarse));
    o.set("fine", strv(fine));
    o.set("relation", JValue::of(relation));
    return mk(std::move(o));
}

JValue buildPort(const std::string& bearer, const std::string& label,
                 const std::string& direction,
                 const std::vector<std::string>& accepts,
                 const std::string& realizable = "") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("port"));
    o.set("bearer", JValue::of(bearer));
    o.set("label", JValue::of(label));
    o.set("direction", JValue::of(direction));
    o.set("accepts", strv(accepts));
    if (!realizable.empty()) o.set("realizable", JValue::of(realizable));
    return mk(std::move(o));
}

JValue buildConduit(const std::string& frm, const std::string& to,
                    const std::vector<std::string>& carries,
                    const std::string& label = "conn",
                    const std::string& transform = "") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("conduit"));
    o.set("label", JValue::of(label));
    o.set("from", JValue::of(frm));
    o.set("to", JValue::of(to));
    o.set("carries", strv(carries));
    if (!transform.empty()) o.set("transform", JValue::of(transform));
    return mk(std::move(o));
}

JValue buildQuality(const std::string& label, const std::string& datatype,
                    const std::string& unit = "",
                    const std::string& stratumId = "") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("quality"));
    o.set("label", JValue::of(label));
    o.set("datatype", JValue::of(datatype));
    if (!unit.empty()) o.set("unit", JValue::of(unit));
    if (!stratumId.empty()) o.set("stratum", JValue::of(stratumId));
    return mk(std::move(o));
}

JValue buildRlz(const std::string& bearer, const std::string& kind,
                const std::string& label = "") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("realizable"));
    o.set("kind", JValue::of(kind));
    o.set("bearer", JValue::of(bearer));
    if (!label.empty()) o.set("label", JValue::of(label));
    return mk(std::move(o));
}

JValue buildIndividual(const std::string& instantiates,
                       const std::string& designator = "",
                       const std::string& partOf = "") {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("token_individual"));
    o.set("instantiates", JValue::of(instantiates));
    if (!designator.empty()) o.set("designator", JValue::of(designator));
    if (!partOf.empty()) o.set("part_of", JValue::of(partOf));
    return mk(std::move(o));
}

JValue interval(const std::string& start, const std::string& end = "",
                int open = -1) {
    JValue iv = JValue::makeObject();
    iv.set("start", JValue::of(start));
    if (!end.empty()) iv.set("end", JValue::of(end));
    if (open >= 0) iv.set("open", JValue::of(open != 0));
    return iv;
}

JValue buildToken(const std::string& instantiates, JValue iv,
                  JValue participants = JValue()) {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("token_occurrence"));
    o.set("instantiates", JValue::of(instantiates));
    o.set("interval", std::move(iv));
    if (participants.isArray()) o.set("participants", std::move(participants));
    return mk(std::move(o));
}

JValue buildState(const std::string& subject, const std::string& qual,
                  JValue value, JValue iv) {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("state_assertion"));
    o.set("subject", JValue::of(subject));
    o.set("quality", JValue::of(qual));
    o.set("value", std::move(value));
    o.set("interval", std::move(iv));
    return mk(std::move(o));
}

JValue buildTcc(const std::vector<std::string>& causes,
                const std::vector<std::string>& effects,
                const std::string& coveringLaw = "",
                JValue actualDelay = JValue(), int counterfactual = -1) {
    JValue o = JValue::makeObject();
    o.set("type", JValue::of("token_causal_claim"));
    o.set("causes", strv(causes));
    o.set("effects", strv(effects));
    if (!coveringLaw.empty()) o.set("covering_law", JValue::of(coveringLaw));
    if (actualDelay.isObject()) o.set("actual_delay", std::move(actualDelay));
    if (counterfactual >= 0)
        o.set("counterfactual", JValue::of(counterfactual != 0));
    return mk(std::move(o));
}

JValue delayObj(double duration, const std::string& unit) {
    JValue d = JValue::makeObject();
    d.set("duration", JValue::of(duration));
    d.set("unit", JValue::of(unit));
    return d;
}

JValue temporalObj(double lo, double hi, const std::string& unit) {
    JValue t = JValue::makeObject();
    t.set("minimum_delay", JValue::of(lo));
    t.set("maximum_delay", JValue::of(hi));
    t.set("unit", JValue::of(unit));
    return t;
}

// The neuroendocrine stratum fixture (ordinal -> stratum object).
std::map<int, JValue> neuro() {
    std::map<int, std::string> labels = {
        {4, "macromolecular"}, {5, "subcellular"}, {6, "cellular"},
        {7, "synaptic"}, {9, "region"}, {14, "community_and_society"}};
    std::map<int, JValue> out;
    for (const auto& [ord, label] : labels)
        out[ord] = buildStratum(label, "neuroendocrine", ord);
    return out;
}

std::string join(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v) out += s + "; ";
    return out;
}

// ----------------------------------------------------------- the vectors

void v01() {
    JValue inp = normalize(vec(1).at("input"));
    auto [schemaOk, schemaWhy] = validate_schema(inp);
    check(schemaOk, join(schemaWhy));
    auto [semOk, semWhy] = validate_semantics(inp);
    check(semOk, join(semWhy));
}

void v02() {
    JValue inp = normalize(vec(2).at("input"));
    check(validate_schema(inp).first, "schema");
    check(validate_semantics(inp).first, "semantics");
    auto [partial, missing] = is_partial(inp);
    check(partial, "expected partial");
    JValue got = JValue::makeArray();
    for (const auto& m : missing) got.array.push_back(JValue::of(m));
    check(got == vec(2).at("expect").at("missing"), "missing list mismatch");
}

void schemaFails(int n, const std::string& mustMention) {
    JValue inp = normalize(vec(n).at("input"));
    auto [ok, why] = validate_schema(inp);
    check(!ok, "expected schema-invalid");
    check(contains(why, mustMention),
          "reasons do not mention '" + mustMention + "': " + join(why));
}

void v03() { schemaFails(3, "effects"); }
void v04() { schemaFails(4, "causes"); }
void v05() { schemaFails(5, "modality"); }
void v06() { schemaFails(6, "colour"); }
void v07() { schemaFails(7, "causes"); }

void v08() {
    auto [ok, why] = validate_schema(normalize(vec(8).at("input")));
    check(ok, join(why));
}

void v09() { schemaFails(9, "label"); }
void v10() { schemaFails(10, "category"); }

void v11() {
    auto [ok, why] = validate_schema(normalize(vec(11).at("input")));
    check(ok, join(why));
}

void v12() { schemaFails(12, "confidence"); }

void v13() {
    JValue inp = normalize(vec(13).at("input"));
    auto [schemaOk, schemaWhy] = validate_schema(inp);
    check(schemaOk, join(schemaWhy));
    auto [semOk, semWhy] = validate_semantics(inp);
    check(semOk, join(semWhy));
}

void semanticsFails(int n, const std::string& mustMention) {
    JValue inp = normalize(vec(n).at("input"));
    auto [ok, why] = validate_semantics(inp);
    check(!ok, "expected semantically-invalid");
    check(contains(why, mustMention),
          "reasons do not mention '" + mustMention + "': " + join(why));
}

void v14() {
    JValue inp = normalize(vec(14).at("input"));
    check(validate_schema(inp).first, "schema");
    semanticsFails(14, "minimum_delay");
}

void v15() { semanticsFails(15, "acyclic"); }
void v16() { semanticsFails(16, "acyclic"); }

void v17() {
    JValue v = vec(17);
    JValue parent = normalize(v.at("given").at("parent"));
    JValue child = normalize(v.at("input"));
    auto [ok, reason] = refinement_valid(child, parent);
    check(!ok && reason.find("rival") != std::string::npos, reason);
}

void v18() { semanticsFails(18, "not a legal field"); }
void v19() { semanticsFails(19, "language-tagged"); }

void v20() {
    std::string dog = sym("continuant:dog"), mam = sym("continuant:mammal"),
                ani = sym("continuant:animal");
    auto enrich = [](const std::string& about, const std::string& entry,
                     int i) {
        JValue body = JValue::makeObject();
        body.set("about", JValue::of(about));
        body.set("field", JValue::of("subsumes"));
        body.set("entry", JValue::of(entry));
        return makeSigned("enrichment", body, "taxo", i);
    };
    // enforcing tier rejects the cycle-completing write
    InMemoryStore s(true);
    s.put_record(enrich(dog, mam, 1));
    s.put_record(enrich(mam, ani, 2));
    bool rejected = false;
    try {
        s.put_record(enrich(ani, dog, 3));
    } catch (const RejectedWrite& e) {
        rejected = true;
        check(std::string(e.what()).find("cycle") != std::string::npos,
              e.what());
    }
    check(rejected, "enforcing store accepted a cycle");
    // decentralized merge: the view breaks the cycle deterministically
    InMemoryStore s2(true);
    s2.put_record(enrich(dog, mam, 1));
    s2.put_record(enrich(mam, ani, 2));
    JValue bad = enrich(ani, dog, 3);
    s2.force_merge_record(bad);
    auto [active, excluded] = s2.active_taxonomy_edges("subsumes");
    (void)active;
    check(excluded.size() == 1 &&
              excluded[0].getString("id") == bad.getString("id"),
          "wrong record excluded");
    bool inRepair = false;
    for (const JValue& g : s2.gaps("inconsistent_hierarchy"))
        if (g.getString("id") == bad.getString("id")) inRepair = true;
    check(inRepair, "excluded record must surface as a repair gap");
}

bool adm(int n) {
    JValue g = vec(n).at("given");
    JValue cro = JValue::makeObject();
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occurrent:c")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occurrent:e")));
    cro.set("causes", std::move(causes));
    cro.set("effects", std::move(effects));
    cro.set("temporal", g.at("temporal"));
    return admissible(cro, g.at("elapsed_seconds").asDouble());
}

void v21() { check(adm(21) == true, "expected admissible"); }
void v22() { check(adm(22) == false, "expected not admissible"); }
void v23() { check(adm(23) == true, "expected admissible"); }

void v24() {
    JValue v = vec(24);
    check(identify(normalize(v.at("inputA"))) ==
              identify(normalize(v.at("inputB"))),
          "identifiers differ");
}

void v25() {
    JValue v = vec(25);
    check(identify(normalize(v.at("inputA"))) ==
              identify(normalize(v.at("inputB"))),
          "identifiers differ");
}

JValue occurrentPressButton() {
    JValue obj = JValue::makeObject();
    obj.set("type", JValue::of("occurrent"));
    obj.set("label", JValue::of("press_button"));
    obj.set("category", JValue::of("action"));
    return obj;
}

void v26() {
    InMemoryStore s;
    JValue obj = occurrentPressButton();
    std::string a = s.put(obj);
    std::string b = s.put(obj);
    check(a == b && s.object_count() == 1, "put is not idempotent");
}

void v27() {
    InMemoryStore s;
    std::string occ = s.put(occurrentPressButton());
    JValue entry = JValue::makeObject();
    entry.set("lang", JValue::of("en"));
    entry.set("text", JValue::of("press the button"));
    auto enrichment = [&](const std::string& who, int i) {
        JValue body = JValue::makeObject();
        body.set("about", JValue::of(occ));
        body.set("field", JValue::of("aliases"));
        body.set("entry", entry);
        return makeSigned("enrichment", body, who, i);
    };
    std::string r1 = s.put_record(enrichment("alice", 1));
    std::string r2 = s.put_record(enrichment("bob", 2));
    check(r1 != r2, "two sources must yield two records");
    JValue view = s.get(occ)->at("enrichments").at("aliases");
    check(view.array.size() == 1, "one materialized entry expected");
    check(view.array[0].at("contributors").array.size() == 2,
          "two contributors expected");
}

void v28() {
    InMemoryStore s;
    JValue claim = JValue::makeObject();
    claim.set("type", JValue::of("causal_relation_object"));
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occurrent:A")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occurrent:B")));
    claim.set("causes", std::move(causes));
    claim.set("effects", std::move(effects));
    claim.set("modality", JValue::of("sufficient"));
    std::string i1 = s.put(claim);
    std::string i2 = s.put(claim);
    check(i1 == i2 && s.object_count() == 1, "one object expected");
    for (const auto& [who, tsIndex] :
         std::vector<std::pair<std::string, int>>{{"lab1", 1}, {"lab2", 2}}) {
        JValue body = JValue::makeObject();
        body.set("about", JValue::of(i1));
        body.set("evidence_type", JValue::of("observation"));
        body.set("strength", JValue::of(0.8));
        body.set("confidence", JValue::of(0.8));
        s.put_record(makeSigned("assertion", body, who, tsIndex));
    }
    check(s.assertions_about(i1).size() == 2, "two assertions expected");
}

JValue demoAssertion() {
    JValue body = JValue::makeObject();
    body.set("about", JValue::of(sym("causal_relation_object:demo")));
    body.set("evidence_type", JValue::of("intervention"));
    body.set("strength", JValue::of(0.7));
    body.set("confidence", JValue::of(0.9));
    return makeSigned("assertion", body, "signer");
}

void v29() { check(verify_record(demoAssertion()) == true, "must verify"); }

void v30() {
    JValue tampered = demoAssertion();
    tampered.set("confidence", JValue::of(0.1));
    check(verify_record(tampered) == false, "tampered must not verify");
}

void v31() {
    InMemoryStore s;
    JValue claim = JValue::makeObject();
    claim.set("type", JValue::of("causal_relation_object"));
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occurrent:A")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occurrent:B")));
    claim.set("causes", std::move(causes));
    claim.set("effects", std::move(effects));
    std::string x = s.put(claim);
    JValue aBody = JValue::makeObject();
    aBody.set("about", JValue::of(x));
    aBody.set("evidence_type", JValue::of("observation"));
    aBody.set("confidence", JValue::of(0.8));
    JValue a = makeSigned("assertion", aBody, "lab1", 1);
    s.put_record(a);
    JValue rBody = JValue::makeObject();
    rBody.set("retracts", JValue::of(a.getString("id")));
    s.put_record(makeSigned("retraction", rBody, "lab1", 2));
    check(s.assertions_about(x).empty(), "default view must exclude");
    std::vector<JValue> hist = s.assertions_about(x, true);
    check(hist.size() == 1, "history must include");
    check(hist[0].at("retracted") == JValue::of(true), "retracted flag");
    JValue fBody = JValue::makeObject();
    fBody.set("retracts", JValue::of(a.getString("id")));
    JValue foreign = makeSigned("retraction", fBody, "mallory", 3);
    bool rejected = false;
    try {
        s.put_record(foreign);
    } catch (const RejectedWrite&) {
        rejected = true;
    }
    check(rejected, "foreign retraction accepted");
    check(s.assertions_about(x).empty(), "still excluded by lab1's own");
    check(s.assertions_about(x, true).size() == 1, "history unchanged");
}

void v32() {
    InMemoryStore s;
    std::string occ = s.put(occurrentPressButton());
    JValue entry = JValue::makeObject();
    entry.set("lang", JValue::of("ja"));
    entry.set("text", JValue::of("botan"));
    JValue eBody = JValue::makeObject();
    eBody.set("about", JValue::of(occ));
    eBody.set("field", JValue::of("aliases"));
    eBody.set("entry", std::move(entry));
    JValue e = makeSigned("enrichment", eBody, "bob", 1);
    s.put_record(e);
    {
        JValue view = *s.get(occ);
        const JValue* aliases = view.at("enrichments").find("aliases");
        check(aliases && aliases->array.size() == 1, "one alias expected");
    }
    JValue rBody = JValue::makeObject();
    rBody.set("retracts", JValue::of(e.getString("id")));
    s.put_record(makeSigned("retraction", rBody, "bob", 2));
    {
        JValue view = *s.get(occ);
        const JValue* aliases = view.at("enrichments").find("aliases");
        check(!aliases || aliases->array.empty(),
              "alias must leave the default view");
    }
    {
        JValue view = *s.get(occ, "history");
        const JValue* aliases = view.at("enrichments").find("aliases");
        check(aliases && aliases->array.size() == 1,
              "history must keep the alias");
    }
}

void v33() {
    InMemoryStore s;
    std::string k1 = key("K1").second;
    std::string k2 = key("K2").second;
    JValue aBody = JValue::makeObject();
    aBody.set("about", JValue::of(sym("causal_relation_object:claim")));
    aBody.set("evidence_type", JValue::of("observation"));
    aBody.set("confidence", JValue::of(0.9));
    JValue a = makeSigned("assertion", aBody, "K1", 1);
    s.put_record(a);
    JValue sBody = JValue::makeObject();
    sBody.set("successor", JValue::of(k2));
    JValue succ = makeSigned("succession", sBody, "K1", 2);
    s.put_record(succ);
    check(s.lineage(k2).count(k1) == 1, "K1 must be in K2's lineage");
    check(s.lineage(k1).count(k2) == 1, "K2 must be in K1's lineage");
    JValue rBody = JValue::makeObject();
    rBody.set("retracts", JValue::of(a.getString("id")));
    JValue r = makeSigned("retraction", rBody, "K2", 3);
    s.put_record(r);  // successor may retract the predecessor's record
    check(s.assertions_about(sym("causal_relation_object:claim")).empty(),
          "the retraction must take effect");
}

void v34() {
    JValue g = normalize(vec(34).at("given"));
    check(conflicts(g.at("A"), g.at("B")) == true, "must conflict");
}

void v35() {
    JValue g = normalize(vec(35).at("given"));
    check(conflicts(g.at("A"), g.at("B")) == false, "must not conflict");
}

void v36() {
    std::string A = sym("occurrent:A"), B = sym("occurrent:B"), C = sym("occurrent:C"),
                D = sym("occurrent:D");
    auto makeCro = [](const std::string& id, const std::string& cause,
                      const std::string& effect) {
        JValue m = JValue::makeObject();
        m.set("id", JValue::of(id));
        JValue causes = JValue::makeArray();
        causes.array.push_back(JValue::of(cause));
        JValue effects = JValue::makeArray();
        effects.array.push_back(JValue::of(effect));
        m.set("causes", std::move(causes));
        m.set("effects", std::move(effects));
        return m;
    };
    JValue m1 = makeCro(sym("causal_relation_object:m1"), A, B);
    JValue m2 = makeCro(sym("causal_relation_object:m2"), B, C);
    JValue m3 = makeCro(sym("causal_relation_object:m3"), D, C);
    JValue P = JValue::makeObject();
    JValue pCauses = JValue::makeArray();
    pCauses.array.push_back(JValue::of(A));
    JValue pEffects = JValue::makeArray();
    pEffects.array.push_back(JValue::of(C));
    P.set("causes", std::move(pCauses));
    P.set("effects", std::move(pEffects));
    JValue mech = JValue::makeArray();
    mech.array.push_back(m1.at("id"));
    mech.array.push_back(m2.at("id"));
    P.set("mechanism", std::move(mech));
    std::map<std::string, JValue> members12 = {{m1.getString("id"), m1},
                                               {m2.getString("id"), m2}};
    check(hierarchy_consistent(P, members12) == "consistent", "m1+m2");
    JValue P2 = P;
    JValue mech2 = JValue::makeArray();
    mech2.array.push_back(m1.at("id"));
    mech2.array.push_back(m3.at("id"));
    P2.set("mechanism", std::move(mech2));
    std::map<std::string, JValue> members13 = {{m1.getString("id"), m1},
                                               {m3.getString("id"), m3}};
    check(hierarchy_consistent(P2, members13) == "inconsistent", "m1+m3");
    std::map<std::string, JValue> members1 = {{m1.getString("id"), m1}};
    check(hierarchy_consistent(P, members1) == "indeterminate", "m1 only");
}

void v37() {
    InMemoryStore s;
    std::string occ = s.put(occurrentPressButton());
    JValue entry = JValue::makeObject();
    entry.set("lang", JValue::of("en"));
    entry.set("text", JValue::of("Press the Button"));
    JValue body = JValue::makeObject();
    body.set("about", JValue::of(occ));
    body.set("field", JValue::of("aliases"));
    body.set("entry", std::move(entry));
    s.put_record(makeSigned("enrichment", body, "alice", 1));
    std::vector<std::string> aliasHit = s.resolve("Press  The   Button", "en");
    check(aliasHit.size() == 1 && aliasHit[0] == occ, "alias match");
    std::vector<std::string> labelHit = s.resolve("press_button", "en");
    check(!labelHit.empty() && labelHit[0] == occ, "label match, first");
}

void v38() {
    InMemoryStore s;
    JValue claim = JValue::makeObject();
    claim.set("type", JValue::of("causal_relation_object"));
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occurrent:A")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occurrent:B")));
    claim.set("causes", causes);
    claim.set("effects", effects);
    std::string P = s.put(claim);
    auto missingFieldIds = [&s]() {
        std::vector<std::string> ids;
        for (const JValue& g : s.gaps("missing_field"))
            ids.push_back(g.getString("id"));
        return ids;
    };
    std::vector<std::string> before = missingFieldIds();
    check(std::find(before.begin(), before.end(), P) != before.end(),
          "P must be a missing_field gap");
    JValue refinement = JValue::makeObject();
    refinement.set("type", JValue::of("causal_relation_object"));
    refinement.set("causes", causes);
    refinement.set("effects", effects);
    JValue temporal = JValue::makeObject();
    temporal.set("minimum_delay", JValue::of(0));
    temporal.set("maximum_delay", JValue::of(1));
    temporal.set("unit", JValue::of("seconds"));
    refinement.set("temporal", std::move(temporal));
    refinement.set("modality", JValue::of("sufficient"));
    refinement.set("refines", JValue::of(P));
    std::string R = s.put(refinement);
    std::vector<std::string> after = missingFieldIds();
    check(std::find(after.begin(), after.end(), P) == after.end(),
          "the gap did not close");
    check(std::find(after.begin(), after.end(), R) == after.end(),
          "the refinement itself must be complete");
}

// ------------------------------------------------ V39-V107: 2.0.0 additions

// Build an id-keyed map from a list of content objects.
std::map<std::string, JValue> mapOf(const std::vector<JValue>& objs) {
    std::map<std::string, JValue> m;
    for (const JValue& o : objs) m[o.getString("id")] = o;
    return m;
}

void schemaOk(const JValue& obj, const std::string& kind = "") {
    auto [ok, why] = validate_schema(obj, kind);
    check(ok, join(why));
}

void v39() {
    JValue st = buildStratum("cellular", "neuroendocrine", 6, "cell",
                             {"cell_biology"});
    schemaOk(st);
}

void v40() {
    JValue bad = JValue::makeObject();
    bad.set("type", JValue::of("stratum"));
    bad.set("label", JValue::of("cellular"));
    bad.set("ordinal", JValue::of(6));
    bad = mk(std::move(bad));
    auto [ok, why] = validate_schema(bad, "stratum");
    check(!ok && contains(why, "scheme"), "expected scheme error: " + join(why));
}

void v41() {
    JValue a = buildStratum("cellular", "neuroendocrine", 6);
    JValue b = buildStratum("neuronal", "neuroendocrine", 6);
    schemaOk(a);
    schemaOk(b);
    check(a.getString("id") != b.getString("id"), "ids must differ");
}

void v42() {
    auto s = neuro();
    JValue s4p = buildStratum("molecular", "physics", 4);
    JValue c = buildOcc("chronic_social_subordination", s[14].getString("id"));
    JValue e = buildOcc("gene_expression", s4p.getString("id"));
    auto smap = mapOf({s[14], s4p});
    auto omap = mapOf({c, e});
    JValue P = buildCro({c.getString("id")}, {e.getString("id")});
    check(classify_cro(P, omap, smap) == "scheme_mismatch", "scheme_mismatch");
}

void v43() {
    schemaOk(buildStratum("macromolecular", "neuroendocrine", 4));
    schemaOk(buildStratum("region", "neuroendocrine", 9));
}

void v44() {
    JValue st = buildStratum("cellular", "neuroendocrine", 6);
    JValue o = buildOcc("neuron_fires", st.getString("id"));
    schemaOk(o);
    check(validate_semantics(o).first, "semantics");
}

void v45() {
    JValue o = buildOcc("press_button");
    schemaOk(o);
    JValue e = buildOcc("light_on");
    JValue P = buildCro({o.getString("id")}, {e.getString("id")});
    check(classify_cro(P, mapOf({o, e}), {}) == "unclassifiable",
          "unclassifiable");
}

void v46() {
    auto s = neuro();
    JValue a = buildOcc("depolarization", s[5].getString("id"));
    JValue b = buildOcc("depolarization", s[6].getString("id"));
    check(a.getString("id") != b.getString("id"), "ids must differ");
}

struct BridgeFixture {
    JValue bridge;
    std::map<std::string, JValue> omap;
    std::map<std::string, JValue> smap;
};

BridgeFixture bridgeFixture(const std::string& relation) {
    auto s = neuro();
    JValue coarse = buildOcc("action_potential_fires", s[6].getString("id"));
    JValue f1 = buildOcc("sodium_channels_open", s[4].getString("id"));
    JValue f2 = buildOcc("sodium_influx", s[4].getString("id"));
    JValue b = buildBridge(coarse.getString("id"),
                           {f1.getString("id"), f2.getString("id")}, relation);
    return {b, mapOf({coarse, f1, f2}), mapOf({s[4], s[6]})};
}

void validBridge(const std::string& relation) {
    BridgeFixture f = bridgeFixture(relation);
    schemaOk(f.bridge);
    auto [ok, why] = bridge_wellformed(f.bridge, f.omap, f.smap);
    check(ok, why);
}

void v47() { validBridge("constitutes"); }
void v48() { validBridge("aggregates"); }
void v49() { validBridge("realizes"); }
void v50() { validBridge("supervenes_on"); }

void v51() {
    auto s = neuro();
    JValue coarse = buildOcc("x_coarse", s[4].getString("id"));
    JValue fine = buildOcc("x_fine", s[6].getString("id"));
    JValue b = buildBridge(coarse.getString("id"), {fine.getString("id")},
                           "constitutes");
    check(!bridge_wellformed(b, mapOf({coarse, fine}), mapOf({s[4], s[6]})).first,
          "must be malformed");
}

void v52() {
    auto s = neuro();
    JValue coarse = buildOcc("c", s[6].getString("id"));
    JValue f1 = buildOcc("f1", s[4].getString("id"));
    JValue f2 = buildOcc("f2", s[5].getString("id"));
    JValue b = buildBridge(coarse.getString("id"),
                           {f1.getString("id"), f2.getString("id")},
                           "constitutes");
    check(!bridge_wellformed(b, mapOf({coarse, f1, f2}),
                             mapOf({s[4], s[5], s[6]})).first,
          "must be malformed");
}

void v53() {
    std::string x = sym("occurrent:x"), y = sym("occurrent:y");
    JValue b1 = buildBridge(x, {y}, "constitutes");
    JValue b2 = buildBridge(y, {x}, "constitutes");
    std::map<std::string, std::vector<std::string>> edges;
    for (const JValue* b : {&b1, &b2})
        for (const JValue& f : b->at("fine").array)
            edges[f.str].push_back(b->getString("coarse"));
    check(has_cycle(edges), "must have a cycle");
}

void v54() {
    JValue a = buildStratum("cellular", "neuroendocrine", 6);
    JValue b = buildStratum("molecular", "physics", 4);
    JValue coarse = buildOcc("c", a.getString("id"));
    JValue fine = buildOcc("f", b.getString("id"));
    JValue br = buildBridge(coarse.getString("id"), {fine.getString("id")},
                            "constitutes");
    check(!bridge_wellformed(br, mapOf({coarse, fine}), mapOf({a, b})).first,
          "must be malformed");
}

void v55() {
    auto s = neuro();
    JValue coarse = buildOcc("decision_made", s[6].getString("id"));
    JValue f1 = buildOcc("cascade_a", s[4].getString("id"));
    JValue f2 = buildOcc("cascade_b", s[4].getString("id"));
    JValue b1 = buildBridge(coarse.getString("id"), {f1.getString("id")},
                            "realizes");
    JValue b2 = buildBridge(coarse.getString("id"), {f2.getString("id")},
                            "realizes");
    check(b1.getString("id") != b2.getString("id"), "ids must differ");
    schemaOk(b1);
    schemaOk(b2);
}

struct ReachFixture {
    JValue parent;
    std::map<std::string, JValue> members;
    std::vector<JValue> bridges;
};

ReachFixture reachFixture() {
    auto s = neuro();
    JValue ap = buildOcc("action_potential_fires", s[6].getString("id"));
    JValue nt = buildOcc("neurotransmitter_released", s[6].getString("id"));
    JValue fa = buildOcc("calcium_enters", s[4].getString("id"));
    JValue fb = buildOcc("vesicle_fuses", s[4].getString("id"));
    JValue m1 = buildCro({fa.getString("id")}, {fb.getString("id")});
    JValue P = buildCro({ap.getString("id")}, {nt.getString("id")},
                        [&](JValue& o) {
                            o.set("mechanism", strv({m1.getString("id")}));
                        });
    std::vector<JValue> bridges = {
        buildBridge(ap.getString("id"), {fa.getString("id")}, "constitutes"),
        buildBridge(nt.getString("id"), {fb.getString("id")}, "constitutes")};
    return {P, mapOf({m1}), bridges};
}

void v56() {
    ReachFixture f = reachFixture();
    check(hierarchy_consistent(f.parent, f.members, f.bridges) == "consistent",
          "must be consistent");
}

void v57() {
    ReachFixture f = reachFixture();
    check(hierarchy_consistent(f.parent, f.members, {}) == "inconsistent",
          "must be inconsistent without bridges");
}

void v58() {
    ReachFixture f = reachFixture();
    std::string literal = hierarchy_consistent(f.parent, f.members, {});
    std::string bridged = hierarchy_consistent(f.parent, f.members, f.bridges);
    check(literal != "consistent" && bridged == "consistent",
          "literal must fail where bridged succeeds");
}

std::string classifyOrds(int causeOrd, int effectOrd) {
    auto s = neuro();
    JValue c = buildOcc("c", s[causeOrd].getString("id"));
    JValue e = buildOcc("e", s[effectOrd].getString("id"));
    auto smap = mapOf({s[causeOrd], s[effectOrd]});
    auto omap = mapOf({c, e});
    return classify_cro(buildCro({c.getString("id")}, {e.getString("id")}),
                        omap, smap);
}

void v59() { check(classifyOrds(6, 6) == "intra_stratal", "intra_stratal"); }
void v60() { check(classifyOrds(6, 5) == "adjacent_stratal", "adjacent"); }
void v61() { check(classifyOrds(14, 4) == "skipping", "skipping"); }

struct SkipFixture {
    JValue parent;
    std::string classification;
};

SkipFixture skipFixture(int causeOrd, int effectOrd,
                        const std::function<void(JValue&)>& patch = nullptr) {
    auto s = neuro();
    JValue c = buildOcc("c", s[causeOrd].getString("id"));
    JValue e = buildOcc("e", s[effectOrd].getString("id"));
    auto smap = mapOf({s[causeOrd], s[effectOrd]});
    auto omap = mapOf({c, e});
    JValue P = buildCro({c.getString("id")}, {e.getString("id")}, patch);
    return {P, classify_cro(P, omap, smap)};
}

bool eqList(const std::vector<std::string>& a,
            const std::vector<std::string>& b) {
    return a == b;
}

void v62() {
    SkipFixture f = skipFixture(14, 4);
    check(eqList(skip_gaps(f.parent, f.classification),
                 {"incomplete_mechanism"}),
          "expected [incomplete_mechanism]");
}

void v63() {
    SkipFixture f = skipFixture(14, 4,
                               [](JValue& o) { o.set("skips", JValue::of(true)); });
    check(skip_gaps(f.parent, f.classification).empty(), "expected []");
}

void v64() {
    SkipFixture f = skipFixture(14, 4, [](JValue& o) {
        o.set("skips", JValue::of(true));
        o.set("mechanism", strv({sym("causal_relation_object:m")}));
    });
    check(eqList(skip_gaps(f.parent, f.classification), {"contradictory_skip"}),
          "expected [contradictory_skip]");
    auto [ok, why] = validate_semantics(f.parent);
    check(!ok && contains(why, "contradictory_skip"),
          "semantics must reject: " + join(why));
}

void v65() {
    SkipFixture f = skipFixture(6, 6,
                               [](JValue& o) { o.set("skips", JValue::of(true)); });
    check(eqList(skip_gaps(f.parent, f.classification), {"vacuous_skip"}),
          "expected [vacuous_skip]");
}

void v66() {
    auto s = neuro();
    JValue c = buildOcc("c", s[14].getString("id"));
    JValue e = buildOcc("e", s[4].getString("id"));
    JValue absent = buildCro({c.getString("id")}, {e.getString("id")});
    JValue falseSkip = buildCro({c.getString("id")}, {e.getString("id")},
                                [](JValue& o) { o.set("skips", JValue::of(false)); });
    check(absent.getString("id") != falseSkip.getString("id"),
          "skips:false must be distinct from skips absent");
}

void v67() {
    auto s = neuro();
    JValue c1 = buildOcc("c1", s[4].getString("id"));
    JValue c2 = buildOcc("c2", s[6].getString("id"));
    JValue e = buildOcc("e", s[6].getString("id"));
    JValue P = buildCro({c1.getString("id"), c2.getString("id")},
                        {e.getString("id")});
    check(endpoints_mixed(P, mapOf({c1, c2, e})), "must be mixed");
}

void v68() {
    JValue P = buildCro({sym("occurrent:a")}, {sym("occurrent:b")},
                        [](JValue& o) { o.set("modality", JValue::of("enabling")); });
    schemaOk(P);
}

JValue modalityPair(const std::string& modality) {
    JValue o = JValue::makeObject();
    o.set("causes", strv({sym("occurrent:a")}));
    o.set("effects", strv({sym("occurrent:b")}));
    o.set("modality", JValue::of(modality));
    return o;
}

void v69() {
    check(conflicts(modalityPair("enabling"), modalityPair("sufficient")) == false,
          "enabling must be compatible with sufficient");
}

void v70() {
    check(conflicts(modalityPair("enabling"), modalityPair("preventive")) == true,
          "enabling must be opposed by preventive");
}

void v71() {
    JValue b = buildCnt("hippocampus");
    JValue p = buildPort(b.getString("id"), "perforant_path", "in",
                         {sym("occurrent:signal")});
    schemaOk(p);
}

void v72() {
    std::string b = buildCnt("hippocampus").getString("id");
    std::string x = sym("occurrent:signal");
    check(buildPort(b, "perforant_path", "in", {x}).getString("id") !=
              buildPort(b, "fornix", "in", {x}).getString("id"),
          "distinct labels must yield distinct ids");
}

struct ConduitFixture {
    JValue conduit;
    std::map<std::string, JValue> pmap;
    std::map<std::string, JValue> cro_map;
};

ConduitFixture conduitFixture(bool transform = false, bool bad_carry = false,
                              bool in_from = false) {
    std::string x = sym("occurrent:motor_command");
    std::string y = sym("occurrent:error_signal");
    std::string z = sym("occurrent:unrelated");
    std::string m1 = buildCnt("motor_cortex").getString("id");
    std::string m2 = buildCnt("spinal_neuron").getString("id");
    JValue frm = buildPort(m1, "out_port", in_from ? "in" : "out", {x});
    JValue to = buildPort(m2, "in_port", "in", transform ? std::vector<std::string>{y}
                                                         : std::vector<std::string>{x});
    std::vector<std::string> carries = bad_carry ? std::vector<std::string>{z}
                                                 : std::vector<std::string>{x};
    std::string xform;
    std::map<std::string, JValue> croMap;
    if (transform) {
        JValue law = buildCro({x}, {y});
        croMap[law.getString("id")] = law;
        xform = law.getString("id");
    }
    JValue c = buildConduit(frm.getString("id"), to.getString("id"), carries,
                            "conn", xform);
    return {c, mapOf({frm, to}), croMap};
}

void v73() {
    ConduitFixture f = conduitFixture();
    schemaOk(f.conduit);
    auto [ok, why] = conduit_wellformed(f.conduit, f.pmap);
    check(ok, why);
}

void v74() {
    ConduitFixture f = conduitFixture(true);
    schemaOk(f.conduit);
    auto [ok, why] = conduit_wellformed(f.conduit, f.pmap, &f.cro_map);
    check(ok, why);
}

void v75() {
    ConduitFixture f = conduitFixture(false, true);
    check(!conduit_wellformed(f.conduit, f.pmap).first, "must be malformed");
}

void v76() {
    ConduitFixture f = conduitFixture(false, false, true);
    check(!conduit_wellformed(f.conduit, f.pmap).first, "must be malformed");
}

void v77() {
    ConduitFixture f = conduitFixture(true);
    auto [ok, why] = conduit_wellformed(f.conduit, f.pmap, &f.cro_map);
    check(ok, why);
    const JValue& law = f.cro_map.begin()->second;
    std::string effect0 = law.at("effects").array[0].str;
    bool inCarries = false;
    for (const JValue& c : f.conduit.at("carries").array)
        if (c.str == effect0) inCarries = true;
    check(!inCarries, "the emitted effect must not be among carries");
}

void v78() {
    std::string b = buildCnt("hippocampus").getString("id");
    check(buildRlz(b, "disposition", "long_term_potentiation").getString("id") !=
              buildRlz(b, "disposition", "pattern_separation").getString("id"),
          "distinct labels must yield distinct ids");
}

void v79() {
    std::string b = buildCnt("hippocampus").getString("id");
    JValue u1 = buildRlz(b, "disposition");
    JValue u2 = buildRlz(b, "disposition");
    schemaOk(u1);
    check(u1.getString("id") == u2.getString("id"), "unlabelled must be equal");
    check(buildRlz(b, "disposition", "some_function").getString("id") !=
              u1.getString("id"),
          "a label must change identity");
}

JValue occEnrichment(const std::string& about, const std::string& field,
                     const std::string& entry) {
    JValue e = JValue::makeObject();
    e.set("type", JValue::of("enrichment"));
    e.set("about", JValue::of(about));
    e.set("field", JValue::of(field));
    e.set("entry", JValue::of(entry));
    return e;
}

void v80() {
    JValue parent = buildOcc("fires");
    JValue child = buildOcc("fires_action_potential");
    JValue e = occEnrichment(child.getString("id"), "occurrent_subsumes",
                             parent.getString("id"));
    auto [ok, why] = validate_semantics(e);
    check(ok, join(why));
}

void v81() {
    std::string a = sym("occurrent:a"), b = sym("occurrent:b");
    std::map<std::string, std::vector<std::string>> edges = {{a, {b}}, {b, {a}}};
    check(has_cycle(edges), "must have a cycle");
}

void v82() {
    JValue whole = buildOcc("eat");
    JValue part = buildOcc("chew");
    JValue e = occEnrichment(part.getString("id"), "occurrent_part_of",
                             whole.getString("id"));
    auto [ok, why] = validate_semantics(e);
    check(ok, join(why));
}

void v83() {
    // occurrent_part_of is legal only for occurrents: an enrichment about a
    // continuant must be rejected (proves the field-to-kind constraint).
    JValue illegal = occEnrichment(sym("continuant:body"), "occurrent_part_of",
                                   sym("occurrent:mouth"));
    check(!validate_semantics(illegal).first,
          "occurrent_part_of about a continuant must be illegal");
    InMemoryStore s;
    std::string whole = s.put(buildOcc("eat"));
    std::string part = s.put(buildOcc("chew"));
    check(s.object_count() == 2, "two occurrents expected");
    check(s.get(whole)->at("object").getString("type") == "occurrent" &&
              s.get(part)->at("object").getString("type") == "occurrent",
          "no causal relation object should have been created");
}

void v84() {
    auto s = neuro();
    JValue a = buildOcc("run", s[9].getString("id"));
    JValue b = buildOcc("sprint", s[6].getString("id"));
    check(a.getString("stratum") != b.getString("stratum"),
          "strata must differ");
}

void v85() {
    JValue c = buildCnt("human_patient");
    JValue ti = buildIndividual(c.getString("id"), "salted_hash_abc123");
    schemaOk(ti);
}

void v86() {
    JValue bad = JValue::makeObject();
    bad.set("type", JValue::of("token_individual"));
    bad.set("designator", JValue::of("x"));
    bad = mk(std::move(bad));
    auto [ok, why] = validate_schema(bad, "token_individual");
    check(!ok && contains(why, "instantiates"),
          "expected instantiates error: " + join(why));
}

void v87() {
    std::string c = buildCnt("human_patient").getString("id");
    check(buildIndividual(c, "hash_a").getString("id") !=
              buildIndividual(c, "hash_b").getString("id"),
          "distinct designators must yield distinct ids");
}

void v88() {
    JValue o = buildOcc("bilateral_hippocampal_resection");
    JValue t = buildToken(o.getString("id"),
                          interval("1953-08-25T00:00:00Z", "1953-08-25T00:00:00Z"));
    schemaOk(t);
}

void v89() {
    std::string o = buildOcc("amnesia_onset").getString("id");
    JValue bounded = buildToken(o, interval("1953-08-25T00:00:00Z",
                                            "1953-08-26T00:00:00Z"));
    JValue instantaneous = buildToken(o, interval("1953-08-25T00:00:00Z"));
    JValue ongoing = buildToken(o, interval("1953-08-25T00:00:00Z", "", 1));
    std::set<std::string> ids = {bounded.getString("id"),
                                 instantaneous.getString("id"),
                                 ongoing.getString("id")};
    check(ids.size() == 3, "three distinct interval shapes expected");
}

void v90() {
    std::string o = buildOcc("resection").getString("id");
    std::string c = buildCnt("human_patient").getString("id");
    std::string patient = buildIndividual(c, "p").getString("id");
    std::string surgeon = buildIndividual(c, "s").getString("id");
    JValue participants = JValue::makeArray();
    JValue r1 = JValue::makeObject();
    r1.set("role", JValue::of("patient"));
    r1.set("filler", JValue::of(patient));
    JValue r2 = JValue::makeObject();
    r2.set("role", JValue::of("agent"));
    r2.set("filler", JValue::of(surgeon));
    participants.array.push_back(std::move(r1));
    participants.array.push_back(std::move(r2));
    JValue t = buildToken(o, interval("1953-08-25T00:00:00Z"),
                          std::move(participants));
    schemaOk(t);
}

void v91() {
    JValue q = buildQuality("cortisol_concentration", "quantity", "ug/dL");
    schemaOk(q);
}

struct StateFixture {
    JValue state;
    JValue quality;
};

StateFixture stateFixture(const std::string& datatype, JValue value,
                          const std::string& unit = "") {
    JValue q = buildQuality("cortisol_concentration", datatype, unit);
    std::string c = buildCnt("human_patient").getString("id");
    std::string subj = buildIndividual(c, "p").getString("id");
    JValue st = buildState(subj, q.getString("id"), std::move(value),
                           interval("2026-01-01T00:00:00Z",
                                    "2026-01-01T01:00:00Z"));
    return {st, q};
}

JValue quantityValue(double q, const std::string& unit) {
    JValue v = JValue::makeObject();
    v.set("quantity", JValue::of(q));
    v.set("unit", JValue::of(unit));
    return v;
}

void v92() {
    StateFixture f = stateFixture("quantity", quantityValue(15.0, "ug/dL"),
                                  "ug/dL");
    schemaOk(f.state);
    check(state_gaps(f.state, f.quality).empty(), "no gaps expected");
}

void v93() {
    JValue v = JValue::makeObject();
    v.set("categorical", JValue::of("elevated"));
    StateFixture f = stateFixture("categorical", std::move(v));
    schemaOk(f.state);
    check(state_gaps(f.state, f.quality).empty(), "no gaps expected");
}

void v94() {
    JValue v = JValue::makeObject();
    v.set("boolean", JValue::of(true));
    StateFixture f = stateFixture("boolean", std::move(v));
    schemaOk(f.state);
    check(state_gaps(f.state, f.quality).empty(), "no gaps expected");
}

void v95() {
    JValue v = JValue::makeObject();
    v.set("categorical", JValue::of("elevated"));
    StateFixture f = stateFixture("quantity", std::move(v), "ug/dL");
    check(eqList(state_gaps(f.state, f.quality), {"value_type_mismatch"}),
          "expected [value_type_mismatch]");
}

void v96() {
    StateFixture f = stateFixture("quantity", quantityValue(15.0, "mg/dL"),
                                  "ug/dL");
    check(eqList(state_gaps(f.state, f.quality), {"unit_mismatch"}),
          "expected [unit_mismatch]");
}

struct LawTokens {
    JValue law, tCause, tEffect;
};

LawTokens lawAndTokens() {
    JValue oCause = buildOcc("resection");
    JValue oEffect = buildOcc("amnesia_onset");
    JValue law = buildCro({oCause.getString("id")}, {oEffect.getString("id")},
                          [](JValue& o) {
                              o.set("temporal", temporalObj(0, 1, "days"));
                              o.set("modality", JValue::of("sufficient"));
                          });
    JValue tCause = buildToken(oCause.getString("id"),
                               interval("1953-08-25T00:00:00Z"));
    JValue tEffect = buildToken(oEffect.getString("id"),
                                interval("1953-08-25T00:00:00Z", "", 1));
    return {law, tCause, tEffect};
}

void v97() {
    LawTokens lt = lawAndTokens();
    JValue claim = buildTcc({lt.tCause.getString("id")},
                            {lt.tEffect.getString("id")},
                            lt.law.getString("id"), delayObj(0, "instant"), 1);
    schemaOk(claim);
}

void v98() {
    LawTokens lt = lawAndTokens();
    JValue claim = buildTcc({lt.tCause.getString("id")},
                            {lt.tEffect.getString("id")});
    schemaOk(claim);
    check(!claim.has("covering_law"), "covering_law must be absent");
}

void v99() {
    LawTokens lt = lawAndTokens();
    check(delay_within_window(delayObj(0, "instant"), lt.law.at("temporal")),
          "must be within the window");
}

void v100() {
    JValue temporal = temporalObj(0, 1, "hours");
    check(delay_within_window(delayObj(5, "days"), temporal) == false,
          "must be outside the window");
}

void v101() {
    std::string o = buildOcc("x").getString("id");
    JValue cause = buildToken(o, interval("2026-01-02T00:00:00Z"));
    JValue effect = buildToken(o, interval("2026-01-01T00:00:00Z"));
    JValue claim = buildTcc({cause.getString("id")}, {effect.getString("id")});
    check(retrocausal(claim, mapOf({cause, effect})), "must be retrocausal");
}

void v102() {
    JValue other = buildCro({sym("occurrent:foo")}, {sym("occurrent:bar")});
    LawTokens lt = lawAndTokens();
    JValue claim = buildTcc({lt.tCause.getString("id")},
                            {lt.tEffect.getString("id")}, other.getString("id"));
    check(covering_law_mismatch(claim, mapOf({lt.tCause, lt.tEffect}), other),
          "must surface a covering-law mismatch");
}

void v103() {
    JValue body = JValue::makeObject();
    body.set("about", JValue::of(sym("token_occurrence:t")));
    body.set("evidence_type", JValue::of("observation"));
    body.set("confidence", JValue::of(0.9));
    JValue a = makeSigned("assertion", body, "signer");
    schemaOk(a);
}

void v104() {
    JValue base = JValue::makeObject();
    base.set("type", JValue::of("assertion"));
    base.set("about", JValue::of(sym("causal_relation_object:law")));
    base.set("source", JValue::of(key("signer").second));
    base.set("evidence_type", JValue::of("intervention"));
    base.set("strength", JValue::of(0.95));
    base.set("confidence", JValue::of(0.99));
    base.set("timestamp", JValue::of("2026-07-14T00:00:00Z"));
    JValue a = base;
    a.set("evidenced_by", strv({sym("token_occurrence:t1"),
                                sym("token_causal_claim:c1")}));
    JValue withId = a;
    withId.set("id", JValue::of(identify(a)));
    schemaOk(withId);
    check(identify(a) != identify(base), "evidenced_by must be identity-bearing");
}

void v105() {
    JValue body = JValue::makeObject();
    body.set("about", JValue::of(sym("causal_relation_object:law")));
    body.set("evidence_type", JValue::of("simulation"));
    body.set("confidence", JValue::of(0.5));
    JValue a = makeSigned("assertion", body, "signer");
    schemaOk(a);
}

void v106() {
    static const std::set<std::string> wholeWord = {
        "occurrent", "causal_relation_object", "continuant", "realizable",
        "assertion", "enrichment", "retraction", "succession", "stratum",
        "bridge", "port", "conduit", "quality", "token_individual",
        "token_occurrence", "state_assertion", "token_causal_claim", "ed25519"};
    std::regex idPattern("^([a-z0-9_]+):[0-9a-f]{64}$");
    std::function<void(const JValue&, std::vector<std::string>&)> scan =
        [&](const JValue& node, std::vector<std::string>& ids) {
            if (node.isString()) {
                std::smatch m;
                if (std::regex_match(node.str, m, idPattern))
                    ids.push_back(m[1].str());
            } else if (node.isArray()) {
                for (const JValue& x : node.array) scan(x, ids);
            } else if (node.isObject()) {
                for (const auto& kv : node.object) scan(kv.second, ids);
            }
        };
    for (int n = 1; n <= 38; ++n) {
        std::vector<std::string> ids;
        scan(vec(n), ids);
        for (const std::string& scheme : ids)
            check(wholeWord.count(scheme) > 0,
                  "V106: abbreviated scheme '" + scheme + "' in vector " +
                      std::to_string(n));
    }
    JValue rec = occurrentPressButton();
    check(identify(rec) == identify(rec), "identity must be deterministic");
    check(identify(rec).substr(0, identify(rec).find(':')) == "occurrent",
          "prefix must be the whole word 'occurrent'");
}

void v107() {
    std::string hexid(64, '0');
    // The abbreviated prefix here is the deliberate negative test; assemble it
    // so it survives any whole-word re-mint pass.
    std::string croAbbr = std::string("c") + "r" + "o";
    JValue abbreviated = JValue::makeObject();
    abbreviated.set("type", JValue::of("causal_relation_object"));
    abbreviated.set("id", JValue::of(croAbbr + ":" + hexid));
    abbreviated.set("causes", strv({"occurrent:" + hexid}));
    abbreviated.set("effects", strv({"occurrent:" + hexid}));
    check(!validate_schema(abbreviated, "causal_relation_object").first,
          "abbreviated scheme must be rejected");
    JValue abbrStr = JValue::makeObject();
    abbrStr.set("type", JValue::of("stratum"));
    abbrStr.set("id", JValue::of(std::string("str:") + hexid));
    abbrStr.set("label", JValue::of("cellular"));
    abbrStr.set("scheme", JValue::of("neuroendocrine"));
    abbrStr.set("ordinal", JValue::of(6));
    check(!validate_schema(abbrStr, "stratum").first,
          "abbreviated stratum scheme must be rejected");
    JValue whole = JValue::makeObject();
    whole.set("type", JValue::of("causal_relation_object"));
    whole.set("id", JValue::of("causal_relation_object:" + hexid));
    whole.set("causes", strv({"occurrent:" + hexid}));
    whole.set("effects", strv({"occurrent:" + hexid}));
    auto [ok, why] = validate_schema(whole, "causal_relation_object");
    check(ok, join(why));
}

}  // namespace

int main() {
    std::printf("causalontology-cpp conformance run\n");
    std::string root, vecdir;
    try {
        root = findRoot();
        vecdir = (fs::path(root) / "conformance" / "vectors").string();
        g_vecdir = vecdir;
        schema_set_spec_dir((fs::path(root) / "spec" / "schema").string());
        std::printf(
            "internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ");
        std::fflush(stdout);
        internalChecks();
        std::printf("ok\n");
    } catch (const std::exception& e) {
        std::printf("FATAL: %s\n", e.what());
        return 1;
    }
    int failures = 0;
    const std::vector<std::function<void()>> tests = {
        v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13,
        v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26,
        v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39,
        v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52,
        v53, v54, v55, v56, v57, v58, v59, v60, v61, v62, v63, v64, v65,
        v66, v67, v68, v69, v70, v71, v72, v73, v74, v75, v76, v77, v78,
        v79, v80, v81, v82, v83, v84, v85, v86, v87, v88, v89, v90, v91,
        v92, v93, v94, v95, v96, v97, v98, v99, v100, v101, v102, v103,
        v104, v105, v106, v107};
    const int total = static_cast<int>(tests.size());
    for (int n = 1; n <= total; ++n) {
        std::string stem = vectorFile(n).second;
        try {
            tests[static_cast<size_t>(n - 1)]();
            std::printf("PASS  %s\n", stem.c_str());
        } catch (const std::exception& e) {
            ++failures;
            std::printf("FAIL  %s :: %s\n", stem.c_str(), e.what());
        }
    }
    for (int i = 0; i < 60; ++i) std::printf("-");
    std::printf("\n%d/%d vectors passed\n", total - failures, total);
    if (failures) return 1;
    std::printf(
        "causalontology-cpp is CONFORMANT to the suite "
        "(vectors frozen at specification 2.0.0).\n");
    return 0;
}

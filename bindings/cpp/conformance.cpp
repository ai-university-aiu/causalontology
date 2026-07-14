// conformance.cpp - the Causalontology conformance runner for
// causalontology-cpp.
//
// Runs every vector in conformance/vectors/ against the C++ binding. An
// implementation is conformant if and only if it passes every vector; this
// runner exits nonzero on any failure. It mirrors
// bindings/python/tests/run_conformance.py exactly.
//
// The vectors are frozen at specification 1.0.0: they carry concrete
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
        "occ", "cro", "cnt", "rlz", "ast", "enr", "ret", "suc", "ed25519"};
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
    semanticsFails(14, "dmin");
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
    std::string dog = sym("cnt:dog"), mam = sym("cnt:mammal"),
                ani = sym("cnt:animal");
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
    causes.array.push_back(JValue::of(sym("occ:c")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occ:e")));
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
    claim.set("type", JValue::of("cro"));
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occ:A")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occ:B")));
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
    body.set("about", JValue::of(sym("cro:demo")));
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
    claim.set("type", JValue::of("cro"));
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occ:A")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occ:B")));
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
    aBody.set("about", JValue::of(sym("cro:claim")));
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
    check(s.assertions_about(sym("cro:claim")).empty(),
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
    std::string A = sym("occ:A"), B = sym("occ:B"), C = sym("occ:C"),
                D = sym("occ:D");
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
    JValue m1 = makeCro(sym("cro:m1"), A, B);
    JValue m2 = makeCro(sym("cro:m2"), B, C);
    JValue m3 = makeCro(sym("cro:m3"), D, C);
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
    claim.set("type", JValue::of("cro"));
    JValue causes = JValue::makeArray();
    causes.array.push_back(JValue::of(sym("occ:A")));
    JValue effects = JValue::makeArray();
    effects.array.push_back(JValue::of(sym("occ:B")));
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
    refinement.set("type", JValue::of("cro"));
    refinement.set("causes", causes);
    refinement.set("effects", effects);
    JValue temporal = JValue::makeObject();
    temporal.set("dmin", JValue::of(0));
    temporal.set("dmax", JValue::of(1));
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
        v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38};
    for (int n = 1; n <= 38; ++n) {
        std::string stem = vectorFile(n).second;
        try {
            tests[static_cast<size_t>(n - 1)]();
            std::printf("PASS  %s\n", stem.c_str());
        } catch (const std::exception& e) {
            ++failures;
            std::printf("FAIL  %s :: %s\n", stem.c_str(), e.what());
        }
    }
    const int total = 38;
    for (int i = 0; i < 60; ++i) std::printf("-");
    std::printf("\n%d/%d vectors passed\n", total - failures, total);
    if (failures) return 1;
    std::printf(
        "causalontology-cpp is CONFORMANT to the suite "
        "(vectors frozen at specification 1.0.0).\n");
    return 0;
}

// semantics.hpp - the semantic rules beyond the schemas (spec/semantics.md).
//
// Local rules are checked here; store-context rules (materialized
// acyclicity, retraction lineage) live in store.cpp where the context is.

#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "json.hpp"

namespace co {

// Rule 4: the fixed unit-conversion constants (average Gregorian values).
// months = 2629746 s, years = 31556952 s.
int64_t unit_seconds(const std::string& unit);

// The optional CRO fields, in spec order.
extern const std::vector<std::string> CRO_OPTIONAL_FIELDS;

// (ok, reasons) - the locally checkable semantic rules.
std::pair<bool, std::vector<std::string>> validate_semantics(
    const JValue& obj, const std::string& kind = "");

// (partial, missing) - which optional CRO fields are unspecified.
std::pair<bool, std::vector<std::string>> is_partial(const JValue& cro);

// Rule 4: temporal admissibility. For a wall-clock window elapsed is in
// seconds; for an ordinal ('ticks') window elapsed is a tick count (3.0.0).
bool admissible(const JValue& cro, double elapsed);

// Rule 6: the formal conflict test.
bool conflicts(const JValue& a, const JValue& b);

// Rule 3: (ok, reason) - is child a valid refinement of parent?
std::pair<bool, std::string> refinement_valid(const JValue& child,
                                              const JValue& parent);

// ALGORITHM A: every finer occurrent an occurrent resolves to via bridges.
std::set<std::string> bridge_closure(const std::string& occurrent_id,
                                     const std::vector<JValue>& bridges);

// ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
// "indeterminate", across strata via bridged reachability. members maps CRO
// identifier -> CRO object for the parent's mechanism; bridges empty gives the
// 1.0.0 literal-reachability degenerate case.
std::string hierarchy_consistent(const JValue& parent,
                                 const std::map<std::string, JValue>& members,
                                 const std::vector<JValue>& bridges = {});

// ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping" |
// "mixed" | "unclassifiable" | "scheme_mismatch".
std::string classify_cro(const JValue& cro,
                         const std::map<std::string, JValue>& occ_map,
                         const std::map<std::string, JValue>& stratum_map);

// True iff causes or effects span more than one distinct stratum.
bool endpoints_mixed(const JValue& cro,
                     const std::map<std::string, JValue>& occ_map);

// ALGORITHM D (Rule 16): the gaps a CRO surfaces for the skip decision.
std::vector<std::string> skip_gaps(const JValue& cro,
                                   const std::string& classification);

// ALGORITHM E helpers: normalize a delay to seconds; window admissibility.
// 3.0.0: an ordinal ('ticks') unit has no seconds mapping - to_seconds throws
// on one, and a delay and a window in different dimensions never fall within
// one another.
double to_seconds(double duration, const std::string& unit);
bool delay_within_window(const JValue& actual_delay, const JValue& temporal);

// Rule 14 / N3.2.1: bridge well-formedness.
std::pair<bool, std::string> bridge_wellformed(
    const JValue& bridge, const std::map<std::string, JValue>& occ_map,
    const std::map<std::string, JValue>& stratum_map);

// 3.0.0 Rule 22 / Algorithm F: cross-stratal seam well-formedness. A seam is
// a MANAGED jump across NON-adjacent strata; a drawn chain must be an
// adjacent-stratum path spanning the two endpoints' strata.
std::pair<bool, std::string> seam_wellformed(
    const JValue& seam, const std::map<std::string, JValue>& occ_map,
    const std::map<std::string, JValue>& stratum_map);

// THE HOME RULE (3.0.0): the coarsest stratum a seam touches (the endpoint of
// the greater ordinal); "" when an endpoint is unstratified.
std::string seam_home(const JValue& seam,
                      const std::map<std::string, JValue>& occ_map,
                      const std::map<std::string, JValue>& stratum_map);

// Rule 17 / N4.2.1-2: conduit well-formedness. cro_map may be null.
std::pair<bool, std::string> conduit_wellformed(
    const JValue& conduit, const std::map<std::string, JValue>& port_map,
    const std::map<std::string, JValue>* cro_map = nullptr);

// Rule 19: the HARD gaps a state assertion surfaces against its quality.
std::vector<std::string> state_gaps(const JValue& state, const JValue& quality);

// Rule 20: covering-law coherence.
bool covering_law_mismatch(const JValue& tcc,
                           const std::map<std::string, JValue>& token_map,
                           const JValue& law);

// 4.0.0 Rule 24: prediction-to-observation pairing. observed may be an empty
// JValue when no token occurrence answered the prediction.
bool prediction_pairing_mismatch(const JValue& error, const JValue& predicted,
                                 const JValue& observed);

// Rule 21: temporal coherence of token causation.
bool retrocausal(const JValue& tcc,
                 const std::map<std::string, JValue>& token_map);

// Rules 4 / 6.1: generic directed-graph cycle detection.
bool has_cycle(const std::map<std::string, std::vector<std::string>>& edges);

}  // namespace co

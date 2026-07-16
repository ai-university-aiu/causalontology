/// The semantic rules beyond the schemas (spec/semantics.md).
///
/// Local rules are checked here; store-context rules (materialized
/// acyclicity, retraction lineage) live in store.dart where the context
/// exists.
library;

import 'dart:math' as math;

import 'canonical.dart';
import 'schema.dart' show deepEquals;

/// Rule 4: the fixed unit-conversion constants (average Gregorian values).
const Map<String, int> unitSeconds = {
  'instant': 0,
  'seconds': 1,
  'minutes': 60,
  'hours': 3600,
  'days': 86400,
  'weeks': 604800,
  'months': 2629746,
  'years': 31556952,
};

/// Rule 12: enrichment field-to-kind validity and entry shapes. Two occurrent
/// forms added in 2.0.0.
const Map<String, (List<String>, String)> enrichmentFields = {
  'aliases': (['occurrent', 'continuant'], 'alias'),
  'participants': (['occurrent'], 'continuant'),
  'subsumes': (['continuant'], 'continuant'),
  'part_of': (['continuant'], 'continuant'),
  'realized_in': (['realizable'], 'occurrent'),
  'occurrent_subsumes': (['occurrent'], 'occurrent'),
  'occurrent_part_of': (['occurrent'], 'occurrent'),
};

const List<String> croOptionalFields = [
  'mechanism', 'temporal', 'modality', 'context',
];

String? _kindOfId(String identifier) =>
    kindOfPrefix[identifier.split(':').first];

/// (ok, reasons) - the locally checkable semantic rules.
(bool, List<String>) validateSemantics(Map<String, dynamic> obj,
    [String? kind]) {
  final k = kind ?? inferKind(obj);
  final errors = <String>[];

  if (k == 'causal_relation_object') {
    final t = obj['temporal'] as Map?;
    if (t != null &&
        t['minimum_delay'] != null &&
        t['maximum_delay'] != null &&
        (t['minimum_delay'] as num) > (t['maximum_delay'] as num)) {
      errors.add('minimum_delay must be <= maximum_delay');
    }
    final oid = obj['id'];
    if (oid is String &&
        oid.isNotEmpty &&
        ((obj['mechanism'] as List?) ?? const []).contains(oid)) {
      errors.add('mechanism must be acyclic '
          '(a Causal Relation Object may not contain itself)');
    }
    if (oid is String && oid.isNotEmpty && obj['refines'] == oid) {
      errors.add('refines must be acyclic');
    }
    // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
    // contradiction between skips:true and a non-empty mechanism.
    if (obj['skips'] == true &&
        ((obj['mechanism'] as List?)?.isNotEmpty ?? false)) {
      errors.add('contradictory_skip: skips is true but a mechanism '
          'is present');
    }
  }

  if (k == 'enrichment') {
    final field = obj['field'] as String?;
    final about = (obj['about'] as String?) ?? '';
    final entry = obj['entry'];
    final spec = enrichmentFields[field];
    if (spec != null) {
      final (legalKinds, shape) = spec;
      final aboutKind = _kindOfId(about);
      if (aboutKind != null && !legalKinds.contains(aboutKind)) {
        errors.add('$field is not a legal field for a $aboutKind (rule 12)');
      }
      if (shape == 'alias') {
        if (!(entry is Map &&
            entry.containsKey('lang') &&
            entry.containsKey('text'))) {
          errors.add('an aliases entry must be a language-tagged text object');
        }
      } else {
        if (!(entry is String && entry.startsWith('$shape:'))) {
          errors.add('a $field entry must be a $shape: identifier');
        }
      }
    }
  }

  return (errors.isEmpty, errors);
}

/// (partial, missing) - which optional CRO fields are unspecified.
(bool, List<String>) isPartial(Map<String, dynamic> cro) {
  final missing =
      croOptionalFields.where((f) => !cro.containsKey(f)).toList();
  return (missing.isNotEmpty, missing);
}

/// Rule 4: temporal admissibility with the fixed constants.
bool admissible(Map<String, dynamic> cro, num elapsedSeconds) {
  final t = cro['temporal'] as Map?;
  if (t == null) {
    return true; // no window imposes no constraint
  }
  final unit = unitSeconds[t['unit'] as String]!;
  final lo = (t['minimum_delay'] as num) * unit;
  final hi = (t['maximum_delay'] as num) * unit;
  return lo <= elapsedSeconds && elapsedSeconds <= hi;
}

bool _windowOverlap(Map<String, dynamic> a, Map<String, dynamic> b) {
  final ta = a['temporal'] as Map?;
  final tb = b['temporal'] as Map?;
  if (ta == null || tb == null) {
    return true; // either absent counts as overlapping
  }
  final ua = unitSeconds[ta['unit'] as String]!;
  final ub = unitSeconds[tb['unit'] as String]!;
  final loA = (ta['minimum_delay'] as num) * ua, hiA = (ta['maximum_delay'] as num) * ua;
  final loB = (tb['minimum_delay'] as num) * ub, hiB = (tb['maximum_delay'] as num) * ub;
  return loA <= hiB && loB <= hiA;
}

bool _contextsCompatible(Map<String, dynamic> a, Map<String, dynamic> b) {
  final ca = a['context'] as List?;
  final cb = b['context'] as List?;
  if (ca == null || ca.isEmpty || cb == null || cb.isEmpty) {
    return true; // either absent (or empty)
  }
  final sa = ca.cast<String>().toSet();
  final sb = cb.cast<String>().toSet();
  return sa.containsAll(sb) || sb.containsAll(sa);
}

// Rule 6 (amended): necessary, sufficient, contributory, enabling are mutually
// compatible; preventive opposes all four.
const Set<String> _positive = {
  'necessary', 'sufficient', 'contributory', 'enabling',
};

bool _sameSet(List a, List b) {
  final sa = a.cast<String>().toSet();
  final sb = b.cast<String>().toSet();
  return sa.length == sb.length && sa.containsAll(sb);
}

/// Rule 6: the formal conflict test.
bool conflicts(Map<String, dynamic> a, Map<String, dynamic> b) {
  if (!_sameSet(a['causes'] as List, b['causes'] as List)) return false;
  if (!_sameSet(a['effects'] as List, b['effects'] as List)) return false;
  if (!_contextsCompatible(a, b)) return false;
  if (!_windowOverlap(a, b)) return false;
  final ma = a['modality'];
  final mb = b['modality'];
  return (ma == 'preventive' && _positive.contains(mb)) ||
      (mb == 'preventive' && _positive.contains(ma));
}

/// Rule 3: (ok, reason) - is child a valid refinement of parent?
(bool, String) refinementValid(
    Map<String, dynamic> child, Map<String, dynamic> parent) {
  if (child['refines'] != parent['id']) {
    return (false, 'child does not name the parent in refines');
  }
  if (!_sameSet(child['causes'] as List, parent['causes'] as List) ||
      !_sameSet(child['effects'] as List, parent['effects'] as List)) {
    return (false, "a refinement must keep the parent's causes and effects");
  }
  var added = 0;
  for (final field in croOptionalFields) {
    if (parent.containsKey(field)) {
      if (!deepEquals(child[field], parent[field])) {
        return (
          false,
          'a refinement may not change a field the parent specified; '
              'this is a rival claim'
        );
      }
    } else if (child.containsKey(field)) {
      added++;
    }
  }
  if (added == 0) {
    return (false, 'a refinement must add at least one unspecified field');
  }
  return (true, 'valid refinement');
}

// ===========================================================================
// 2.0.0 NORMATIVE ALGORITHMS (Section 12)
// ===========================================================================

/// ALGORITHM A. Every finer occurrent an occurrent resolves to, following
/// Bridges downward, transitively. Includes the starting occurrent (N12.1.1).
/// The visited guard (N12.1.2) prevents an infinite loop on cyclic data.
Set<String> bridgeClosure(
    String occurrentId, Iterable<Map<String, dynamic>> bridges) {
  final result = <String>{occurrentId};
  final frontier = <String>[occurrentId];
  final visited = <String>{};
  final coarseIndex = <String, List<Map<String, dynamic>>>{};
  for (final b in bridges) {
    coarseIndex.putIfAbsent(b['coarse'] as String, () => []).add(b);
  }
  while (frontier.isNotEmpty) {
    final current = frontier.removeLast();
    if (visited.contains(current)) continue;
    visited.add(current);
    for (final b in coarseIndex[current] ?? const []) {
      for (final f in (b['fine'] as List).cast<String>()) {
        result.add(f);
        frontier.add(f);
      }
    }
  }
  return result;
}

bool _pathExists(Map<String, Set<String>> edges, String src, String dst) {
  final seen = <String>{};
  final stack = <String>[src];
  while (stack.isNotEmpty) {
    final node = stack.removeLast();
    if (node == dst) return true;
    if (seen.contains(node)) continue;
    seen.add(node);
    stack.addAll(edges[node] ?? const <String>{});
  }
  return false;
}

/// ALGORITHM B (amended Rule 7): 'consistent' | 'inconsistent' |
/// 'indeterminate', ACROSS STRATA via bridged reachability.
///
/// members: mapping from CRO identifier to CRO object for the mechanism
/// entries. bridges: the store's bridges (empty -> 1.0.0 literal reachability,
/// the degenerate case, N12.2.3).
String hierarchyConsistent(
    Map<String, dynamic> parent, Map<String, Map<String, dynamic>> members,
    [Iterable<Map<String, dynamic>> bridges = const []]) {
  final mechanism = ((parent['mechanism'] as List?) ?? const []).cast<String>();
  if (mechanism.isEmpty) {
    return 'consistent'; // nothing claimed, nothing to check (N12.2.1)
  }
  final edges = <String, Set<String>>{};
  for (final mid in mechanism) {
    final m = members[mid];
    if (m == null) {
      return 'indeterminate'; // dangling; ignorance, not refutation
    }
    for (final c in (m['causes'] as List).cast<String>()) {
      edges.putIfAbsent(c, () => <String>{})
          .addAll((m['effects'] as List).cast<String>());
    }
  }
  final bCause = {
    for (final c in (parent['causes'] as List).cast<String>())
      c: bridgeClosure(c, bridges),
  };
  final bEffect = {
    for (final e in (parent['effects'] as List).cast<String>())
      e: bridgeClosure(e, bridges),
  };
  for (final c in (parent['causes'] as List).cast<String>()) {
    for (final e in (parent['effects'] as List).cast<String>()) {
      final connected = bCause[c]!
          .any((cp) => bEffect[e]!.any((ep) => _pathExists(edges, cp, ep)));
      if (!connected) {
        return 'inconsistent';
      }
    }
  }
  return 'consistent';
}

String? _stratumOf(Map<String, Map<String, dynamic>> occMap, String occId) =>
    occMap[occId]?['stratum'] as String?;

/// ALGORITHM C (Rule 15): 'intra_stratal' | 'adjacent_stratal' | 'skipping' |
/// 'mixed' | 'unclassifiable' | 'scheme_mismatch'. Derived, never asserted.
String classifyCro(Map<String, dynamic> cro,
    Map<String, Map<String, dynamic>> occMap,
    Map<String, Map<String, dynamic>> stratumMap) {
  final causeStrata =
      (cro['causes'] as List).map((c) => _stratumOf(occMap, c as String)).toList();
  final effectStrata =
      (cro['effects'] as List).map((e) => _stratumOf(occMap, e as String)).toList();
  if ([...causeStrata, ...effectStrata].any((s) => s == null)) {
    return 'unclassifiable'; // surface unstratified_occurrent (invitation)
  }
  final allStrata = {...causeStrata, ...effectStrata};
  final schemes = allStrata.map((s) => stratumMap[s]!['scheme']).toSet();
  if (schemes.length > 1) {
    return 'scheme_mismatch'; // HARD
  }
  final cOrd =
      causeStrata.map((s) => stratumMap[s]!['ordinal'] as num).toList();
  final eOrd =
      effectStrata.map((s) => stratumMap[s]!['ordinal'] as num).toList();
  final cMax = cOrd.reduce(math.max), cMin = cOrd.reduce(math.min);
  final eMax = eOrd.reduce(math.max), eMin = eOrd.reduce(math.min);
  if (cMax == cMin && cMin == eMax && eMax == eMin) {
    return 'intra_stratal';
  }
  num gap = double.infinity, span = 0;
  for (final i in cOrd) {
    for (final j in eOrd) {
      final d = (i - j).abs();
      if (d < gap) gap = d;
      if (d > span) span = d;
    }
  }
  if (span == 1) return 'adjacent_stratal';
  if (gap > 1) return 'skipping';
  return 'mixed'; // some pairs adjacent, some skipping
}

/// True iff causes or effects span more than one distinct stratum (surfaces
/// mixed_stratal_endpoints, an invitation; N12.3.2).
bool endpointsMixed(
    Map<String, dynamic> cro, Map<String, Map<String, dynamic>> occMap) {
  final cs =
      (cro['causes'] as List).map((c) => _stratumOf(occMap, c as String)).toSet();
  final es =
      (cro['effects'] as List).map((e) => _stratumOf(occMap, e as String)).toSet();
  if (cs.contains(null) || es.contains(null)) return false;
  return cs.length > 1 || es.length > 1;
}

/// ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
/// skip decision. THE ASYMMETRY (clause 3) is implemented exactly.
List<String> skipGaps(Map<String, dynamic> cro, String classification) {
  final gaps = <String>[];
  final hasMech = (cro['mechanism'] as List?)?.isNotEmpty ?? false;
  if (cro['skips'] == true && hasMech) {
    gaps.add('contradictory_skip'); // HARD
    return gaps;
  }
  if (cro['skips'] == true &&
      classification != 'skipping' &&
      classification != 'unclassifiable') {
    gaps.add('vacuous_skip'); // invitation
  }
  if (classification == 'skipping' && !hasMech) {
    if (cro['skips'] == true) {
      // NOTHING: absence is a finding
    } else {
      gaps.add('incomplete_mechanism'); // invitation
    }
  }
  return gaps;
}

/// ALGORITHM E helper: normalize a delay to seconds by the fixed table.
num toSeconds(num duration, String unit) {
  if (unit == 'instant') return 0;
  return duration * unitSeconds[unit]!;
}

/// ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
/// temporal window? Inclusive at both ends (N12.5.2).
bool delayWithinWindow(
    Map<String, dynamic>? actualDelay, Map<String, dynamic>? temporal) {
  if (actualDelay == null ||
      actualDelay.isEmpty ||
      temporal == null ||
      temporal.isEmpty) {
    return true; // nothing to check
  }
  final observed =
      toSeconds(actualDelay['duration'] as num, actualDelay['unit'] as String);
  final lo = toSeconds(temporal['minimum_delay'] as num, temporal['unit'] as String);
  final hi = toSeconds(temporal['maximum_delay'] as num, temporal['unit'] as String);
  return lo <= observed && observed <= hi;
}

/// Rule 14 / N3.2.1: (ok, reason). All of (a)-(e) must hold, else
/// malformed_bridge.
(bool, String) bridgeWellformed(Map<String, dynamic> bridge,
    Map<String, Map<String, dynamic>> occMap,
    Map<String, Map<String, dynamic>> stratumMap) {
  final coarse = occMap[bridge['coarse']] ?? const {};
  final cs = coarse['stratum'] as String?;
  if (cs == null) {
    return (false, 'malformed_bridge: coarse has no stratum (a)');
  }
  final fineStrata = (bridge['fine'] as List)
      .map((f) => occMap[f]?['stratum'] as String?)
      .toList();
  if (fineStrata.any((s) => s == null)) {
    return (false, 'malformed_bridge: a fine member has no stratum (b)');
  }
  if (fineStrata.toSet().length != 1) {
    return (false, 'malformed_bridge: fine members span >1 stratum (c)');
  }
  final fs = fineStrata.first!;
  if (stratumMap[cs]!['scheme'] != stratumMap[fs]!['scheme']) {
    return (false, 'malformed_bridge: coarse and fine differ in scheme (d)');
  }
  if (!((stratumMap[cs]!['ordinal'] as num) >
      (stratumMap[fs]!['ordinal'] as num))) {
    return (false, 'malformed_bridge: coarse ordinal not > fine ordinal (e)');
  }
  return (true, 'well-formed bridge');
}

/// Rule 17 / N4.2.1-2: (ok, reason). N4.2.1 with the transform exception of
/// N4.2.2.
(bool, String) conduitWellformed(Map<String, dynamic> conduit,
    Map<String, Map<String, dynamic>> portMap,
    [Map<String, Map<String, dynamic>>? croMap]) {
  final frm = portMap[conduit['from']];
  final to = portMap[conduit['to']];
  if (frm == null || to == null) {
    return (false, 'malformed_conduit: dangling port reference');
  }
  if (!const ['out', 'bidirectional'].contains(frm['direction'])) {
    return (false, 'malformed_conduit: from port is not out/bidirectional (a)');
  }
  if (!const ['in', 'bidirectional'].contains(to['direction'])) {
    return (false, 'malformed_conduit: to port is not in/bidirectional (b)');
  }
  final carries = (conduit['carries'] as List).cast<String>();
  final fromAccepts = (frm['accepts'] as List).cast<String>();
  if (!carries.every(fromAccepts.contains)) {
    return (false, 'malformed_conduit: carries not accepted by from (c)');
  }
  final transform = conduit['transform'];
  final toAccepts = (to['accepts'] as List).cast<String>();
  if (transform == null) {
    if (!carries.every(toAccepts.contains)) {
      return (false, 'malformed_conduit: carries not accepted by to (d)');
    }
  } else {
    final law = croMap?[transform];
    if (law != null) {
      if (!(law['effects'] as List).cast<String>().every(toAccepts.contains)) {
        return (false,
            'malformed_conduit: transform effects not accepted by to '
                '(d, relaxed per N4.2.2)');
      }
    }
  }
  return (true, 'well-formed conduit');
}

/// Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against its
/// quality: value_type_mismatch and/or unit_mismatch.
List<String> stateGaps(
    Map<String, dynamic> state, Map<String, dynamic> quality) {
  final gaps = <String>[];
  final dt = quality['datatype'];
  final v = (state['value'] as Map?) ?? const {};
  final shape = v.containsKey('quantity')
      ? 'quantity'
      : v.containsKey('categorical')
          ? 'categorical'
          : v.containsKey('boolean')
              ? 'boolean'
              : null;
  if (shape != dt) {
    gaps.add('value_type_mismatch');
  } else if (dt == 'quantity' && v['unit'] != quality['unit']) {
    gaps.add('unit_mismatch');
  }
  return gaps;
}

/// Rule 20: True iff the token claim's cause/effect tokens do not instantiate
/// the covering law's causes/effects (surfaces covering_law_mismatch).
bool coveringLawMismatch(Map<String, dynamic> tcc,
    Map<String, Map<String, dynamic>> tokenMap, Map<String, dynamic>? law) {
  if (law == null || law.isEmpty) return false;
  final lawCauses = (law['causes'] as List).cast<String>().toSet();
  final lawEffects = (law['effects'] as List).cast<String>().toSet();
  for (final c in (tcc['causes'] as List).cast<String>()) {
    if (!lawCauses.contains(tokenMap[c]!['instantiates'])) return true;
  }
  for (final e in (tcc['effects'] as List).cast<String>()) {
    if (!lawEffects.contains(tokenMap[e]!['instantiates'])) return true;
  }
  return false;
}

/// Rule 21: True iff any cause token starts after any effect token (HARD;
/// retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically.
bool retrocausal(
    Map<String, dynamic> tcc, Map<String, Map<String, dynamic>> tokenMap) {
  for (final c in (tcc['causes'] as List).cast<String>()) {
    final cstart = (tokenMap[c]!['interval'] as Map)['start'] as String;
    for (final e in (tcc['effects'] as List).cast<String>()) {
      final estart = (tokenMap[e]!['interval'] as Map)['start'] as String;
      if (cstart.compareTo(estart) > 0) return true;
    }
  }
  return false;
}

/// Rules 4 / 6.1: True iff a directed graph (node -> successors) has a cycle.
/// Used for the bridge graph, occurrent_subsumes/part_of, and token mereology.
bool hasCycle(Map<String, dynamic> edges) {
  const white = 0, grey = 1, black = 2;
  final state = <String, int>{};

  bool visit(String node) {
    state[node] = grey;
    for (final nxt in (edges[node] as List?) ?? const []) {
      final s = state[nxt as String] ?? white;
      if (s == grey) return true;
      if (s == white && visit(nxt)) return true;
    }
    state[node] = black;
    return false;
  }

  for (final n in edges.keys.toList()) {
    if ((state[n] ?? white) == white && visit(n)) return true;
  }
  return false;
}

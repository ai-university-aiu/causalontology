/// The semantic rules beyond the schemas (spec/semantics.md).
///
/// Local rules are checked here; store-context rules (materialized
/// acyclicity, retraction lineage) live in store.dart where the context
/// exists.
library;

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

/// Rule 12: enrichment field-to-kind validity and entry shapes.
const Map<String, (List<String>, String)> enrichmentFields = {
  'aliases': (['occurrent', 'continuant'], 'alias'),
  'participants': (['occurrent'], 'cnt'),
  'subsumes': (['continuant'], 'cnt'),
  'part_of': (['continuant'], 'cnt'),
  'realized_in': (['realizable'], 'occ'),
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

  if (k == 'cro') {
    final t = obj['temporal'] as Map?;
    if (t != null &&
        t['dmin'] != null &&
        t['dmax'] != null &&
        (t['dmin'] as num) > (t['dmax'] as num)) {
      errors.add('dmin must be <= dmax');
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
  final lo = (t['dmin'] as num) * unit;
  final hi = (t['dmax'] as num) * unit;
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
  final loA = (ta['dmin'] as num) * ua, hiA = (ta['dmax'] as num) * ua;
  final loB = (tb['dmin'] as num) * ub, hiB = (tb['dmax'] as num) * ub;
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

const Set<String> _positive = {'necessary', 'sufficient', 'contributory'};

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

/// Rule 7: 'consistent' | 'inconsistent' | 'indeterminate'.
///
/// members: a mapping from CRO identifier to CRO object for the parent's
/// mechanism entries (the store's view of them).
String hierarchyConsistent(
    Map<String, dynamic> parent, Map<String, Map<String, dynamic>> members) {
  final mechanism = ((parent['mechanism'] as List?) ?? const []).cast<String>();
  if (mechanism.isEmpty) {
    return 'consistent'; // nothing claimed, nothing to check
  }
  final edges = <String, Set<String>>{};
  for (final mid in mechanism) {
    final m = members[mid];
    if (m == null) {
      return 'indeterminate'; // a dangling_reference gap, not a failure
    }
    for (final c in (m['causes'] as List).cast<String>()) {
      edges.putIfAbsent(c, () => <String>{})
          .addAll((m['effects'] as List).cast<String>());
    }
  }

  bool reachable(String src, String dst) {
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

  for (final c in (parent['causes'] as List).cast<String>()) {
    for (final e in (parent['effects'] as List).cast<String>()) {
      if (!reachable(c, e)) {
        return 'inconsistent';
      }
    }
  }
  return 'consistent';
}

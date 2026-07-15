#!/usr/bin/env python3
"""Appendix D — THE WORKED REFERENCE ENCODING (the golden example).

The steroid hormone channel: the layer-skipping causal path by which a social
event at the community stratum (ordinal 14) alters gene expression at the
macromolecular stratum (ordinal 4), WITHOUT being re-encoded at any of the ten
intervening strata. Every identifier here is the real SHA-256 of the object's
RFC 8785 canonical identity-bearing bytes, computed (never assigned) by the
causalontology binding.

Running this file encodes the channel end to end, checks that the skipping
Causal Relation Object surfaces NO gap, and answers the acceptance query of
change-order Section 11(8). If it prints the answer, 2.0.0 is proven on the
hardest case its author could find (Checklist Step 13).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bindings" / "python"))

from causalontology import (identify, validate_schema, classify_cro, skip_gaps,
                            hierarchy_consistent, bridge_closure)


def mk(o):
    o = dict(o); o["id"] = identify(o); return o


# D.1 THE STRATA (two of the fifteen; the scheme is shared) --------------------
macromolecular = mk({"type": "stratum", "label": "macromolecular",
                     "scheme": "neuroendocrine", "ordinal": 4, "unit": "protein",
                     "governs": ["structural_biology", "biochemistry"]})
society = mk({"type": "stratum", "label": "community_and_society",
              "scheme": "neuroendocrine", "ordinal": 14, "unit": "institution",
              "governs": ["cultural_neuroscience", "social_epidemiology"]})

# D.2 THE OCCURRENTS -----------------------------------------------------------
subordination = mk({"type": "occurrent", "label": "chronic_social_subordination",
                    "category": "process", "stratum": society["id"]})
gr_binds_dna = mk({"type": "occurrent", "label": "glucocorticoid_receptor_binds_dna",
                   "category": "event", "stratum": macromolecular["id"]})

# D.3 THE SKIPPING Causal Relation Object (the point of the whole exercise) -----
skipping = mk({"type": "causal_relation_object",
               "causes": [subordination["id"]], "effects": [gr_binds_dna["id"]],
               "temporal": {"minimum_delay": 1, "maximum_delay": 24, "unit": "hours"},
               "modality": "contributory", "context": [], "skips": True})

occ_map = {subordination["id"]: subordination, gr_binds_dna["id"]: gr_binds_dna}
stratum_map = {macromolecular["id"]: macromolecular, society["id"]: society}

classification = classify_cro(skipping, occ_map, stratum_map)
gaps = skip_gaps(skipping, classification)

# The identical record WITHOUT skips would surface incomplete_mechanism (V62).
absent = dict(skipping); absent.pop("skips")
gaps_absent = skip_gaps(absent, classify_cro(absent, occ_map, stratum_map))


def main():
    print("Steroid hormone channel — Appendix D, encoded in 2.0.0\n")
    for name, obj in [("stratum (society)", society),
                      ("stratum (macromolecular)", macromolecular),
                      ("occurrent (subordination)", subordination),
                      ("occurrent (GR binds DNA)", gr_binds_dna),
                      ("SKIPPING causal_relation_object", skipping)]:
        ok, why = validate_schema(obj)
        assert ok, (name, why)
        print("  %-34s %s" % (name, obj["id"]))

    print("\nAlgorithm C classification: causes@14, effects@4, gap 10 -> %s"
          % classification.upper())
    assert classification == "skipping"
    print("Algorithm D (skips: true):  gaps = %s   <- NO GAP" % (gaps or "[]"))
    assert gaps == []
    print("Algorithm D (skips absent): gaps = %s" % gaps_absent)
    assert gaps_absent == ["incomplete_mechanism"]

    # D.8 THE ACCEPTANCE QUERY (Section 11.8)
    print("\nAcceptance query: 'By what route does a social event alter gene "
          "expression,\n  and is that route RELAYED or DIRECT?'")
    social = [o for o in occ_map.values()
              if o.get("stratum") == society["id"]]
    answer = []
    for cro_obj in [skipping]:
        if any(c in [o["id"] for o in social] for c in cro_obj["causes"]):
            cls = classify_cro(cro_obj, occ_map, stratum_map)
            if cls == "skipping":
                route = "DIRECT" if cro_obj.get("skips") else "RELAYED"
                answer.append((cro_obj["id"], cls, route))
    for cid, cls, route in answer:
        print("  ANSWER: %s\n          classified %s, route %s "
              "(the cortisol molecule that binds the DNA is the same physical\n"
              "          molecule the adrenal released; ten layers crossed in "
              "one physical step)." % (cid, cls.upper(), route))
    assert answer and answer[0][2] == "DIRECT"
    print("\n2.0.0 is proven on the hardest case its author could find.")


if __name__ == "__main__":
    main()

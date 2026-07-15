# frozen_string_literal: false

# The semantic rules beyond the schemas (spec/semantics.md).
#
# Local rules are checked here; store-context rules (materialized acyclicity,
# retraction lineage) live in store.rb where the context exists.

require "set"
require_relative "canonical"

module Causalontology
  module Semantics
    # Rule 4: the fixed unit-conversion constants (average Gregorian values).
    UNIT_SECONDS = {
      "instant" => 0,
      "seconds" => 1,
      "minutes" => 60,
      "hours"   => 3600,
      "days"    => 86400,
      "weeks"   => 604800,
      "months"  => 2629746,
      "years"   => 31556952,
    }.freeze

    # Rule 12: enrichment field-to-kind validity and entry shapes. Two
    # occurrent forms added in 2.0.0.
    ENRICHMENT_FIELDS = {
      "aliases"            => [["occurrent", "continuant"], "alias"],
      "participants"       => [["occurrent"],               "continuant"],
      "subsumes"           => [["continuant"],              "continuant"],
      "part_of"            => [["continuant"],              "continuant"],
      "realized_in"        => [["realizable"],              "occurrent"],
      "occurrent_subsumes" => [["occurrent"],               "occurrent"],
      "occurrent_part_of"  => [["occurrent"],               "occurrent"],
    }.freeze

    CRO_OPTIONAL_FIELDS = ["mechanism", "temporal", "modality", "context"].freeze

    # Rule 6 (amended): necessary, sufficient, contributory, enabling are
    # mutually compatible; preventive opposes all four.
    POSITIVE = Set.new(["necessary", "sufficient", "contributory",
                        "enabling"]).freeze

    module_function

    def kind_of_id(identifier)
      Canonical::KIND_OF_PREFIX[identifier.split(":", 2)[0]]
    end

    # [ok, reasons] - the locally checkable semantic rules.
    def validate_semantics(obj, kind = nil)
      kind ||= Canonical.infer_kind(obj)
      errors = []

      if kind == "causal_relation_object"
        t = obj["temporal"]
        if !t.nil? && !t["minimum_delay"].nil? && !t["maximum_delay"].nil? && t["minimum_delay"] > t["maximum_delay"]
          errors << "minimum_delay must be <= maximum_delay"
        end
        oid = obj["id"]
        if oid && (obj["mechanism"] || []).include?(oid)
          errors << "mechanism must be acyclic " \
                    "(a Causal Relation Object may not contain itself)"
        end
        if oid && obj["refines"] == oid
          errors << "refines must be acyclic"
        end
        # Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        # contradiction between skips:true and a non-empty mechanism.
        if obj["skips"] == true && obj["mechanism"] && !obj["mechanism"].empty?
          errors << "contradictory_skip: skips is true but a mechanism " \
                    "is present"
        end
      end

      if kind == "enrichment"
        field = obj["field"]
        about = obj["about"] || ""
        entry = obj["entry"]
        spec = ENRICHMENT_FIELDS[field]
        if spec
          legal_kinds, shape = spec
          about_kind = kind_of_id(about)
          if about_kind && !legal_kinds.include?(about_kind)
            errors << "#{field} is not a legal field for a #{about_kind} (rule 12)"
          end
          if shape == "alias"
            unless entry.is_a?(Hash) && entry.key?("lang") && entry.key?("text")
              errors << "an aliases entry must be a language-tagged text object"
            end
          else
            unless entry.is_a?(String) && entry.start_with?(shape + ":")
              errors << "a #{field} entry must be a #{shape}: identifier"
            end
          end
        end
      end

      [errors.empty?, errors]
    end

    # [partial, missing] - which optional CRO fields are unspecified.
    def is_partial(cro)
      missing = CRO_OPTIONAL_FIELDS.reject { |f| cro.key?(f) }
      [!missing.empty?, missing]
    end

    # Rule 4: temporal admissibility with the fixed constants.
    def admissible(cro, elapsed_seconds)
      t = cro["temporal"]
      return true if t.nil? # no window imposes no constraint
      unit = UNIT_SECONDS.fetch(t["unit"])
      lo = t["minimum_delay"] * unit
      hi = t["maximum_delay"] * unit
      lo <= elapsed_seconds && elapsed_seconds <= hi
    end

    def window_overlap(a, b)
      ta = a["temporal"]
      tb = b["temporal"]
      return true if ta.nil? || tb.nil? # either absent counts as overlapping
      ua = UNIT_SECONDS.fetch(ta["unit"])
      ub = UNIT_SECONDS.fetch(tb["unit"])
      lo_a = ta["minimum_delay"] * ua
      hi_a = ta["maximum_delay"] * ua
      lo_b = tb["minimum_delay"] * ub
      hi_b = tb["maximum_delay"] * ub
      lo_a <= hi_b && lo_b <= hi_a
    end

    def contexts_compatible(a, b)
      ca = a["context"]
      cb = b["context"]
      return true if ca.nil? || ca.empty? || cb.nil? || cb.empty?
      sa = Set.new(ca)
      sb = Set.new(cb)
      sa == sb || sa.subset?(sb) || sb.subset?(sa)
    end

    # Rule 6: the formal conflict test.
    def conflicts(a, b)
      return false if Set.new(a["causes"]) != Set.new(b["causes"])
      return false if Set.new(a["effects"]) != Set.new(b["effects"])
      return false unless contexts_compatible(a, b)
      return false unless window_overlap(a, b)
      ma = a["modality"]
      mb = b["modality"]
      (ma == "preventive" && POSITIVE.include?(mb)) ||
        (mb == "preventive" && POSITIVE.include?(ma))
    end

    # Rule 3: [ok, reason] - is child a valid refinement of parent?
    def refinement_valid(child, parent)
      if child["refines"] != parent["id"]
        return [false, "child does not name the parent in refines"]
      end
      if Set.new(child["causes"]) != Set.new(parent["causes"]) ||
         Set.new(child["effects"]) != Set.new(parent["effects"])
        return [false, "a refinement must keep the parent's causes and effects"]
      end
      added = 0
      CRO_OPTIONAL_FIELDS.each do |field|
        if parent.key?(field)
          if child[field] != parent[field]
            return [false, "a refinement may not change a field the " \
                           "parent specified; this is a rival claim"]
          end
        elsif child.key?(field)
          added += 1
        end
      end
      if added == 0
        return [false, "a refinement must add at least one unspecified field"]
      end
      [true, "valid refinement"]
    end

    # =======================================================================
    # 2.0.0 NORMATIVE ALGORITHMS (Section 12)
    # =======================================================================

    # ALGORITHM A. Every finer occurrent an occurrent resolves to, following
    # Bridges downward, transitively. Includes the starting occurrent
    # (N12.1.1). `bridges` is any iterable of bridge objects. The visited guard
    # (N12.1.2) prevents an infinite loop on malformed cyclic data.
    def bridge_closure(occurrent_id, bridges)
      result = Set.new([occurrent_id])
      frontier = [occurrent_id]
      visited = Set.new
      coarse_index = {}
      bridges.each { |b| (coarse_index[b["coarse"]] ||= []) << b }
      until frontier.empty?
        current = frontier.pop
        next if visited.include?(current)
        visited << current
        (coarse_index[current] || []).each do |b|
          b["fine"].each do |f|
            result << f
            frontier << f
          end
        end
      end
      result
    end

    def path_exists(edges, src, dst)
      seen = Set.new
      stack = [src]
      until stack.empty?
        node = stack.pop
        return true if node == dst
        next if seen.include?(node)
        seen << node
        stack.concat((edges[node] || []).to_a)
      end
      false
    end

    # ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
    # "indeterminate", ACROSS STRATA via bridged reachability.
    #
    # members: mapping from CRO identifier to CRO object for the mechanism
    # entries. bridges: the store's bridges (empty -> 1.0.0 literal
    # reachability, the degenerate case, N12.2.3).
    def hierarchy_consistent(parent, members, bridges = [])
      mechanism = parent["mechanism"] || []
      return "consistent" if mechanism.empty? # nothing claimed (N12.2.1)
      edges = {}
      mechanism.each do |mid|
        m = members[mid]
        return "indeterminate" if m.nil? # dangling; ignorance, not refutation
        m["causes"].each do |c|
          (edges[c] ||= Set.new).merge(m["effects"])
        end
      end
      b_cause = {}
      parent["causes"].each { |c| b_cause[c] = bridge_closure(c, bridges) }
      b_effect = {}
      parent["effects"].each { |e| b_effect[e] = bridge_closure(e, bridges) }
      parent["causes"].each do |c|
        parent["effects"].each do |e|
          connected = b_cause[c].any? do |cp|
            b_effect[e].any? { |ep| path_exists(edges, cp, ep) }
          end
          return "inconsistent" unless connected
        end
      end
      "consistent"
    end

    # ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" |
    # "skipping" | "mixed" | "unclassifiable" | "scheme_mismatch".
    # Derived, never asserted; recompute on ingest (N12.3.1).
    def classify_cro(cro, occ_map, stratum_map)
      stratum_of = lambda { |occ_id| (occ_map[occ_id] || {})["stratum"] }
      cause_strata = cro["causes"].map { |c| stratum_of.call(c) }
      effect_strata = cro["effects"].map { |e| stratum_of.call(e) }
      if (cause_strata + effect_strata).any?(&:nil?)
        return "unclassifiable" # surface unstratified_occurrent (invitation)
      end
      all_strata = Set.new(cause_strata) | Set.new(effect_strata)
      schemes = Set.new(all_strata.map { |s| stratum_map[s]["scheme"] })
      return "scheme_mismatch" if schemes.length > 1 # HARD
      c_ord = cause_strata.map { |s| stratum_map[s]["ordinal"] }
      e_ord = effect_strata.map { |s| stratum_map[s]["ordinal"] }
      if c_ord.max == c_ord.min && c_ord.min == e_ord.max && e_ord.max == e_ord.min
        return "intra_stratal"
      end
      pairs = c_ord.product(e_ord).map { |i, j| (i - j).abs }
      gap = pairs.min
      span = pairs.max
      return "adjacent_stratal" if span == 1
      return "skipping" if gap > 1
      "mixed" # some pairs adjacent, some skipping
    end

    # True iff causes or effects span more than one distinct stratum
    # (surfaces mixed_stratal_endpoints, an invitation; N12.3.2).
    def endpoints_mixed(cro, occ_map)
      stratum_of = lambda { |occ_id| (occ_map[occ_id] || {})["stratum"] }
      cs = Set.new(cro["causes"].map { |c| stratum_of.call(c) })
      es = Set.new(cro["effects"].map { |e| stratum_of.call(e) })
      return false if cs.include?(nil) || es.include?(nil)
      cs.length > 1 || es.length > 1
    end

    # ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
    # skip decision. THE ASYMMETRY (clause 3) is the whole point of the field
    # and is implemented exactly.
    def skip_gaps(cro, classification)
      gaps = []
      has_mech = !(cro["mechanism"] || []).empty?
      if cro["skips"] == true && has_mech
        gaps << "contradictory_skip" # HARD
        return gaps
      end
      if cro["skips"] == true &&
         !["skipping", "unclassifiable"].include?(classification)
        gaps << "vacuous_skip" # invitation
      end
      if classification == "skipping" && !has_mech
        if cro["skips"] == true
          # NOTHING: absence is a finding
        else
          gaps << "incomplete_mechanism" # invitation
        end
      end
      gaps
    end

    # ALGORITHM E helper: normalize a delay to seconds by the fixed table.
    def to_seconds(duration, unit)
      return 0 if unit == "instant"
      duration * UNIT_SECONDS.fetch(unit)
    end

    # ALGORITHM E (Rule 20): does an observed delay fall within a covering
    # law's temporal window? Inclusive at both ends (N12.5.2).
    def delay_within_window(actual_delay, temporal)
      return true if actual_delay.nil? || actual_delay.empty? ||
                     temporal.nil? || temporal.empty?
      observed = to_seconds(actual_delay["duration"], actual_delay["unit"])
      lo = to_seconds(temporal["minimum_delay"], temporal["unit"])
      hi = to_seconds(temporal["maximum_delay"], temporal["unit"])
      lo <= observed && observed <= hi
    end

    # Rule 14 / N3.2.1: Bridge well-formedness. [ok, reason]. All of (a)-(e)
    # of N3.2.1 must hold, else malformed_bridge.
    def bridge_wellformed(bridge, occ_map, stratum_map)
      coarse = occ_map[bridge["coarse"]] || {}
      cs = coarse["stratum"]
      return [false, "malformed_bridge: coarse has no stratum (a)"] if cs.nil?
      fine_strata = bridge["fine"].map { |f| (occ_map[f] || {})["stratum"] }
      if fine_strata.any?(&:nil?)
        return [false, "malformed_bridge: a fine member has no stratum (b)"]
      end
      if Set.new(fine_strata).length != 1
        return [false, "malformed_bridge: fine members span >1 stratum (c)"]
      end
      fs = fine_strata[0]
      if stratum_map[cs]["scheme"] != stratum_map[fs]["scheme"]
        return [false, "malformed_bridge: coarse and fine differ in scheme (d)"]
      end
      unless stratum_map[cs]["ordinal"] > stratum_map[fs]["ordinal"]
        return [false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"]
      end
      [true, "well-formed bridge"]
    end

    # Rule 17 / N4.2.1-2: Conduit well-formedness. [ok, reason]. N4.2.1 with
    # the transform exception of N4.2.2.
    def conduit_wellformed(conduit, port_map, cro_map = nil)
      frm = port_map[conduit["from"]]
      to = port_map[conduit["to"]]
      if frm.nil? || to.nil?
        return [false, "malformed_conduit: dangling port reference"]
      end
      unless ["out", "bidirectional"].include?(frm["direction"])
        return [false, "malformed_conduit: from port is not out/bidirectional (a)"]
      end
      unless ["in", "bidirectional"].include?(to["direction"])
        return [false, "malformed_conduit: to port is not in/bidirectional (b)"]
      end
      carries = conduit["carries"]
      unless carries.all? { |o| frm["accepts"].include?(o) }
        return [false, "malformed_conduit: carries not accepted by from (c)"]
      end
      transform = conduit["transform"]
      if transform.nil?
        unless carries.all? { |o| to["accepts"].include?(o) }
          return [false, "malformed_conduit: carries not accepted by to (d)"]
        end
      else
        law = (cro_map || {})[transform]
        unless law.nil?
          unless law["effects"].all? { |o| to["accepts"].include?(o) }
            return [false, "malformed_conduit: transform effects not " \
                           "accepted by to (d, relaxed per N4.2.2)"]
          end
        end
      end
      [true, "well-formed conduit"]
    end

    # Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against its
    # quality: value_type_mismatch and/or unit_mismatch.
    def state_gaps(state, quality)
      gaps = []
      dt = quality["datatype"]
      v = state["value"] || {}
      shape = if v.key?("quantity") then "quantity"
              elsif v.key?("categorical") then "categorical"
              elsif v.key?("boolean") then "boolean"
              end
      if shape != dt
        gaps << "value_type_mismatch"
      elsif dt == "quantity" && v["unit"] != quality["unit"]
        gaps << "unit_mismatch"
      end
      gaps
    end

    # Rule 20: true iff the token claim's cause/effect tokens do not
    # instantiate the covering law's causes/effects (surfaces
    # covering_law_mismatch).
    def covering_law_mismatch(tcc, token_map, law)
      return false if law.nil?
      law_causes = Set.new(law["causes"])
      law_effects = Set.new(law["effects"])
      tcc["causes"].each do |c|
        return true unless law_causes.include?(token_map[c]["instantiates"])
      end
      tcc["effects"].each do |e|
        return true unless law_effects.include?(token_map[e]["instantiates"])
      end
      false
    end

    # Rule 21: true iff any cause token starts after any effect token (HARD;
    # retrocausal_claim). RFC 3339 UTC "Z" strings compare lexicographically.
    def retrocausal(tcc, token_map)
      tcc["causes"].each do |c|
        cstart = token_map[c]["interval"]["start"]
        tcc["effects"].each do |e|
          estart = token_map[e]["interval"]["start"]
          return true if cstart > estart
        end
      end
      false
    end

    # Rules 4 / 6.1: true iff a directed graph (node -> iterable of successors)
    # has a cycle. Used for bridge graph, occurrent_subsumes, occurrent_part_of,
    # and token mereology (part_of).
    def has_cycle(edges)
      white = 0
      grey = 1
      black = 2
      state = {}
      visit = nil
      visit = lambda do |node|
        state[node] = grey
        (edges[node] || []).each do |nxt|
          s = state.fetch(nxt, white)
          return true if s == grey
          return true if s == white && visit.call(nxt)
        end
        state[node] = black
        false
      end
      edges.keys.any? { |n| state.fetch(n, white) == white && visit.call(n) }
    end
  end
end

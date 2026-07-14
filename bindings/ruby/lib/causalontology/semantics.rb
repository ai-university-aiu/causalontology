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

    # Rule 12: enrichment field-to-kind validity and entry shapes.
    ENRICHMENT_FIELDS = {
      "aliases"      => [["occurrent", "continuant"], "alias"],
      "participants" => [["occurrent"],               "cnt"],
      "subsumes"     => [["continuant"],              "cnt"],
      "part_of"      => [["continuant"],              "cnt"],
      "realized_in"  => [["realizable"],              "occ"],
    }.freeze

    CRO_OPTIONAL_FIELDS = ["mechanism", "temporal", "modality", "context"].freeze

    # The positive modalities of the formal conflict test (rule 6).
    POSITIVE = Set.new(["necessary", "sufficient", "contributory"]).freeze

    module_function

    def kind_of_id(identifier)
      Canonical::KIND_OF_PREFIX[identifier.split(":", 2)[0]]
    end

    # [ok, reasons] - the locally checkable semantic rules.
    def validate_semantics(obj, kind = nil)
      kind ||= Canonical.infer_kind(obj)
      errors = []

      if kind == "cro"
        t = obj["temporal"]
        if !t.nil? && !t["dmin"].nil? && !t["dmax"].nil? && t["dmin"] > t["dmax"]
          errors << "dmin must be <= dmax"
        end
        oid = obj["id"]
        if oid && (obj["mechanism"] || []).include?(oid)
          errors << "mechanism must be acyclic " \
                    "(a Causal Relation Object may not contain itself)"
        end
        if oid && obj["refines"] == oid
          errors << "refines must be acyclic"
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
      lo = t["dmin"] * unit
      hi = t["dmax"] * unit
      lo <= elapsed_seconds && elapsed_seconds <= hi
    end

    def window_overlap(a, b)
      ta = a["temporal"]
      tb = b["temporal"]
      return true if ta.nil? || tb.nil? # either absent counts as overlapping
      ua = UNIT_SECONDS.fetch(ta["unit"])
      ub = UNIT_SECONDS.fetch(tb["unit"])
      lo_a = ta["dmin"] * ua
      hi_a = ta["dmax"] * ua
      lo_b = tb["dmin"] * ub
      hi_b = tb["dmax"] * ub
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

    # Rule 7: "consistent" | "inconsistent" | "indeterminate".
    #
    # members: a mapping from CRO identifier to CRO object for the parent's
    # mechanism entries (the store's view of them).
    def hierarchy_consistent(parent, members)
      mechanism = parent["mechanism"] || []
      return "consistent" if mechanism.empty? # nothing claimed, nothing to check
      edges = {}
      mechanism.each do |mid|
        m = members[mid]
        return "indeterminate" if m.nil? # a dangling_reference gap, not a failure
        m["causes"].each do |c|
          (edges[c] ||= Set.new).merge(m["effects"])
        end
      end

      reachable = lambda do |src, dst|
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

      parent["causes"].each do |c|
        parent["effects"].each do |e|
          return "inconsistent" unless reachable.call(c, e)
        end
      end
      "consistent"
    end
  end
end

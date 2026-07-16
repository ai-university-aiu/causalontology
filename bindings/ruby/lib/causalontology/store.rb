# frozen_string_literal: false

# An in-memory conformant store.
#
# Implements the store side of the abstract operation set (spec/store.md):
# immutable content objects with idempotent put; signed, add-only provenance
# records; materialized enrichment views with contributors; retraction handling
# in default views; succession lineage; the resolve minimum; the deterministic
# cycle-breaking view rule; and the stigmergy gap read.
#
# Ruby Hashes preserve insertion order, exactly like Python dicts, so every
# iteration below deliberately mirrors the reference store's iteration order.

require "set"
require_relative "canonical"
require_relative "schema"
require_relative "semantics"
require_relative "signing"

module Causalontology
  CONTENT_KINDS = Set.new(["occurrent", "causal_relation_object", "continuant",
                           "realizable", "stratum", "bridge", "port", "conduit",
                           "quality", "token_individual", "token_occurrence",
                           "state_assertion", "token_causal_claim"]).freeze
  RECORD_KINDS = Set.new(["assertion", "enrichment", "retraction", "succession"]).freeze

  # An enforcing store refused a write, with the reason as the message.
  class RejectedWrite < StandardError; end

  class InMemoryStore
    attr_reader :enforcing, :objects, :records, :quarantine

    def initialize(enforcing: true)
      @enforcing = enforcing
      @objects = {}    # id -> content object
      @records = {}    # id -> provenance record
      @quarantine = {} # id -> record (unsigned / unverifiable)
    end

    # ---------------------------------------------------------------- put

    # Write a content object; idempotent; returns the identifier.
    def put(obj, kind = nil)
      kind ||= Canonical.infer_kind(obj)
      unless CONTENT_KINDS.include?(kind)
        raise ArgumentError, "put() takes content objects; use put_record()"
      end
      obj = obj.dup
      obj["type"] = kind unless obj.key?("type")
      obj["id"] = Canonical.identify(obj, kind) unless obj.key?("id")
      return obj["id"] if @objects.key?(obj["id"]) # immutable: identical identity is a no-op
      ok, why = Schema.validate_schema(obj, kind)
      raise RejectedWrite, why.join("; ") unless ok
      ok, why = Semantics.validate_semantics(obj, kind)
      raise RejectedWrite, why.join("; ") unless ok
      @objects[obj["id"]] = obj
      obj["id"]
    end

    # Write a signed provenance record; returns the identifier.
    def put_record(record, kind = nil, force: false)
      kind ||= Canonical.infer_kind(record)
      unless RECORD_KINDS.include?(kind)
        raise ArgumentError, "put_record() takes provenance records"
      end
      record = record.dup
      record["type"] = kind unless record.key?("type")
      rid = record["id"]
      rid = Canonical.identify(record, kind) if rid.nil? || rid.empty?
      record["id"] = rid
      return rid if @records.key?(rid) # add-only and idempotent
      unless Signing.verify_record(record, kind)
        @quarantine[rid] = record
        raise RejectedWrite, "unsigned or unverifiable record: quarantined"
      end
      ok, why = Semantics.validate_semantics(record, kind)
      raise RejectedWrite, why.join("; ") unless ok
      if kind == "retraction" && !retraction_source_ok(record)
        raise RejectedWrite,
              "a retraction is valid only from the retracted record's " \
              "source or its succession lineage"
      end
      if kind == "enrichment" && @enforcing && !force
        if ["subsumes", "part_of"].include?(record["field"]) && would_cycle(record)
          raise RejectedWrite,
                "would create a cycle in the materialized " \
                "#{record["field"]} graph"
        end
      end
      @records[rid] = record
      rid
    end

    # Simulate a decentralized replica merge (no enforcement gate).
    def force_merge_record(record, kind = nil)
      put_record(record, kind, force: true)
    end

    # ----------------------------------------------------- record queries

    def records_of(kind)
      @records.values.select { |r| r["type"] == kind }
    end

    def retracted_ids
      out = Set.new
      records_of("retraction").each { |r| out << r["retracts"] }
      out
    end

    def retraction_source_ok(retraction)
      target = @records[retraction["retracts"]]
      return true if target.nil? # open world: the target may arrive later
      lineage(target["source"]).include?(retraction["source"])
    end

    # The succession chain closure containing key (includes key).
    def lineage(key)
      succ = {}
      pred = {}
      records_of("succession").each do |s|
        succ[s["predecessor"]] = s["successor"]
        pred[s["successor"]] = s["predecessor"]
      end
      chain = Set.new([key])
      cursor = key
      while pred.key?(cursor)
        cursor = pred[cursor]
        chain << cursor
      end
      cursor = key
      while succ.key?(cursor)
        cursor = succ[cursor]
        chain << cursor
      end
      chain
    end

    def assertions_about(identifier, include_retracted: false)
      retracted = retracted_ids
      out = []
      records_of("assertion").each do |r|
        next unless r["about"] == identifier
        if retracted.include?(r["id"])
          out << r.merge("retracted" => true) if include_retracted
          next
        end
        out << r
      end
      out
    end

    def enrichments_about(identifier, include_retracted: false)
      retracted = retracted_ids
      out = []
      records_of("enrichment").each do |r|
        next unless r["about"] == identifier
        next if retracted.include?(r["id"]) && !include_retracted
        out << r
      end
      out
    end

    # --------------------------------------------------- materialized views

    # [edges, excluded] for subsumes/part_of after rule 13 cycle-breaking.
    def active_taxonomy_edges(field)
      retracted = retracted_ids
      recs = records_of("enrichment").select do |r|
        r["field"] == field && !retracted.include?(r["id"])
      end
      active = recs.dup
      excluded = []
      loop do
        cyc = self.class.find_cycle_records(active)
        break if cyc.empty?
        # exclude the cycle-completing record with the LATEST timestamp,
        # ties broken by lexicographic record identifier (deterministic)
        loser = cyc.max_by { |r| [r["timestamp"], r["id"]] }
        active.delete_at(active.index(loser))
        excluded << loser
      end
      [active, excluded]
    end

    # The records forming one directed cycle among the given enrichment
    # records, or an empty array when the graph they draw is acyclic.
    def self.find_cycle_records(recs)
      edges = {}
      recs.each { |r| (edges[r["about"]] ||= []) << [r["entry"], r] }
      state = Hash.new(0)
      cycle = []

      dfs = nil
      dfs = lambda do |node, path_records|
        state[node] = 1
        (edges[node] || []).each do |nxt, rec|
          if state[nxt] == 1
            cycle.concat(path_records + [rec])
            return true
          end
          if state[nxt] == 0
            return true if dfs.call(nxt, path_records + [rec])
          end
        end
        state[node] = 2
        false
      end

      edges.keys.each do |start|
        return cycle if state[start] == 0 && dfs.call(start, [])
      end
      []
    end

    def would_cycle(record)
      retracted = retracted_ids
      recs = records_of("enrichment").select do |r|
        r["field"] == record["field"] && !retracted.include?(r["id"])
      end
      !self.class.find_cycle_records(recs + [record]).empty?
    end

    # The object with its materialized enrichment sets and contributors.
    def get(identifier, view: "default")
      obj = @objects[identifier]
      return nil if obj.nil?
      include_retracted = (view == "history")
      excluded_ids = Set.new
      ["subsumes", "part_of"].each do |field|
        _, excluded = active_taxonomy_edges(field)
        excluded.each { |r| excluded_ids << r["id"] }
      end
      fields = {}
      enrichments_about(identifier, include_retracted: include_retracted).each do |rec|
        next if excluded_ids.include?(rec["id"]) && view != "history"
        entry = rec["entry"]
        entry_key = [rec["field"],
                     entry.is_a?(Hash) ? entry.to_a.sort : entry]
        slot = (fields[rec["field"]] ||= {})
        bucket = (slot[entry_key] ||= { "entry" => entry, "contributors" => [] })
        bucket["contributors"] << {
          "source" => rec["source"], "timestamp" => rec["timestamp"]
        }
      end
      enrichments = fields.transform_values(&:values)
      return { "object" => obj } if view == "raw"
      { "object" => obj, "enrichments" => enrichments }
    end

    # -------------------------------------------------------------- resolve

    def self.canon_label(text)
      text.strip.downcase.split.join("_")
    end

    def self.norm_alias(text)
      text.split.join(" ").downcase(:fold)
    end

    # The conformance minimum: exact label, then alias, then nothing.
    def resolve(text, lang = nil)
      label_hits = []
      alias_hits = []
      wanted_label = self.class.canon_label(text)
      wanted_alias = self.class.norm_alias(text)
      retracted = retracted_ids
      @objects.each do |oid, obj|
        next unless ["occurrent", "continuant"].include?(obj["type"])
        if obj["label"] == wanted_label
          label_hits << oid
          next
        end
        records_of("enrichment").each do |rec|
          next unless rec["about"] == oid && rec["field"] == "aliases"
          next if retracted.include?(rec["id"])
          entry = rec["entry"]
          next if !lang.nil? && entry["lang"] != lang
          if self.class.norm_alias(entry["text"] || "") == wanted_alias
            alias_hits << oid
            break
          end
        end
      end
      label_hits + alias_hits
    end

    # ---------------------------------------------------------------- gaps

    # The stigmergy read. Gap kinds per spec/store.md.
    def gaps(kind = nil)
      out = []
      refined = Set.new
      @objects.each_value do |obj|
        next unless obj["type"] == "causal_relation_object" && obj["refines"]
        parent = @objects[obj["refines"]]
        next if parent.nil?
        ok, _reason = Semantics.refinement_valid(obj, parent)
        refined << parent["id"] if ok
      end
      @objects.each do |oid, obj|
        next unless obj["type"] == "causal_relation_object"
        # missing_field: lacking the temporal window or the modality -
        # mechanism and context may legitimately stay unspecified forever
        # (empty_mechanism is its own kind; absent context = context-free).
        if (!obj.key?("temporal") || !obj.key?("modality")) &&
           !refined.include?(oid)
          out << { "id" => oid, "kind" => "missing_field",
                   "missing" => Semantics.is_partial(obj)[1] }
        end
        if !obj.key?("mechanism") || obj["mechanism"] == []
          unless refined.include?(oid)
            out << { "id" => oid, "kind" => "empty_mechanism" }
          end
        end
      end
      ["subsumes", "part_of"].each do |field|
        _, excluded = active_taxonomy_edges(field)
        excluded.each do |rec|
          out << { "id" => rec["id"], "kind" => "inconsistent_hierarchy",
                   "note" => "excluded by the deterministic " \
                             "cycle-breaking view rule" }
        end
      end
      # dangling_reference: a reference to an object absent from the store -
      # the red link that says "this page is wanted".
      @objects.each do |oid, obj|
        refs = []
        if obj["type"] == "causal_relation_object"
          refs = (obj["causes"] || []).to_a +
                 (obj["effects"] || []).to_a +
                 (obj["context"] || []).to_a +
                 (obj["mechanism"] || []).to_a
          refs << obj["refines"] if obj["refines"]
        elsif obj["type"] == "realizable"
          refs = [obj["bearer"]]
        end
        refs.each do |ref|
          if ref && !@objects.key?(ref)
            out << { "id" => oid, "kind" => "dangling_reference", "ref" => ref }
          end
        end
      end
      # conflict: pairs of claims satisfying the formal test (rule 6).
      cros = @objects.values.select { |o| o["type"] == "causal_relation_object" }
      (0...cros.length).each do |i|
        ((i + 1)...cros.length).each do |j|
          if Semantics.conflicts(cros[i], cros[j])
            out << { "kind" => "conflict",
                     "a" => cros[i]["id"], "b" => cros[j]["id"] }
          end
        end
      end
      out = out.select { |g| g["kind"] == kind } unless kind.nil?
      out
    end
  end
end

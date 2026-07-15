# frozen_string_literal: false

# Schema validation against spec/schema/*.schema.json.
#
# A deliberately small interpreter for exactly the JSON Schema keywords the
# seventeen Causalontology schemas use: type, const, enum, pattern, required,
# properties, additionalProperties, items, minItems, minLength, minimum,
# maximum, oneOf, local $ref (#/$defs/...), and cross-file $ref to a sibling
# schema (https://causalontology.org/schema/<file>.schema.json#/...). "format"
# is treated as an annotation, as the 2020-12 draft does by default.

require "json"
require_relative "canonical"

module Causalontology
  module Schema
    # kind -> schema file. Three token kinds keep their original 1.0.0-reserved
    # file names (individual/token/state); the id scheme is the whole word.
    SCHEMA_FILES = {
      "occurrent"  => "occurrent.schema.json",
      "causal_relation_object" => "causal_relation_object.schema.json",
      "continuant" => "continuant.schema.json",
      "realizable" => "realizable.schema.json",
      "stratum"    => "stratum.schema.json",
      "bridge"     => "bridge.schema.json",
      "port"       => "port.schema.json",
      "conduit"    => "conduit.schema.json",
      "quality"    => "quality.schema.json",
      "token_individual"   => "individual.schema.json",
      "token_occurrence"   => "token.schema.json",
      "state_assertion"    => "state.schema.json",
      "token_causal_claim" => "token_causal_claim.schema.json",
      "assertion"  => "assertion.schema.json",
      "enrichment" => "enrichment.schema.json",
      "retraction" => "retraction.schema.json",
      "succession" => "succession.schema.json",
    }.freeze

    BASE = "https://causalontology.org/schema/"

    @cache = {}

    class << self
      def schema_dir
        env = ENV["CAUSALONTOLOGY_SPEC"]
        return File.join(env, "schema") if env && !env.empty?
        # lib/causalontology -> lib -> ruby -> bindings -> repository root
        File.expand_path("../../../../spec/schema", __dir__)
      end

      # Load and cache a schema document by its file name.
      def load_file(filename)
        @cache[filename] ||= JSON.parse(
          File.read(File.join(schema_dir, filename)))
      end

      def load_schema(kind)
        unless SCHEMA_FILES.key?(kind)
          raise ArgumentError, "unknown kind: #{kind.inspect}"
        end
        load_file(SCHEMA_FILES[kind])
      end

      # Navigate a JSON pointer (slash-separated) within a document.
      def navigate(doc, pointer)
        node = doc
        pointer.split("/").each do |part|
          next if part == ""
          node = node[part]
        end
        node
      end

      # Resolve local and cross-file $refs to a concrete schema node plus the
      # root document it lives in. Returns [schema, root].
      def resolve_ref(schema, root)
        while schema.is_a?(Hash) && schema.key?("$ref")
          ref = schema["$ref"]
          if ref.start_with?("#/")
            schema = navigate(root, ref[2..])
          elsif ref.start_with?(BASE)
            rest = ref[BASE.length..]
            filename, pointer = rest.split("#/", 2)
            root = load_file(filename)
            schema = pointer ? navigate(root, pointer) : root
          else
            raise ArgumentError, "unsupported $ref: #{ref.inspect}"
          end
        end
        [schema, root]
      end

      def type_matches?(value, t)
        case t
        when "object"  then value.is_a?(Hash)
        when "array"   then value.is_a?(Array)
        when "string"  then value.is_a?(String)
        when "number"  then value.is_a?(Integer) || value.is_a?(Float)
        when "integer" then value.is_a?(Integer)
        when "boolean" then value == true || value == false
        else
          raise ArgumentError, "unknown schema type: #{t.inspect}"
        end
      end

      def numeric?(value)
        value.is_a?(Integer) || value.is_a?(Float)
      end

      def check(value, schema, root, path, errors)
        schema, root = resolve_ref(schema, root)

        if schema.key?("oneOf")
          passing = 0
          schema["oneOf"].each do |sub|
            suberrs = []
            check(value, sub, root, path, suberrs)
            passing += 1 if suberrs.empty?
          end
          if passing != 1
            errors << "#{path}: matches #{passing} of the oneOf branches " \
                      "(need exactly 1)"
          end
          return
        end

        t = schema["type"]
        if !t.nil? && !type_matches?(value, t)
          errors << "#{path}: expected #{t}"
          return
        end

        if schema.key?("const") && value != schema["const"]
          errors << "#{path}: must equal #{schema["const"].inspect}"
        end
        if schema.key?("enum") && !schema["enum"].include?(value)
          errors << "#{path}: #{value.inspect} not in enumeration"
        end
        if schema.key?("pattern") && value.is_a?(String)
          unless Regexp.new(schema["pattern"]).match?(value)
            errors << "#{path}: #{value.inspect} does not match " \
                      "#{schema["pattern"]}"
          end
        end
        if schema.key?("minLength") && value.is_a?(String)
          if value.length < schema["minLength"]
            errors << "#{path}: shorter than minLength"
          end
        end
        if schema.key?("minimum") && numeric?(value)
          if value < schema["minimum"]
            errors << "#{path}: below minimum #{schema["minimum"]}"
          end
        end
        if schema.key?("maximum") && numeric?(value)
          if value > schema["maximum"]
            errors << "#{path}: above maximum #{schema["maximum"]}"
          end
        end

        if value.is_a?(Array)
          if schema.key?("minItems") && value.length < schema["minItems"]
            errors << "#{path}: fewer than #{schema["minItems"]} items"
          end
          if schema.key?("items")
            value.each_with_index do |item, i|
              check(item, schema["items"], root, "#{path}[#{i}]", errors)
            end
          end
        end

        if value.is_a?(Hash)
          props = schema["properties"] || {}
          (schema["required"] || []).each do |req|
            unless value.key?(req)
              errors << "#{path}: required property '#{req}' missing"
            end
          end
          if schema["additionalProperties"] == false
            value.each_key do |key|
              unless props.key?(key)
                errors << "#{path}: additional property '#{key}'"
              end
            end
          end
          props.each do |key, sub|
            if value.key?(key)
              check(value[key], sub, root, "#{path}.#{key}", errors)
            end
          end
        end
      end

      # [ok, reasons] - structural validity against the kind's JSON Schema.
      def validate_schema(obj, kind = nil)
        kind ||= Canonical.infer_kind(obj)
        root = load_schema(kind)
        errors = []
        check(obj, root, root, "$", errors)
        [errors.empty?, errors]
      end
    end
  end
end

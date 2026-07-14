# frozen_string_literal: false

# Schema validation against spec/schema/*.schema.json.
#
# A deliberately small interpreter for exactly the JSON Schema keywords the
# eight Causalontology schemas use: type, const, enum, pattern, required,
# properties, additionalProperties, items, minItems, minLength, minimum,
# maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
# annotation, as the 2020-12 draft does by default.

require "json"
require_relative "canonical"

module Causalontology
  module Schema
    SCHEMA_FILES = {
      "cro"        => "cro.schema.json",
      "occurrent"  => "occurrent.schema.json",
      "continuant" => "continuant.schema.json",
      "realizable" => "realizable.schema.json",
      "assertion"  => "assertion.schema.json",
      "enrichment" => "enrichment.schema.json",
      "retraction" => "retraction.schema.json",
      "succession" => "succession.schema.json",
    }.freeze

    @cache = {}

    class << self
      def schema_dir
        env = ENV["CAUSALONTOLOGY_SPEC"]
        return File.join(env, "schema") if env && !env.empty?
        # lib/causalontology -> lib -> ruby -> bindings -> repository root
        File.expand_path("../../../../spec/schema", __dir__)
      end

      def load_schema(kind)
        unless SCHEMA_FILES.key?(kind)
          raise ArgumentError, "unknown kind: #{kind.inspect}"
        end
        @cache[kind] ||= JSON.parse(
          File.read(File.join(schema_dir, SCHEMA_FILES[kind])))
      end

      # Follow local $ref chains (#/$defs/...) to the referenced subschema.
      def resolve_ref(schema, root)
        while schema.key?("$ref")
          ref = schema["$ref"]
          unless ref.start_with?("#/")
            raise ArgumentError, "only local $ref supported: #{ref.inspect}"
          end
          node = root
          ref[2..].split("/").each { |part| node = node[part] }
          schema = node
        end
        schema
      end

      def type_matches?(value, t)
        case t
        when "object"  then value.is_a?(Hash)
        when "array"   then value.is_a?(Array)
        when "string"  then value.is_a?(String)
        when "number"  then value.is_a?(Integer) || value.is_a?(Float)
        when "boolean" then value == true || value == false
        else
          raise ArgumentError, "unknown schema type: #{t.inspect}"
        end
      end

      def numeric?(value)
        value.is_a?(Integer) || value.is_a?(Float)
      end

      def check(value, schema, root, path, errors)
        schema = resolve_ref(schema, root)

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

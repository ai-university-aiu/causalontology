// SchemaValidator.swift
//
// Schema validation against spec/schema/*.schema.json.
//
// A deliberately small interpreter for exactly the JSON Schema keywords the
// eight Causalontology schemas use: type, const, enum, pattern, required,
// properties, additionalProperties, items, minItems, minLength, minimum,
// maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
// annotation, as the 2020-12 draft does by default.

import Foundation

/// Loads the eight schemas from a spec/schema directory and validates
/// objects against them. Not thread-safe (the schema cache is unlocked);
/// the conformance harness is single-threaded.
public final class SchemaValidator {
    /// The schema file name per kind.
    public static let schemaFiles: [String: String] = [
        "causal_relation_object": "cro.schema.json",
        "occurrent": "occurrent.schema.json",
        "continuant": "continuant.schema.json",
        "realizable": "realizable.schema.json",
        "assertion": "assertion.schema.json",
        "enrichment": "enrichment.schema.json",
        "retraction": "retraction.schema.json",
        "succession": "succession.schema.json",
    ]

    private let schemaDirectory: URL
    private var cache: [String: JsonValue] = [:]

    public init(schemaDirectory: URL) {
        self.schemaDirectory = schemaDirectory
    }

    /// The default spec/schema directory: the CAUSALONTOLOGY_SPEC environment
    /// variable (a spec/ directory) if set, else the CAUSALONTOLOGY_ROOT
    /// environment variable (the repository root) if set, else the location
    /// derived from this source file's position in the repository
    /// (bindings/swift/Sources/Causalontology/ -> five parents up -> root).
    public static func defaultSchemaDirectory() -> URL {
        let environment = ProcessInfo.processInfo.environment
        if let spec = environment["CAUSALONTOLOGY_SPEC"] {
            return URL(fileURLWithPath: spec).appendingPathComponent("schema")
        }
        if let root = environment["CAUSALONTOLOGY_ROOT"] {
            return URL(fileURLWithPath: root)
                .appendingPathComponent("spec")
                .appendingPathComponent("schema")
        }
        var url = URL(fileURLWithPath: #filePath)
        // SchemaValidator.swift -> Causalontology -> Sources -> swift
        // -> bindings -> repository root.
        for _ in 0..<5 {
            url.deleteLastPathComponent()
        }
        return url.appendingPathComponent("spec").appendingPathComponent("schema")
    }

    /// A shared validator over the default schema directory.
    public static let standard = SchemaValidator(schemaDirectory: defaultSchemaDirectory())

    /// Load (and cache) the root schema for a kind.
    public func loadSchema(forKind kind: String) throws -> JsonValue {
        if let cached = cache[kind] {
            return cached
        }
        guard let fileName = SchemaValidator.schemaFiles[kind] else {
            throw CausalontologyError("unknown kind: \(kind)")
        }
        let url = schemaDirectory.appendingPathComponent(fileName)
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw CausalontologyError("cannot read schema file: \(url.path)")
        }
        let schema = try JsonValue.parse(data)
        cache[kind] = schema
        return schema
    }

    /// (ok, reasons) - structural validity against the kind's JSON Schema.
    public func validate(
        _ obj: [String: JsonValue],
        kind: String? = nil
    ) throws -> (ok: Bool, reasons: [String]) {
        let resolvedKind: String
        if let kind = kind {
            resolvedKind = kind
        } else {
            resolvedKind = try inferKind(obj)
        }
        let root = try loadSchema(forKind: resolvedKind)
        var errors: [String] = []
        try check(.object(obj), schema: root, root: root, path: "$", errors: &errors)
        return (errors.isEmpty, errors)
    }

    // MARK: - The keyword interpreter

    /// Follow local $ref chains ("#/$defs/...") to the referenced subschema.
    private func resolveRef(_ schema: JsonValue, root: JsonValue) throws -> JsonValue {
        var current = schema
        while let ref = current["$ref"]?.stringValue {
            guard ref.hasPrefix("#/") else {
                throw CausalontologyError("only local $ref supported: \(ref)")
            }
            var node = root
            for part in ref.dropFirst(2).split(separator: "/") {
                guard let next = node[String(part)] else {
                    throw CausalontologyError("unresolvable $ref: \(ref)")
                }
                node = next
            }
            current = node
        }
        return current
    }

    /// True when the value is an instance of the named JSON Schema type.
    private func typeMatches(_ value: JsonValue, _ typeName: String) -> Bool {
        switch typeName {
        case "object":
            return value.objectValue != nil
        case "array":
            return value.arrayValue != nil
        case "string":
            return value.stringValue != nil
        case "number":
            // Booleans are never numbers here (JsonValue keeps them apart).
            return value.numberValue != nil
        case "boolean":
            return value.boolValue != nil
        case "null":
            return value.isNull
        default:
            return false
        }
    }

    /// A short display form for error messages.
    private func describe(_ value: JsonValue) -> String {
        switch value {
        case let .string(text):
            return "'\(text)'"
        default:
            return (try? jcsString(value)) ?? "<value>"
        }
    }

    /// True when the pattern is found anywhere in the string (re.search
    /// semantics; every Causalontology pattern is itself ^...$-anchored).
    private func patternFound(_ pattern: String, in text: String) throws -> Bool {
        let regex: NSRegularExpression
        do {
            regex = try NSRegularExpression(pattern: pattern)
        } catch {
            throw CausalontologyError("invalid schema pattern: \(pattern)")
        }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.firstMatch(in: text, options: [], range: range) != nil
    }

    /// The recursive keyword check; appends messages to errors.
    private func check(
        _ value: JsonValue,
        schema rawSchema: JsonValue,
        root: JsonValue,
        path: String,
        errors: inout [String]
    ) throws {
        let schema = try resolveRef(rawSchema, root: root)

        if let branches = schema["oneOf"]?.arrayValue {
            var passing = 0
            for branch in branches {
                var branchErrors: [String] = []
                try check(value, schema: branch, root: root, path: path, errors: &branchErrors)
                if branchErrors.isEmpty {
                    passing += 1
                }
            }
            if passing != 1 {
                errors.append("\(path): matches \(passing) of the oneOf branches (need exactly 1)")
            }
            return
        }

        if let typeName = schema["type"]?.stringValue {
            if !typeMatches(value, typeName) {
                errors.append("\(path): expected \(typeName)")
                return
            }
        }

        if let constValue = schema["const"], value != constValue {
            errors.append("\(path): must equal \(describe(constValue))")
        }
        if let allowed = schema["enum"]?.arrayValue, !allowed.contains(value) {
            errors.append("\(path): \(describe(value)) not in enumeration")
        }
        if let pattern = schema["pattern"]?.stringValue, let text = value.stringValue {
            if try !patternFound(pattern, in: text) {
                errors.append("\(path): '\(text)' does not match \(pattern)")
            }
        }
        if let minLength = schema["minLength"]?.numberValue, let text = value.stringValue {
            if Double(text.unicodeScalars.count) < minLength {
                errors.append("\(path): shorter than minLength")
            }
        }
        if let minimum = schema["minimum"]?.numberValue, let number = value.numberValue {
            if number < minimum {
                errors.append("\(path): below minimum \(describe(schema["minimum"]!))")
            }
        }
        if let maximum = schema["maximum"]?.numberValue, let number = value.numberValue {
            if number > maximum {
                errors.append("\(path): above maximum \(describe(schema["maximum"]!))")
            }
        }

        if let items = value.arrayValue {
            if let minItems = schema["minItems"]?.numberValue {
                if Double(items.count) < minItems {
                    errors.append("\(path): fewer than \(Int(minItems)) items")
                }
            }
            if let itemSchema = schema["items"] {
                for (index, item) in items.enumerated() {
                    try check(item, schema: itemSchema, root: root,
                              path: "\(path)[\(index)]", errors: &errors)
                }
            }
        }

        if let members = value.objectValue {
            let properties = schema["properties"]?.objectValue ?? [:]
            if let required = schema["required"]?.arrayValue {
                for requirement in required {
                    if let name = requirement.stringValue, members[name] == nil {
                        errors.append("\(path): required property '\(name)' missing")
                    }
                }
            }
            if schema["additionalProperties"] == JsonValue.bool(false) {
                for key in members.keys.sorted() where properties[key] == nil {
                    errors.append("\(path): additional property '\(key)'")
                }
            }
            for key in properties.keys.sorted() {
                if let member = members[key] {
                    try check(member, schema: properties[key]!, root: root,
                              path: "\(path).\(key)", errors: &errors)
                }
            }
        }
    }
}

/// (ok, reasons) against the shared default validator - the module-level
/// convenience mirroring the Python binding's validate_schema.
public func validateSchema(
    _ obj: [String: JsonValue],
    kind: String? = nil
) throws -> (ok: Bool, reasons: [String]) {
    return try SchemaValidator.standard.validate(obj, kind: kind)
}

// Schema validation against spec/schema/*.schema.json.
//
// A deliberately small interpreter for exactly the JSON Schema keywords
// the eight Causalontology schemas use: type, const, enum, pattern,
// required, properties, additionalProperties, items, minItems, minLength,
// minimum, maximum, oneOf, and local $ref (#/$defs/...). "format" is
// treated as an annotation, as the 2020-12 draft does by default.

using System.Text.RegularExpressions;

namespace Causalontology;

public static class SchemaValidator
{
    private static readonly IReadOnlyDictionary<string, string> SchemaFiles =
        new Dictionary<string, string>
        {
            ["causal_relation_object"] = "cro.schema.json",
            ["occurrent"] = "occurrent.schema.json",
            ["continuant"] = "continuant.schema.json",
            ["realizable"] = "realizable.schema.json",
            ["assertion"] = "assertion.schema.json",
            ["enrichment"] = "enrichment.schema.json",
            ["retraction"] = "retraction.schema.json",
            ["succession"] = "succession.schema.json",
        };

    private static readonly Dictionary<string, JsonMap> Cache = new();

    private static string SchemaDir()
    {
        var env = Environment.GetEnvironmentVariable("CAUSALONTOLOGY_SPEC");
        if (!string.IsNullOrEmpty(env))
            return Path.Combine(env, "schema");
        var root = Environment.GetEnvironmentVariable("CAUSALONTOLOGY_ROOT");
        if (!string.IsNullOrEmpty(root))
            return Path.Combine(root, "spec", "schema");
        // walk up from the working directory until spec/schema is found
        var dir = Directory.GetCurrentDirectory();
        for (var i = 0; i < 12 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "spec", "schema");
            if (Directory.Exists(candidate))
                return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new DirectoryNotFoundException(
            "no spec/schema above the working directory; "
            + "set CAUSALONTOLOGY_SPEC or CAUSALONTOLOGY_ROOT");
    }

    /// <summary>The parsed JSON Schema for a kind (cached).</summary>
    public static JsonMap LoadSchema(string kind)
    {
        if (!SchemaFiles.TryGetValue(kind, out var file))
            throw new ArgumentException($"unknown kind: {kind}");
        if (!Cache.TryGetValue(kind, out var schema))
        {
            schema = (JsonMap)Json.ParseFile(Path.Combine(SchemaDir(), file))!;
            Cache[kind] = schema;
        }
        return schema;
    }

    private static JsonMap Resolve(JsonMap schema, JsonMap root)
    {
        while (schema.Get("$ref") is string reference)
        {
            if (!reference.StartsWith("#/", StringComparison.Ordinal))
                throw new ArgumentException(
                    $"only local $ref supported: {reference}");
            object? node = root;
            foreach (var part in reference[2..].Split('/'))
                node = ((JsonMap)node!)[part];
            schema = (JsonMap)node!;
        }
        return schema;
    }

    private static bool TypeMatches(object? value, string type) => type switch
    {
        "object" => value is JsonMap,
        "array" => value is List<object?>,
        "string" => value is string,
        "number" => Json.IsNumber(value), // bool is not a number in JSON
        "boolean" => value is bool,
        _ => throw new ArgumentException($"unknown schema type: {type}"),
    };

    private static void Check(object? value, JsonMap schema, JsonMap root,
                              string path, List<string> errors)
    {
        schema = Resolve(schema, root);

        if (schema.Get("oneOf") is List<object?> branches)
        {
            var passing = 0;
            foreach (var branch in branches)
            {
                var subErrors = new List<string>();
                Check(value, (JsonMap)branch!, root, path, subErrors);
                if (subErrors.Count == 0)
                    passing++;
            }
            if (passing != 1)
                errors.Add($"{path}: matches {passing} of the oneOf branches "
                           + "(need exactly 1)");
            return;
        }

        if (schema.Get("type") is string type)
        {
            if (!TypeMatches(value, type))
            {
                errors.Add($"{path}: expected {type}");
                return;
            }
        }

        if (schema.ContainsKey("const")
            && !Json.DeepEquals(value, schema["const"]))
            errors.Add($"{path}: must equal '{schema["const"]}'");
        if (schema.Get("enum") is List<object?> allowed
            && !allowed.Any(item => Json.DeepEquals(value, item)))
            errors.Add($"{path}: '{value}' not in enumeration");
        if (schema.Get("pattern") is string pattern && value is string text)
        {
            if (!Regex.IsMatch(text, pattern))
                errors.Add($"{path}: '{text}' does not match {pattern}");
        }
        if (schema.ContainsKey("minLength") && value is string str)
        {
            if (str.Length < Json.ToDouble(schema["minLength"]))
                errors.Add($"{path}: shorter than minLength");
        }
        if (schema.ContainsKey("minimum") && Json.IsNumber(value))
        {
            if (Json.ToDouble(value) < Json.ToDouble(schema["minimum"]))
                errors.Add($"{path}: below minimum {schema["minimum"]}");
        }
        if (schema.ContainsKey("maximum") && Json.IsNumber(value))
        {
            if (Json.ToDouble(value) > Json.ToDouble(schema["maximum"]))
                errors.Add($"{path}: above maximum {schema["maximum"]}");
        }

        if (value is List<object?> array)
        {
            if (schema.ContainsKey("minItems")
                && array.Count < Json.ToDouble(schema["minItems"]))
                errors.Add($"{path}: fewer than {schema["minItems"]} items");
            if (schema.Get("items") is JsonMap items)
            {
                for (var i = 0; i < array.Count; i++)
                    Check(array[i], items, root, $"{path}[{i}]", errors);
            }
        }

        if (value is JsonMap obj)
        {
            var properties = schema.Get("properties") as JsonMap ?? new JsonMap();
            if (schema.Get("required") is List<object?> required)
            {
                foreach (var req in required)
                {
                    if (!obj.ContainsKey((string)req!))
                        errors.Add($"{path}: required property '{req}' missing");
                }
            }
            if (schema.Get("additionalProperties") is bool additional && !additional)
            {
                foreach (var key in obj.Keys)
                {
                    if (!properties.ContainsKey(key))
                        errors.Add($"{path}: additional property '{key}'");
                }
            }
            foreach (var key in properties.Keys)
            {
                if (obj.ContainsKey(key))
                    Check(obj[key], (JsonMap)properties[key]!, root,
                          $"{path}.{key}", errors);
            }
        }
    }

    /// <summary>(ok, reasons) — structural validity against the kind's JSON Schema.</summary>
    public static (bool Ok, List<string> Reasons) ValidateSchema(
        JsonMap obj, string? kind = null)
    {
        kind ??= Canonical.InferKind(obj);
        var root = LoadSchema(kind);
        var errors = new List<string>();
        Check(obj, root, root, "$", errors);
        return (errors.Count == 0, errors);
    }
}

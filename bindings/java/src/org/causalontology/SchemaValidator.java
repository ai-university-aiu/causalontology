package org.causalontology;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Schema validation against spec/schema/*.schema.json.
 *
 * A deliberately small interpreter for exactly the JSON Schema keywords the
 * eight Causalontology schemas use: type, const, enum, pattern (search
 * semantics, like Python re.search / java.util.regex find()), required,
 * properties, additionalProperties:false, items, minItems, minLength,
 * minimum, maximum, oneOf (exactly one branch), and local $ref
 * ("#/$defs/..."). "format" is treated as an annotation, as the 2020-12
 * draft does by default.
 *
 * The schema directory is resolved from the system property
 * "causalontology.spec" or the environment variable CAUSALONTOLOGY_SPEC
 * (either names the spec/ directory), falling back to ../../spec/schema
 * relative to the working directory (bindings/java when run through
 * run_conformance.sh).
 */
public final class SchemaValidator {

    private static final Map<String, String> SCHEMA_FILES;

    static {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("cro", "cro.schema.json");
        files.put("occurrent", "occurrent.schema.json");
        files.put("continuant", "continuant.schema.json");
        files.put("realizable", "realizable.schema.json");
        files.put("assertion", "assertion.schema.json");
        files.put("enrichment", "enrichment.schema.json");
        files.put("retraction", "retraction.schema.json");
        files.put("succession", "succession.schema.json");
        SCHEMA_FILES = files;
    }

    private static final Map<String, Map<String, Object>> CACHE =
        new HashMap<>();

    private SchemaValidator() {
    }

    private static Path schemaDir() {
        String override = System.getProperty("causalontology.spec");
        if (override == null || override.isEmpty()) {
            override = System.getenv("CAUSALONTOLOGY_SPEC");
        }
        if (override != null && !override.isEmpty()) {
            return Paths.get(override, "schema");
        }
        return Paths.get("..", "..", "spec", "schema");
    }

    /** Load (and cache) the root schema for a kind. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> loadSchema(String kind) {
        String file = SCHEMA_FILES.get(kind);
        if (file == null) {
            throw new IllegalArgumentException("unknown kind: " + kind);
        }
        return CACHE.computeIfAbsent(kind, k -> {
            try {
                String text = Files.readString(schemaDir().resolve(file));
                return (Map<String, Object>) Json.parse(text);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    /** (ok, reasons) - structural validity against the kind's JSON Schema. */
    public static Validation validateSchema(Map<String, Object> obj,
                                            String kind) {
        String k = kind != null ? kind : Canonical.inferKind(obj);
        Map<String, Object> root = loadSchema(k);
        List<String> errors = new ArrayList<>();
        check(obj, root, root, "$", errors);
        return new Validation(errors.isEmpty(), errors);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> resolveRef(Map<String, Object> schema,
                                                  Map<String, Object> root) {
        Map<String, Object> current = schema;
        while (current.containsKey("$ref")) {
            String ref = (String) current.get("$ref");
            if (!ref.startsWith("#/")) {
                throw new IllegalArgumentException(
                    "only local $ref supported: " + ref);
            }
            Object node = root;
            for (String part : ref.substring(2).split("/")) {
                node = ((Map<String, Object>) node).get(part);
            }
            current = (Map<String, Object>) node;
        }
        return current;
    }

    @SuppressWarnings("unchecked")
    private static void check(Object value, Map<String, Object> schemaIn,
                              Map<String, Object> root, String path,
                              List<String> errors) {
        Map<String, Object> schema = resolveRef(schemaIn, root);

        if (schema.containsKey("oneOf")) {
            int passing = 0;
            for (Object sub : (List<Object>) schema.get("oneOf")) {
                List<String> subErrors = new ArrayList<>();
                check(value, (Map<String, Object>) sub, root, path, subErrors);
                if (subErrors.isEmpty()) {
                    passing++;
                }
            }
            if (passing != 1) {
                errors.add(path + ": matches " + passing
                           + " of the oneOf branches (need exactly 1)");
            }
            return;
        }

        String type = (String) schema.get("type");
        if (type != null) {
            boolean ok;
            switch (type) {
                case "object":
                    ok = value instanceof Map;
                    break;
                case "array":
                    ok = value instanceof List;
                    break;
                case "string":
                    ok = value instanceof String;
                    break;
                case "number":
                    // Boolean is not a Number in Java, so unlike Python no
                    // special bool exclusion is needed here.
                    ok = value instanceof Number;
                    break;
                case "boolean":
                    ok = value instanceof Boolean;
                    break;
                default:
                    throw new IllegalArgumentException(
                        "unsupported schema type: " + type);
            }
            if (!ok) {
                errors.add(path + ": expected " + type);
                return;
            }
        }

        if (schema.containsKey("const")
                && !Json.deepEquals(value, schema.get("const"))) {
            errors.add(path + ": must equal '" + schema.get("const") + "'");
        }
        if (schema.containsKey("enum")) {
            boolean found = false;
            for (Object option : (List<Object>) schema.get("enum")) {
                if (Json.deepEquals(value, option)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                errors.add(path + ": '" + value + "' not in enumeration");
            }
        }
        if (schema.containsKey("pattern") && value instanceof String) {
            String s = (String) value;
            String pattern = (String) schema.get("pattern");
            if (!Pattern.compile(pattern).matcher(s).find()) {
                errors.add(path + ": '" + s + "' does not match " + pattern);
            }
        }
        if (schema.containsKey("minLength") && value instanceof String) {
            String s = (String) value;
            int minLength = ((Number) schema.get("minLength")).intValue();
            if (s.length() < minLength) {
                errors.add(path + ": shorter than minLength");
            }
        }
        if (schema.containsKey("minimum") && value instanceof Number) {
            double v = ((Number) value).doubleValue();
            double minimum = ((Number) schema.get("minimum")).doubleValue();
            if (v < minimum) {
                errors.add(path + ": below minimum " + schema.get("minimum"));
            }
        }
        if (schema.containsKey("maximum") && value instanceof Number) {
            double v = ((Number) value).doubleValue();
            double maximum = ((Number) schema.get("maximum")).doubleValue();
            if (v > maximum) {
                errors.add(path + ": above maximum " + schema.get("maximum"));
            }
        }

        if (value instanceof List) {
            List<Object> list = (List<Object>) value;
            if (schema.containsKey("minItems")) {
                int minItems = ((Number) schema.get("minItems")).intValue();
                if (list.size() < minItems) {
                    errors.add(path + ": fewer than " + minItems + " items");
                }
            }
            if (schema.containsKey("items")) {
                Map<String, Object> items =
                    (Map<String, Object>) schema.get("items");
                for (int i = 0; i < list.size(); i++) {
                    check(list.get(i), items, root,
                          path + "[" + i + "]", errors);
                }
            }
        }

        if (value instanceof Map) {
            Map<String, Object> mapValue = (Map<String, Object>) value;
            Map<String, Object> props;
            if (schema.containsKey("properties")) {
                props = (Map<String, Object>) schema.get("properties");
            } else {
                props = new LinkedHashMap<>();
            }
            if (schema.containsKey("required")) {
                for (Object required : (List<Object>) schema.get("required")) {
                    if (!mapValue.containsKey(required)) {
                        errors.add(path + ": required property '" + required
                                   + "' missing");
                    }
                }
            }
            if (Boolean.FALSE.equals(schema.get("additionalProperties"))) {
                for (String key : mapValue.keySet()) {
                    if (!props.containsKey(key)) {
                        errors.add(path + ": additional property '" + key
                                   + "'");
                    }
                }
            }
            for (Map.Entry<String, Object> prop : props.entrySet()) {
                if (mapValue.containsKey(prop.getKey())) {
                    check(mapValue.get(prop.getKey()),
                          (Map<String, Object>) prop.getValue(), root,
                          path + "." + prop.getKey(), errors);
                }
            }
        }
    }
}

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
        // kind -> schema file. Three token kinds keep their original
        // 1.0.0-reserved file names (individual/token/state); the id scheme
        // is the whole word.
        Map<String, String> files = new LinkedHashMap<>();
        files.put("occurrent", "occurrent.schema.json");
        files.put("causal_relation_object",
                  "causal_relation_object.schema.json");
        files.put("continuant", "continuant.schema.json");
        files.put("realizable", "realizable.schema.json");
        files.put("stratum", "stratum.schema.json");
        files.put("bridge", "bridge.schema.json");
        files.put("port", "port.schema.json");
        files.put("conduit", "conduit.schema.json");
        files.put("quality", "quality.schema.json");
        files.put("token_individual", "individual.schema.json");
        files.put("token_occurrence", "token.schema.json");
        files.put("state_assertion", "state.schema.json");
        files.put("token_causal_claim", "token_causal_claim.schema.json");
        files.put("assertion", "assertion.schema.json");
        files.put("enrichment", "enrichment.schema.json");
        files.put("retraction", "retraction.schema.json");
        files.put("succession", "succession.schema.json");
        SCHEMA_FILES = files;
    }

    private static final String BASE =
        "https://causalontology.org/schema/";

    /** kind cache is unused; files are cached by filename for cross-refs. */
    private static final Map<String, Map<String, Object>> FILE_CACHE =
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

    /** Load (and cache) a schema file by its filename. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> loadFile(String file) {
        return FILE_CACHE.computeIfAbsent(file, f -> {
            try {
                String text = Files.readString(schemaDir().resolve(f));
                return (Map<String, Object>) Json.parse(text);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    /** Load (and cache) the root schema for a kind. */
    static Map<String, Object> loadSchema(String kind) {
        String file = SCHEMA_FILES.get(kind);
        if (file == null) {
            throw new IllegalArgumentException("unknown kind: " + kind);
        }
        return loadFile(file);
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

    /** A concrete schema node together with the file root it lives in. */
    private static final class Resolved {
        final Map<String, Object> schema;
        final Map<String, Object> root;

        Resolved(Map<String, Object> schema, Map<String, Object> root) {
            this.schema = schema;
            this.root = root;
        }
    }

    /**
     * Resolve local and cross-file $refs to a concrete schema node plus the
     * root it belongs to. Cross-file refs (the state -> token interval one)
     * switch the root so any further local refs resolve in the sibling file.
     */
    @SuppressWarnings("unchecked")
    private static Resolved resolve(Map<String, Object> schema,
                                    Map<String, Object> root) {
        Map<String, Object> current = schema;
        Map<String, Object> currentRoot = root;
        while (current.containsKey("$ref")) {
            String ref = (String) current.get("$ref");
            if (ref.startsWith("#/")) {
                current = (Map<String, Object>) navigate(currentRoot,
                                                         ref.substring(2));
            } else if (ref.startsWith(BASE)) {
                String rest = ref.substring(BASE.length());
                int hash = rest.indexOf("#/");
                String filename = hash < 0 ? rest : rest.substring(0, hash);
                String pointer = hash < 0 ? "" : rest.substring(hash + 2);
                currentRoot = loadFile(filename);
                current = pointer.isEmpty() ? currentRoot
                    : (Map<String, Object>) navigate(currentRoot, pointer);
            } else {
                throw new IllegalArgumentException("unsupported $ref: " + ref);
            }
        }
        return new Resolved(current, currentRoot);
    }

    private static Object navigate(Object doc, String pointer) {
        Object node = doc;
        for (String part : pointer.split("/")) {
            if (part.isEmpty()) {
                continue;
            }
            node = ((Map<?, ?>) node).get(part);
        }
        return node;
    }

    @SuppressWarnings("unchecked")
    private static void check(Object value, Map<String, Object> schemaIn,
                              Map<String, Object> rootIn, String path,
                              List<String> errors) {
        Resolved resolved = resolve(schemaIn, rootIn);
        Map<String, Object> schema = resolved.schema;
        Map<String, Object> root = resolved.root;

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
                case "integer":
                    // Integral JSON tokens parse to Long (see Json.parse).
                    ok = value instanceof Long || value instanceof Integer;
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

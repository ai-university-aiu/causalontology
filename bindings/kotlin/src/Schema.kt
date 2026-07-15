// Schema validation against spec/schema/*.schema.json.
//
// A deliberately small interpreter for exactly the JSON Schema keywords the
// eight Causalontology schemas use: type, const, enum, pattern, required,
// properties, additionalProperties, items, minItems, minLength, minimum,
// maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
// annotation, as the 2020-12 draft does by default. Patterns are interpreted
// with kotlin.text.Regex (the four anchored pattern families the schemas use
// are plain regular expressions).
package org.causalontology

object Schema {

    val SCHEMA_FILES: Map<String, String> = mapOf(
        "causal_relation_object" to "cro.schema.json",
        "occurrent" to "occurrent.schema.json",
        "continuant" to "continuant.schema.json",
        "realizable" to "realizable.schema.json",
        "assertion" to "assertion.schema.json",
        "enrichment" to "enrichment.schema.json",
        "retraction" to "retraction.schema.json",
        "succession" to "succession.schema.json"
    )

    private val cache = HashMap<String, JObj>()

    // The repository root: CAUSALONTOLOGY_ROOT when set, else the working
    // directory (the conformance script runs from the repository root).
    fun repoRoot(): String = getEnvVar("CAUSALONTOLOGY_ROOT") ?: "."

    // The schema directory: $CAUSALONTOLOGY_SPEC/schema when set, else
    // <root>/spec/schema (mirrors schema.py's _schema_dir).
    private fun schemaDir(): String {
        val env = getEnvVar("CAUSALONTOLOGY_SPEC")
        if (env != null && env.isNotEmpty()) return "$env/schema"
        return repoRoot() + "/spec/schema"
    }

    fun loadSchema(kind: String): JObj {
        val file = SCHEMA_FILES[kind]
            ?: throw IllegalArgumentException("unknown kind: $kind")
        return cache.getOrPut(kind) {
            asObj(Json.parse(readFile(schemaDir() + "/" + file)))
        }
    }

    // Follow local $ref chains (#/$defs/...) to the referenced subschema.
    private fun resolve(schemaIn: JObj, root: JObj): JObj {
        var schema = schemaIn
        while (schema.containsKey("\$ref")) {
            val ref = schema["\$ref"] as String
            if (!ref.startsWith("#/")) {
                throw IllegalArgumentException("only local \$ref supported: $ref")
            }
            var node: Any? = root
            for (part in ref.substring(2).split("/")) {
                node = asObj(node)[part]
            }
            schema = asObj(node)
        }
        return schema
    }

    private fun typeMatches(t: String, value: Any?): Boolean = when (t) {
        "object" -> value is Map<*, *>
        "array" -> value is List<*>
        "string" -> value is String
        "number" -> (value is Long || value is Double) && value !is Boolean
        "boolean" -> value is Boolean
        else -> throw IllegalArgumentException("unsupported schema type: $t")
    }

    private fun check(value: Any?, schemaIn: JObj, root: JObj, path: String,
                      errors: MutableList<String>) {
        val schema = resolve(schemaIn, root)

        if (schema.containsKey("oneOf")) {
            var passing = 0
            for (sub in asList(schema["oneOf"])) {
                val subErrs = mutableListOf<String>()
                check(value, asObj(sub), root, path, subErrs)
                if (subErrs.isEmpty()) passing++
            }
            if (passing != 1) {
                errors.add("$path: matches $passing of the oneOf branches (need exactly 1)")
            }
            return
        }

        val t = schema["type"] as? String
        if (t != null) {
            if (!typeMatches(t, value)) {
                errors.add("$path: expected $t")
                return
            }
        }

        if (schema.containsKey("const") && !deepEq(value, schema["const"])) {
            errors.add("$path: must equal ${reprValue(schema["const"])}")
        }
        if (schema.containsKey("enum") &&
            asList(schema["enum"]).none { deepEq(it, value) }) {
            errors.add("$path: ${reprValue(value)} not in enumeration")
        }
        if (schema.containsKey("pattern") && value is String) {
            val pattern = schema["pattern"] as String
            if (!Regex(pattern).containsMatchIn(value)) {
                errors.add("$path: ${reprValue(value)} does not match $pattern")
            }
        }
        if (schema.containsKey("minLength") && value is String) {
            if (value.length < (schema["minLength"] as Long)) {
                errors.add("$path: shorter than minLength")
            }
        }
        if (schema.containsKey("minimum") && (value is Long || value is Double)) {
            if (asDoubleNum(value) < asDoubleNum(schema["minimum"])) {
                errors.add("$path: below minimum ${plainNum(schema["minimum"])}")
            }
        }
        if (schema.containsKey("maximum") && (value is Long || value is Double)) {
            if (asDoubleNum(value) > asDoubleNum(schema["maximum"])) {
                errors.add("$path: above maximum ${plainNum(schema["maximum"])}")
            }
        }

        if (value is List<*>) {
            val minItems = schema["minItems"] as? Long
            if (minItems != null && value.size < minItems) {
                errors.add("$path: fewer than $minItems items")
            }
            if (schema.containsKey("items")) {
                for ((i, item) in value.withIndex()) {
                    check(item, asObj(schema["items"]), root, "$path[$i]", errors)
                }
            }
        }

        if (value is Map<*, *>) {
            val obj = asObj(value)
            val props = (schema["properties"] as? Map<*, *>)?.let { asObj(it) } ?: emptyMap()
            for (req in (schema["required"] as? List<*>) ?: emptyList<Any?>()) {
                if (!obj.containsKey(req as String)) {
                    errors.add("$path: required property '$req' missing")
                }
            }
            if (schema["additionalProperties"] == false) {
                for (key in obj.keys) {
                    if (!props.containsKey(key)) {
                        errors.add("$path: additional property '$key'")
                    }
                }
            }
            for ((key, sub) in props) {
                if (obj.containsKey(key)) {
                    check(obj[key], asObj(sub), root, "$path.$key", errors)
                }
            }
        }
    }

    // A repr-like rendering for error messages (strings quoted, numbers plain).
    private fun reprValue(v: Any?): String = when (v) {
        null -> "None"
        is String -> "'" + v + "'"
        is Boolean -> if (v) "True" else "False"
        else -> v.toString()
    }

    private fun plainNum(v: Any?): String = when (v) {
        is Long -> v.toString()
        is Double -> Jcs.serialize(v)
        else -> v.toString()
    }

    // (ok, reasons) - structural validity against the kind's JSON Schema.
    fun validateSchema(obj: JObj, kind: String? = null): Pair<Boolean, List<String>> {
        val k = kind ?: Canonical.inferKind(obj)
        val root = loadSchema(k)
        val errors = mutableListOf<String>()
        check(obj, root, root, "$", errors)
        return Pair(errors.isEmpty(), errors)
    }
}

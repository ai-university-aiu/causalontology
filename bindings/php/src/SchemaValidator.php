<?php

/* Schema validation against spec/schema/*.schema.json.
 *
 * A deliberately small interpreter for exactly the JSON Schema keywords the
 * eight Causalontology schemas use: type, const, enum, pattern, required,
 * properties, additionalProperties, items, minItems, minLength, minimum,
 * maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
 * annotation, as the 2020-12 draft does by default.
 */

declare(strict_types=1);

namespace Causalontology;

final class SchemaValidator
{
    /** The schema file per kind, under spec/schema/. */
    public const SCHEMA_FILES = [
        'causal_relation_object'        => 'cro.schema.json',
        'occurrent'  => 'occurrent.schema.json',
        'continuant' => 'continuant.schema.json',
        'realizable' => 'realizable.schema.json',
        'assertion'  => 'assertion.schema.json',
        'enrichment' => 'enrichment.schema.json',
        'retraction' => 'retraction.schema.json',
        'succession' => 'succession.schema.json',
    ];

    /** @var array<string, array> loaded schemas, one per kind */
    private static array $cache = [];

    /** A static utility class, never an instance. */
    private function __construct()
    {
    }

    /** The spec/schema directory: env override, else the repository's. */
    private static function schemaDir(): string
    {
        $env = getenv('CAUSALONTOLOGY_SPEC');
        if (is_string($env) && $env !== '') {
            return $env . '/schema';
        }
        // src/SchemaValidator.php -> bindings/php/src, three levels below root.
        return dirname(__DIR__, 3) . '/spec/schema';
    }

    /** Load (and cache) the JSON Schema for a kind. */
    public static function loadSchema(string $kind): array
    {
        if (!isset(self::SCHEMA_FILES[$kind])) {
            throw new \InvalidArgumentException('unknown kind: ' . var_export($kind, true));
        }
        if (!isset(self::$cache[$kind])) {
            $file = self::schemaDir() . '/' . self::SCHEMA_FILES[$kind];
            $raw = @file_get_contents($file);
            if ($raw === false) {
                throw new \RuntimeException('cannot read schema file: ' . $file);
            }
            self::$cache[$kind] = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        }
        return self::$cache[$kind];
    }

    /**
     * [ok, reasons] - structural validity against the kind's JSON Schema.
     *
     * @return array{0: bool, 1: list<string>}
     */
    public static function validateSchema(array $obj, ?string $kind = null): array
    {
        $kind ??= Canonical::inferKind($obj);
        $root = self::loadSchema($kind);
        $errors = [];
        self::check($obj, $root, $root, '$', $errors);
        return [$errors === [], $errors];
    }

    /** Follow local $ref chains (#/$defs/...) to the referenced schema. */
    private static function resolveRef(array $schema, array $root): array
    {
        while (array_key_exists('$ref', $schema)) {
            $ref = $schema['$ref'];
            if (!str_starts_with($ref, '#/')) {
                throw new \InvalidArgumentException('only local $ref supported: ' . $ref);
            }
            $node = $root;
            foreach (explode('/', substr($ref, 2)) as $part) {
                $node = $node[$part];
            }
            $schema = $node;
        }
        return $schema;
    }

    /** Does the value match a JSON Schema primitive type name? */
    private static function typeMatches(mixed $value, string $type): bool
    {
        return match ($type) {
            // An empty decoded array counts as a list, never a map - see the
            // representational note in Jcs.php (our data has no empty object).
            'object'  => Jcs::isMap($value),
            'array'   => Jcs::isList($value),
            'string'  => is_string($value),
            // PHP booleans are a distinct type, so no bool-as-number leak.
            'number'  => is_int($value) || is_float($value),
            'boolean' => is_bool($value),
            default   => throw new \InvalidArgumentException('unsupported schema type: ' . $type),
        };
    }

    /** Recursive keyword interpreter; appends messages to $errors. */
    private static function check(mixed $value, array $schema, array $root,
                                  string $path, array &$errors): void
    {
        $schema = self::resolveRef($schema, $root);

        if (array_key_exists('oneOf', $schema)) {
            $passing = 0;
            foreach ($schema['oneOf'] as $subSchema) {
                $subErrors = [];
                self::check($value, $subSchema, $root, $path, $subErrors);
                if ($subErrors === []) {
                    $passing++;
                }
            }
            if ($passing !== 1) {
                $errors[] = sprintf('%s: matches %d of the oneOf branches (need exactly 1)',
                                    $path, $passing);
            }
            return;
        }

        if (array_key_exists('type', $schema)) {
            if (!self::typeMatches($value, $schema['type'])) {
                $errors[] = $path . ': expected ' . $schema['type'];
                return;
            }
        }

        if (array_key_exists('const', $schema) && !Jcs::equal($value, $schema['const'])) {
            $errors[] = $path . ': must equal ' . json_encode($schema['const']);
        }
        if (array_key_exists('enum', $schema)) {
            $found = false;
            foreach ($schema['enum'] as $candidate) {
                if (Jcs::equal($value, $candidate)) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $errors[] = $path . ': ' . json_encode($value) . ' not in enumeration';
            }
        }
        if (array_key_exists('pattern', $schema) && is_string($value)) {
            // re.search semantics: an unanchored match; '~' never occurs in
            // the eight schemas' patterns, so it is a safe delimiter.
            if (preg_match('~' . $schema['pattern'] . '~', $value) !== 1) {
                $errors[] = $path . ': ' . json_encode($value)
                          . ' does not match ' . $schema['pattern'];
            }
        }
        if (array_key_exists('minLength', $schema) && is_string($value)) {
            // Byte length: equivalent to character length for the only
            // constraint the schemas carry (minLength 1).
            if (strlen($value) < $schema['minLength']) {
                $errors[] = $path . ': shorter than minLength';
            }
        }
        if (array_key_exists('minimum', $schema) && (is_int($value) || is_float($value))) {
            if ($value < $schema['minimum']) {
                $errors[] = $path . ': below minimum ' . $schema['minimum'];
            }
        }
        if (array_key_exists('maximum', $schema) && (is_int($value) || is_float($value))) {
            if ($value > $schema['maximum']) {
                $errors[] = $path . ': above maximum ' . $schema['maximum'];
            }
        }

        if (Jcs::isList($value)) {
            if (array_key_exists('minItems', $schema) && count($value) < $schema['minItems']) {
                $errors[] = sprintf('%s: fewer than %d items', $path, $schema['minItems']);
            }
            if (array_key_exists('items', $schema)) {
                foreach ($value as $index => $item) {
                    self::check($item, $schema['items'], $root,
                                $path . '[' . $index . ']', $errors);
                }
            }
        }

        if (Jcs::isMap($value)) {
            $properties = $schema['properties'] ?? [];
            foreach ($schema['required'] ?? [] as $required) {
                if (!array_key_exists($required, $value)) {
                    $errors[] = $path . ": required property '" . $required . "' missing";
                }
            }
            if (($schema['additionalProperties'] ?? null) === false) {
                foreach (array_keys($value) as $key) {
                    if (!array_key_exists((string) $key, $properties)) {
                        $errors[] = $path . ": additional property '" . $key . "'";
                    }
                }
            }
            foreach ($properties as $key => $subSchema) {
                if (array_key_exists($key, $value)) {
                    self::check($value[$key], $subSchema, $root,
                                $path . '.' . $key, $errors);
                }
            }
        }
    }
}

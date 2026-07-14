<?php

/* RFC 8785 (JSON Canonicalization Scheme) serialization.
 *
 * Sorted keys (byte order over the UTF-8 key bytes, which equals UTF-16
 * code-unit order for the ASCII keys Causalontology uses), minimal string
 * escaping, and ECMAScript-style canonical numbers (1.0 -> "1", 0.7 stays
 * "0.7", exponents as "1e-7" not "1e-07").
 *
 * PHP specifics, decided once and documented here:
 *
 * - json_decode(..., true) preserves the integer-versus-decimal source
 *   distinction (JSON "1" decodes to int, "1.0" to float), which is exactly
 *   what the canonical number rule needs.
 *
 * - json_decode(..., true) cannot distinguish an empty JSON object {} from
 *   an empty JSON array []. Causalontology data carries empty ARRAYS only
 *   (mechanism: [], context: []) and never an empty object, so an empty PHP
 *   array serializes as "[]" - correct for every conformance vector. This
 *   is the one representational compromise of the PHP binding.
 *
 * - Shortest-round-trip float printing relies on serialize_precision=-1
 *   (the PHP 8 default), pinned explicitly before the first float is
 *   serialized. As in the Python binding, full ECMAScript exponent
 *   formatting for extreme magnitudes is pinned at the 1.0.0 conformance
 *   freeze; the ranges the vectors exercise are exact.
 */

declare(strict_types=1);

namespace Causalontology;

final class Jcs
{
    /** The minimal two-character escapes of RFC 8785 section 3.2.2.2. */
    private const ESCAPES = [
        '"'    => '\\"',
        '\\'   => '\\\\',
        "\x08" => '\\b',
        "\t"   => '\\t',
        "\n"   => '\\n',
        "\x0c" => '\\f',
        "\r"   => '\\r',
    ];

    /** Pinned once so float printing is shortest-round-trip everywhere. */
    private static bool $precisionPinned = false;

    /** A static utility class, never an instance. */
    private function __construct()
    {
    }

    /** True iff the value is a PHP array acting as a JSON array (list). */
    public static function isList(mixed $value): bool
    {
        return is_array($value) && array_is_list($value);
    }

    /**
     * True iff the value is a PHP array acting as a JSON object (map).
     * An empty array counts as a list, per the header note above.
     */
    public static function isMap(mixed $value): bool
    {
        return is_array($value) && !array_is_list($value);
    }

    /** The RFC 8785 canonical serialization of a decoded JSON value. */
    public static function serialize(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            return self::number($value);
        }
        if (is_string($value)) {
            return self::string($value);
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                $parts = [];
                foreach ($value as $item) {
                    $parts[] = self::serialize($item);
                }
                return '[' . implode(',', $parts) . ']';
            }
            // A map: sort keys bytewise; cast keys to string because PHP
            // silently turns decoded keys like "0" into integers.
            $map = $value;
            uksort($map, static fn ($a, $b): int => strcmp((string) $a, (string) $b));
            $parts = [];
            foreach ($map as $key => $item) {
                $parts[] = self::string((string) $key) . ':' . self::serialize($item);
            }
            return '{' . implode(',', $parts) . '}';
        }
        throw new \InvalidArgumentException('cannot canonicalize ' . get_debug_type($value));
    }

    /** Structural equality via canonical serialization (values are JSON). */
    public static function equal(mixed $a, mixed $b): bool
    {
        try {
            return self::serialize($a) === self::serialize($b);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Canonical string form: minimal escapes, lowercase \u00xx controls. */
    private static function string(string $s): string
    {
        $out = '"';
        $length = strlen($s);
        // Byte-wise iteration is UTF-8-safe here: every byte of a multibyte
        // character is >= 0x80, so only ASCII bytes can match an escape.
        for ($i = 0; $i < $length; $i++) {
            $ch = $s[$i];
            if (isset(self::ESCAPES[$ch])) {
                $out .= self::ESCAPES[$ch];
            } elseif (ord($ch) < 0x20) {
                $out .= sprintf('\\u%04x', ord($ch));
            } else {
                $out .= $ch;
            }
        }
        return $out . '"';
    }

    /** Canonical number form for floats (ints serialize verbatim). */
    private static function number(float $f): string
    {
        if (!is_finite($f)) {
            throw new \InvalidArgumentException('NaN and Infinity are not permitted (RFC 8785)');
        }
        if ($f === 0.0) {
            return '0'; // covers -0.0 as well: PHP compares float values
        }
        if (floor($f) === $f && abs($f) < 1e21) {
            // Integer-valued in the ES6 plain-integer range: print without a
            // decimal point. sprintf('%.0f', ...) is exact for every double
            // (unlike number_format, which is not trusted above 2**53).
            return sprintf('%.0f', $f);
        }
        if (!self::$precisionPinned) {
            // The PHP 8 default already is -1 (shortest round-trip); pin it
            // so a stray php.ini cannot change identity hashing.
            ini_set('serialize_precision', '-1');
            self::$precisionPinned = true;
        }
        // json_encode honors serialize_precision=-1 and yields the shortest
        // decimal that round-trips, e.g. "0.7"; lowercase any exponent.
        $encoded = json_encode($f);
        if ($encoded === false) {
            throw new \InvalidArgumentException('cannot serialize float ' . var_export($f, true));
        }
        $r = strtolower($encoded);
        if (str_contains($r, 'e')) {
            // Normalize to the ES6 exponent shape: "1.0e-7" -> "1e-7",
            // "1.0e+21" -> "1e+21" (mantissa without a trailing ".0",
            // exponent without leading zeros, sign always present).
            [$mantissa, $exponent] = explode('e', $r, 2);
            if (str_contains($mantissa, '.')) {
                $mantissa = rtrim(rtrim($mantissa, '0'), '.');
            }
            $sign = str_starts_with($exponent, '-') ? '-' : '+';
            $digits = ltrim(ltrim($exponent, '+-'), '0');
            if ($digits === '') {
                $digits = '0';
            }
            $r = $mantissa . 'e' . $sign . $digits;
        }
        return $r;
    }
}

// RFC 8785 (JSON Canonicalization Scheme) serialization.
//
// Object keys are sorted with sort.Strings; for the ASCII keys the
// Causalontology schemas allow, byte order and the UTF-16 code-unit order
// RFC 8785 prescribes coincide. Strings use the minimal escape set. Numbers
// follow the ECMAScript Number-to-string rules: an integer source literal
// is emitted verbatim, and every floating value is rendered from its
// shortest round-trip decimal: printed as a plain integer when it is
// integral with magnitude below 1e21, in plain decimal notation down to
// 1e-4, and in normalized exponent form otherwise (e-7, not e-07; e+21
// keeps its plus sign). This mirrors _jcs_number in the Python binding's
// canonical.py; full ECMAScript exponent formatting for extreme
// magnitudes is pinned at the 1.0.0 conformance freeze, as there.
package causalontology

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// SerializeJCS renders one JSON value in its RFC 8785 canonical form.
func SerializeJCS(value any) (string, error) {
	var builder strings.Builder
	if err := appendJCS(&builder, value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

// JSONEqual reports semantic equality of two JSON values by comparing
// their canonical serializations, so 1 and 1.0 compare equal exactly as
// they do under Python's == on parsed JSON.
func JSONEqual(a, b any) bool {
	canonicalA, errA := SerializeJCS(a)
	canonicalB, errB := SerializeJCS(b)
	if errA != nil || errB != nil {
		return false
	}
	return canonicalA == canonicalB
}

// appendJCS writes the canonical form of one value onto the builder.
func appendJCS(builder *strings.Builder, value any) error {
	switch v := value.(type) {
	case nil:
		builder.WriteString("null")
	case bool:
		if v {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
	case string:
		builder.WriteString(jcsQuote(v))
	case json.Number, int, int64, float64:
		rendered, err := jcsNumber(v)
		if err != nil {
			return err
		}
		builder.WriteString(rendered)
	case []any:
		builder.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				builder.WriteByte(',')
			}
			if err := appendJCS(builder, item); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				builder.WriteByte(',')
			}
			builder.WriteString(jcsQuote(key))
			builder.WriteByte(':')
			if err := appendJCS(builder, v[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalize a value of type %T", value)
	}
	return nil
}

// jcsQuote renders a string with the RFC 8785 minimal escapes: the seven
// short escapes, \u00xx (lowercase) for the remaining control characters,
// and everything else verbatim.
func jcsQuote(text string) string {
	var builder strings.Builder
	builder.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\t':
			builder.WriteString(`\t`)
		case '\n':
			builder.WriteString(`\n`)
		case '\f':
			builder.WriteString(`\f`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&builder, `\u%04x`, r)
			} else {
				builder.WriteRune(r)
			}
		}
	}
	builder.WriteByte('"')
	return builder.String()
}

// jcsNumber renders any numeric value form canonically. An integer-source
// json.Number is emitted verbatim ("6" stays "6"); a decimal-source
// json.Number ("6.000") and every native float go through the ES6 float
// rules; native ints print in plain decimal.
func jcsNumber(value any) (string, error) {
	switch n := value.(type) {
	case json.Number:
		if IsIntegerNumber(n) {
			return n.String(), nil
		}
		f, err := n.Float64()
		if err != nil {
			return "", err
		}
		return jcsFloat(f)
	case int:
		return strconv.Itoa(n), nil
	case int64:
		return strconv.FormatInt(n, 10), nil
	case float64:
		return jcsFloat(n)
	}
	return "", fmt.Errorf("cannot canonicalize a number of type %T", value)
}

// jcsFloat renders a float64 from its shortest round-trip digits, exactly
// as the Python binding's _jcs_number does: an integral value below 1e21
// prints as a plain integer; decimal notation covers magnitudes down to
// 1e-4 (Python repr's threshold - every float at or above 1e16 is
// integral, so the two implementations agree everywhere); anything
// outside that range uses the normalized exponent form (e-7, not e-07;
// e+21 keeps its plus sign).
func jcsFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("NaN and Infinity are not permitted (RFC 8785)")
	}
	if f == 0 {
		// Both zeros serialize as "0" (ES6 String(-0) is "0").
		return "0", nil
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		// An integral value below 1e21 prints as its exact integer,
		// Python's str(int(n)); big.Float carries a float64 exactly, so
		// this stays exact beyond the int64 range too.
		integer, _ := big.NewFloat(f).Int(nil)
		return integer.String(), nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// The shortest round-trip decimal in exponent form: "d[.ddd]e±XX".
	shortest := strconv.FormatFloat(f, 'e', -1, 64)
	markerIndex := strings.IndexByte(shortest, 'e')
	mantissa := shortest[:markerIndex]
	exponent, err := strconv.Atoi(shortest[markerIndex+1:])
	if err != nil {
		return "", err
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	// k is the number of significant digits; n is the position of the
	// decimal point relative to the start of the digits (ES6 7.1.12.1).
	k := len(digits)
	n := exponent + 1
	switch {
	case k <= n && n <= 21:
		// Defensive only: integral values below 1e21 were already printed
		// exactly above, so no reachable value lands here.
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		// A decimal point inside the digits.
		return sign + digits[:n] + "." + digits[n:], nil
	case -3 <= n && n <= 0:
		// A small decimal: leading "0." and padding zeros, down to 1e-4
		// (the same threshold Python's repr uses).
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	default:
		// Exponent form with the normalized exponent: e-7, e+21.
		rendered := digits[:1]
		if k > 1 {
			rendered += "." + digits[1:]
		}
		exponentValue := n - 1
		exponentSign := "+"
		if exponentValue < 0 {
			exponentSign = "-"
			exponentValue = -exponentValue
		}
		return sign + rendered + "e" + exponentSign + strconv.Itoa(exponentValue), nil
	}
}

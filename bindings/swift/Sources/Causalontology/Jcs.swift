// Jcs.swift
//
// RFC 8785 (JSON Canonicalization Scheme) serialization.
//
// A faithful port of the Python binding's serializer for the value ranges
// Causalontology uses (integers, integer-valued floats, and short decimals);
// full ECMAScript exponent formatting for extreme magnitudes is pinned at
// the 1.0.0 conformance freeze, exactly as in the Python binding.

import Foundation

/// The canonical serialization of a JsonValue as a String.
public func jcsString(_ value: JsonValue) throws -> String {
    switch value {
    case .null:
        return "null"
    case let .bool(flag):
        return flag ? "true" : "false"
    case let .int(number):
        return String(number)
    case let .double(number):
        return try jcsNumber(number)
    case let .string(text):
        return jcsQuotedString(text)
    case let .array(items):
        var parts: [String] = []
        for item in items {
            parts.append(try jcsString(item))
        }
        return "[" + parts.joined(separator: ",") + "]"
    case let .object(members):
        // RFC 8785: member names sorted by their UTF-16 code units.
        let sortedKeys = members.keys.sorted(by: utf16LessThan)
        var parts: [String] = []
        for key in sortedKeys {
            let serializedValue = try jcsString(members[key]!)
            parts.append(jcsQuotedString(key) + ":" + serializedValue)
        }
        return "{" + parts.joined(separator: ",") + "}"
    }
}

/// The canonical serialization of a JsonValue as UTF-8 bytes.
public func jcsData(_ value: JsonValue) throws -> Data {
    return Data(try jcsString(value).utf8)
}

/// True when a sorts strictly before b by UTF-16 code units (RFC 8785).
func utf16LessThan(_ a: String, _ b: String) -> Bool {
    let aUnits = Array(a.utf16)
    let bUnits = Array(b.utf16)
    let shared = min(aUnits.count, bUnits.count)
    var i = 0
    while i < shared {
        if aUnits[i] != bUnits[i] {
            return aUnits[i] < bUnits[i]
        }
        i += 1
    }
    return aUnits.count < bUnits.count
}

/// The RFC 8785 string form: minimal escaping only.
func jcsQuotedString(_ text: String) -> String {
    var out = "\""
    for scalar in text.unicodeScalars {
        switch scalar.value {
        case 0x22:
            // The double quote.
            out += "\\\""
        case 0x5C:
            // The backslash.
            out += "\\\\"
        case 0x08:
            out += "\\b"
        case 0x09:
            out += "\\t"
        case 0x0A:
            out += "\\n"
        case 0x0C:
            out += "\\f"
        case 0x0D:
            out += "\\r"
        default:
            if scalar.value < 0x20 {
                // Other control characters as lowercase \u00xx.
                out += String(format: "\\u%04x", scalar.value)
            } else {
                out.append(Character(scalar))
            }
        }
    }
    out += "\""
    return out
}

/// The RFC 8785 number form for a floating value, mirroring the Python
/// binding's _jcs_number: integer-valued floats below 1e21 print with no
/// decimal point and no exponent; other values use the shortest round-trip
/// decimal with a normalized ECMAScript-style exponent.
func jcsNumber(_ number: Double) throws -> String {
    guard number.isFinite else {
        throw CausalontologyError("NaN and Infinity are not permitted (RFC 8785)")
    }
    // Covers both 0.0 and -0.0, which canonicalize to "0".
    if number == 0 {
        return "0"
    }
    if number.truncatingRemainder(dividingBy: 1) == 0 && abs(number) < 1e21 {
        // Integer-valued: print the integer digits. Every integer-valued
        // Double with magnitude below 2^63 is exactly representable here;
        // the (unused-in-practice) band up to 1e21 falls through below.
        if let integer = Int64(exactly: number) {
            return String(integer)
        }
    }
    // Swift's Double description is the shortest decimal that round-trips,
    // matching ECMAScript digits for this range.
    var text = "\(number)"
    if let eIndex = text.firstIndex(of: "e") {
        // Normalize the exponent: 1e-07 -> 1e-7; positive keeps '+'.
        let mantissa = String(text[text.startIndex..<eIndex])
        var exponent = String(text[text.index(after: eIndex)...])
        var sign = "+"
        if exponent.hasPrefix("-") {
            sign = "-"
            exponent.removeFirst()
        } else if exponent.hasPrefix("+") {
            exponent.removeFirst()
        }
        while exponent.count > 1 && exponent.hasPrefix("0") {
            exponent.removeFirst()
        }
        text = mantissa + "e" + sign + exponent
    }
    return text
}

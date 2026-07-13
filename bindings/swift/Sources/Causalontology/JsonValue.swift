// JsonValue.swift
//
// A lossless JSON value model for the Causalontology Swift binding.
//
// Foundation's JSONSerialization does not reliably preserve the distinction
// between the JSON literals 1 and 1.0, and identity in Causalontology is
// computed over RFC 8785 canonical bytes, where that distinction is erased
// by the canonical NUMBER serialization, not by the parser. To keep the
// pipeline honest end to end, this file provides a small recursive-descent
// JSON parser that keeps Int64 for integer literals (no '.', no 'e'/'E')
// and Double for everything else.

import Foundation

/// The error type used across the binding where the Python reference raises
/// ValueError or TypeError: a plain message, nothing more.
public struct CausalontologyError: Error, CustomStringConvertible {
    /// The human-readable reason.
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String {
        return message
    }
}

/// A JSON value that distinguishes integer literals from floating literals.
public enum JsonValue {
    case object([String: JsonValue])
    case array([JsonValue])
    case string(String)
    case int(Int64)
    case double(Double)
    case bool(Bool)
    case null
}

// MARK: - Accessors

extension JsonValue {
    /// The dictionary payload if this value is a JSON object, else nil.
    public var objectValue: [String: JsonValue]? {
        if case let .object(members) = self { return members }
        return nil
    }

    /// The array payload if this value is a JSON array, else nil.
    public var arrayValue: [JsonValue]? {
        if case let .array(items) = self { return items }
        return nil
    }

    /// The string payload if this value is a JSON string, else nil.
    public var stringValue: String? {
        if case let .string(text) = self { return text }
        return nil
    }

    /// The boolean payload if this value is a JSON boolean, else nil.
    public var boolValue: Bool? {
        if case let .bool(flag) = self { return flag }
        return nil
    }

    /// The integer payload if this value is an integer literal, else nil.
    public var intValue: Int64? {
        if case let .int(number) = self { return number }
        return nil
    }

    /// The numeric payload as Double for either an integer or a floating
    /// literal (never for booleans), else nil.
    public var numberValue: Double? {
        switch self {
        case let .int(number):
            return Double(number)
        case let .double(number):
            return number
        default:
            return nil
        }
    }

    /// True when this value is the JSON null literal.
    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// Member lookup on a JSON object; nil for other value kinds.
    public subscript(key: String) -> JsonValue? {
        return objectValue?[key]
    }

    /// Element lookup on a JSON array; nil for other kinds or out of range.
    public subscript(index: Int) -> JsonValue? {
        guard let items = arrayValue else { return nil }
        guard index >= 0 && index < items.count else { return nil }
        return items[index]
    }
}

// MARK: - Equality

extension JsonValue: Equatable {
    /// Structural equality; an integer literal equals a floating literal of
    /// the same numeric value (as in Python, where 1 == 1.0), which is also
    /// exactly the RFC 8785 canonical view of the two.
    public static func == (lhs: JsonValue, rhs: JsonValue) -> Bool {
        switch (lhs, rhs) {
        case let (.object(a), .object(b)):
            return a == b
        case let (.array(a), .array(b)):
            return a == b
        case let (.string(a), .string(b)):
            return a == b
        case let (.bool(a), .bool(b)):
            return a == b
        case (.null, .null):
            return true
        case let (.int(a), .int(b)):
            return a == b
        case let (.double(a), .double(b)):
            return a == b
        case let (.int(a), .double(b)), let (.double(b), .int(a)):
            return Double(a) == b
        default:
            return false
        }
    }
}

// MARK: - Parsing

extension JsonValue {
    /// Parse UTF-8 encoded JSON data into a JsonValue.
    public static func parse(_ data: Data) throws -> JsonValue {
        guard let text = String(data: data, encoding: .utf8) else {
            throw CausalontologyError("JSON input is not valid UTF-8")
        }
        return try parse(text)
    }

    /// Parse a JSON text into a JsonValue.
    public static func parse(_ text: String) throws -> JsonValue {
        var parser = JsonParser(text)
        let value = try parser.parseValue()
        parser.skipWhitespace()
        guard parser.isAtEnd else {
            throw CausalontologyError("trailing characters after JSON value")
        }
        return value
    }
}

/// A minimal, strict-enough recursive-descent JSON parser. The one property
/// that matters for conformance: integer literals stay Int64, floating
/// literals stay Double.
struct JsonParser {
    private let chars: [Character]
    private var pos: Int

    init(_ text: String) {
        self.chars = Array(text)
        self.pos = 0
    }

    var isAtEnd: Bool {
        return pos >= chars.count
    }

    mutating func skipWhitespace() {
        while pos < chars.count {
            let c = chars[pos]
            if c == " " || c == "\t" || c == "\n" || c == "\r" {
                pos += 1
            } else {
                break
            }
        }
    }

    private func peek() -> Character? {
        return pos < chars.count ? chars[pos] : nil
    }

    private mutating func expect(_ c: Character) throws {
        guard pos < chars.count, chars[pos] == c else {
            throw CausalontologyError("expected '\(c)' at position \(pos)")
        }
        pos += 1
    }

    mutating func parseValue() throws -> JsonValue {
        skipWhitespace()
        guard let c = peek() else {
            throw CausalontologyError("unexpected end of JSON input")
        }
        switch c {
        case "{":
            return try parseObject()
        case "[":
            return try parseArray()
        case "\"":
            return .string(try parseString())
        case "t":
            try parseLiteral("true")
            return .bool(true)
        case "f":
            try parseLiteral("false")
            return .bool(false)
        case "n":
            try parseLiteral("null")
            return .null
        default:
            return try parseNumber()
        }
    }

    private mutating func parseLiteral(_ literal: String) throws {
        for expected in literal {
            guard pos < chars.count, chars[pos] == expected else {
                throw CausalontologyError("invalid literal at position \(pos)")
            }
            pos += 1
        }
    }

    private mutating func parseObject() throws -> JsonValue {
        try expect("{")
        var members: [String: JsonValue] = [:]
        skipWhitespace()
        if peek() == "}" {
            pos += 1
            return .object(members)
        }
        while true {
            skipWhitespace()
            let key = try parseString()
            skipWhitespace()
            try expect(":")
            let value = try parseValue()
            members[key] = value
            skipWhitespace()
            guard let c = peek() else {
                throw CausalontologyError("unterminated JSON object")
            }
            if c == "," {
                pos += 1
                continue
            }
            if c == "}" {
                pos += 1
                return .object(members)
            }
            throw CausalontologyError("expected ',' or '}' at position \(pos)")
        }
    }

    private mutating func parseArray() throws -> JsonValue {
        try expect("[")
        var items: [JsonValue] = []
        skipWhitespace()
        if peek() == "]" {
            pos += 1
            return .array(items)
        }
        while true {
            let value = try parseValue()
            items.append(value)
            skipWhitespace()
            guard let c = peek() else {
                throw CausalontologyError("unterminated JSON array")
            }
            if c == "," {
                pos += 1
                continue
            }
            if c == "]" {
                pos += 1
                return .array(items)
            }
            throw CausalontologyError("expected ',' or ']' at position \(pos)")
        }
    }

    private mutating func parseString() throws -> String {
        guard peek() == "\"" else {
            throw CausalontologyError("expected string at position \(pos)")
        }
        pos += 1
        var out = ""
        while true {
            guard pos < chars.count else {
                throw CausalontologyError("unterminated JSON string")
            }
            let c = chars[pos]
            pos += 1
            if c == "\"" {
                return out
            }
            if c == "\\" {
                guard pos < chars.count else {
                    throw CausalontologyError("unterminated escape sequence")
                }
                let escape = chars[pos]
                pos += 1
                switch escape {
                case "\"":
                    out.append("\"")
                case "\\":
                    out.append("\\")
                case "/":
                    out.append("/")
                case "b":
                    out.append("\u{08}")
                case "f":
                    out.append("\u{0C}")
                case "n":
                    out.append("\n")
                case "r":
                    out.append("\r")
                case "t":
                    out.append("\t")
                case "u":
                    let unit = try parseHex4()
                    if unit >= 0xD800 && unit <= 0xDBFF {
                        // High surrogate: a low surrogate escape must follow.
                        guard pos + 1 < chars.count,
                              chars[pos] == "\\", chars[pos + 1] == "u" else {
                            throw CausalontologyError("lone high surrogate in JSON string")
                        }
                        pos += 2
                        let low = try parseHex4()
                        guard low >= 0xDC00 && low <= 0xDFFF else {
                            throw CausalontologyError("invalid low surrogate in JSON string")
                        }
                        let combined = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                        guard let scalar = Unicode.Scalar(combined) else {
                            throw CausalontologyError("invalid surrogate pair in JSON string")
                        }
                        out.append(Character(scalar))
                    } else if unit >= 0xDC00 && unit <= 0xDFFF {
                        throw CausalontologyError("lone low surrogate in JSON string")
                    } else {
                        guard let scalar = Unicode.Scalar(unit) else {
                            throw CausalontologyError("invalid \\u escape in JSON string")
                        }
                        out.append(Character(scalar))
                    }
                default:
                    throw CausalontologyError("invalid escape '\\\(escape)' in JSON string")
                }
            } else {
                out.append(c)
            }
        }
    }

    private mutating func parseHex4() throws -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            guard pos < chars.count, let digit = chars[pos].hexDigitValue else {
                throw CausalontologyError("invalid \\u escape in JSON string")
            }
            value = value * 16 + UInt32(digit)
            pos += 1
        }
        return value
    }

    private mutating func parseNumber() throws -> JsonValue {
        var text = ""
        var isDouble = false
        if peek() == "-" {
            text.append("-")
            pos += 1
        }
        var sawDigit = false
        while let c = peek(), c.isNumber, c.isASCII {
            text.append(c)
            pos += 1
            sawDigit = true
        }
        guard sawDigit else {
            throw CausalontologyError("invalid JSON number at position \(pos)")
        }
        if peek() == "." {
            isDouble = true
            text.append(".")
            pos += 1
            var sawFraction = false
            while let c = peek(), c.isNumber, c.isASCII {
                text.append(c)
                pos += 1
                sawFraction = true
            }
            guard sawFraction else {
                throw CausalontologyError("invalid JSON number: no digits after '.'")
            }
        }
        if peek() == "e" || peek() == "E" {
            isDouble = true
            text.append(chars[pos])
            pos += 1
            if peek() == "+" || peek() == "-" {
                text.append(chars[pos])
                pos += 1
            }
            var sawExponent = false
            while let c = peek(), c.isNumber, c.isASCII {
                text.append(c)
                pos += 1
                sawExponent = true
            }
            guard sawExponent else {
                throw CausalontologyError("invalid JSON number: no digits in exponent")
            }
        }
        if !isDouble, let integer = Int64(text) {
            return .int(integer)
        }
        guard let floating = Double(text) else {
            throw CausalontologyError("unparseable JSON number: \(text)")
        }
        return .double(floating)
    }
}

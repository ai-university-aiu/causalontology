# frozen_string_literal: false

# RFC 8785 (JSON Canonicalization Scheme) serialization.
#
# Sorted keys (code-point order), minimal string escaping, ECMAScript-style
# canonical numbers (1.0 -> "1", 0.7 stays "0.7", exponent "1e-7" not
# "1e-07"). The number serialization implements the RFC 8785 rules for the
# value ranges Causalontology uses (integers, integer-valued floats, and
# short decimals); full ECMAScript exponent formatting for extreme
# magnitudes is pinned at the 1.0.0 conformance freeze.
#
# Ruby specifics relied on here: JSON.parse keeps the integer-versus-decimal
# source distinction ("1" -> Integer, "1.0" -> Float), and Float#to_s prints
# the shortest round-trip decimal with the same decimal/exponent thresholds
# as Python's repr (1e16 and 1e-4), so only the exponent spelling needs
# normalizing ("1.0e-07" -> "1e-7").

module Causalontology
  module Jcs
    # The two-character escapes of RFC 8785 section 3.2.2.2.
    ESCAPES = {
      '"'  => '\"',
      "\\" => "\\\\",
      "\b" => "\\b",
      "\t" => "\\t",
      "\n" => "\\n",
      "\f" => "\\f",
      "\r" => "\\r",
    }.freeze

    module_function

    # A JSON string literal with minimal escaping: the seven two-character
    # escapes, \u00xx for remaining control characters, everything else
    # (including multibyte text) passed through as UTF-8.
    def string(s)
      parts = +'"'
      s.each_char do |ch|
        if ESCAPES.key?(ch)
          parts << ESCAPES[ch]
        elsif ch.ord < 0x20
          parts << format("\\u%04x", ch.ord)
        else
          parts << ch
        end
      end
      parts << '"'
      parts
    end

    # A canonical JSON number: integers verbatim; integer-valued floats
    # below 1e21 printed as integers; other floats in shortest round-trip
    # form with the exponent normalized to ES6 style ("1e-7", "1e+21").
    def number(n)
      return n.to_s if n.is_a?(Integer)
      raise ArgumentError, "NaN and Infinity are not permitted (RFC 8785)" unless n.finite?
      return "0" if n == 0
      return n.to_i.to_s if n == n.truncate && n.abs < 1e21
      r = n.to_s # shortest round-trip decimal
      if r.include?("e")
        mant, exp = r.split("e")
        mant = mant.sub(/\.0\z/, "") # Ruby prints "1.0e-07"; ES6 prints "1e-7"
        sign = exp.start_with?("-") ? "-" : "+"
        digits = exp.sub(/\A[+-]/, "").sub(/\A0+/, "")
        digits = "0" if digits.empty?
        r = mant + "e" + sign + digits
      end
      r
    end

    # The canonical serialization of a parsed JSON value (nil, true/false,
    # Integer, Float, String, Array, or Hash with String keys).
    def encode(value)
      case value
      when nil
        "null"
      when true
        "true"
      when false
        "false"
      when Integer, Float
        number(value)
      when String
        string(value)
      when Array
        "[" + value.map { |v| encode(v) }.join(",") + "]"
      when Hash
        items = value.keys.sort_by(&:codepoints)
        "{" + items.map { |k| string(k) + ":" + encode(value[k]) }.join(",") + "}"
      else
        raise TypeError, "cannot canonicalize #{value.class}"
      end
    end
  end
end

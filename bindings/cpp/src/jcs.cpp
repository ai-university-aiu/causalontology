// jcs.cpp - RFC 8785 serialization over the JValue variant.

#include "jcs.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <stdexcept>

namespace co {

std::string jcs_string(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\f': out += "\\f"; break;
            case '\r': out += "\\r"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    // UTF-8 is bytes: everything >= 0x20 passes through.
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
    return out;
}

namespace {

// The ECMAScript-style canonical form of a finite double (RFC 8785).
std::string jcs_double(double n) {
    if (!std::isfinite(n))
        throw std::runtime_error(
            "NaN and Infinity are not permitted (RFC 8785)");
    if (n == 0) return "0";  // covers -0.0 as well
    if (n == std::trunc(n) && std::fabs(n) < 1e21) {
        // An integral double below 1e21 prints as an exact integer; the
        // x86 long double's 64-bit mantissa holds every such value exactly.
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.0Lf", static_cast<long double>(n));
        return buf;
    }
    // Shortest round-trip decimal via std::to_chars, then the exponent is
    // normalized to the ES6 style (1e-07 -> 1e-7; e+NN keeps its plus).
    char buf[64];
    auto res = std::to_chars(buf, buf + sizeof buf, n);
    std::string r(buf, res.ptr);
    size_t e = r.find('e');
    if (e != std::string::npos) {
        std::string mant = r.substr(0, e);
        std::string exp = r.substr(e + 1);
        std::string sign = (!exp.empty() && exp[0] == '-') ? "-" : "+";
        size_t i = 0;
        while (i < exp.size() && (exp[i] == '+' || exp[i] == '-')) ++i;
        while (i < exp.size() && exp[i] == '0') ++i;
        std::string digits = exp.substr(i);
        if (digits.empty()) digits = "0";
        r = mant + "e" + sign + digits;
    }
    return r;
}

}  // namespace

std::string jcs(const JValue& value) {
    switch (value.type) {
        case JValue::Type::Null:
            return "null";
        case JValue::Type::Bool:
            return value.boolean ? "true" : "false";
        case JValue::Type::Int:
            return std::to_string(value.integer);
        case JValue::Type::Double:
            return jcs_double(value.real);
        case JValue::Type::String:
            return jcs_string(value.str);
        case JValue::Type::Array: {
            std::string out = "[";
            for (size_t i = 0; i < value.array.size(); ++i) {
                if (i) out += ",";
                out += jcs(value.array[i]);
            }
            out += "]";
            return out;
        }
        case JValue::Type::Object: {
            // RFC 8785 sorts keys by code point; UTF-8 byte order agrees.
            std::vector<std::pair<std::string, const JValue*>> items;
            items.reserve(value.object.size());
            for (const auto& kv : value.object)
                items.emplace_back(kv.first, &kv.second);
            std::sort(items.begin(), items.end(),
                      [](const auto& a, const auto& b) {
                          return a.first < b.first;
                      });
            std::string out = "{";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) out += ",";
                out += jcs_string(items[i].first) + ":" + jcs(*items[i].second);
            }
            out += "}";
            return out;
        }
    }
    throw std::runtime_error("jcs: unreachable value type");
}

}  // namespace co

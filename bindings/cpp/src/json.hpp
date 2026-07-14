// json.hpp - a shape-preserving JSON layer for causalontology-cpp.
//
// JValue is a small tagged variant over: null, bool, int64_t, double,
// std::string (UTF-8 bytes), array (std::vector<JValue>), and an ordered
// object (std::vector<std::pair<std::string, JValue>>) - the association
// vector preserves insertion order and sidesteps map-ordering questions.
//
// The recursive-descent parser tags numbers by their source literal: a
// numeric literal with no '.', 'e', or 'E' decodes to Int (int64_t), so
// the integer-versus-decimal distinction (1 versus 1.0) survives to the
// canonicalizer, exactly as the Python binding's json module does.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace co {

class JValue {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    int64_t integer = 0;
    double real = 0.0;
    std::string str;
    std::vector<JValue> array;
    std::vector<std::pair<std::string, JValue>> object;

    JValue() = default;

    static JValue makeNull() { return JValue(); }
    static JValue of(bool b) {
        JValue v; v.type = Type::Bool; v.boolean = b; return v;
    }
    static JValue of(int64_t i) {
        JValue v; v.type = Type::Int; v.integer = i; return v;
    }
    static JValue of(int i) { return of(static_cast<int64_t>(i)); }
    static JValue of(double d) {
        JValue v; v.type = Type::Double; v.real = d; return v;
    }
    static JValue of(const std::string& s) {
        JValue v; v.type = Type::String; v.str = s; return v;
    }
    static JValue of(const char* s) { return of(std::string(s)); }
    static JValue makeArray() {
        JValue v; v.type = Type::Array; return v;
    }
    static JValue makeObject() {
        JValue v; v.type = Type::Object; return v;
    }

    bool isNull() const { return type == Type::Null; }
    bool isBool() const { return type == Type::Bool; }
    bool isInt() const { return type == Type::Int; }
    bool isDouble() const { return type == Type::Double; }
    bool isNumber() const { return type == Type::Int || type == Type::Double; }
    bool isString() const { return type == Type::String; }
    bool isArray() const { return type == Type::Array; }
    bool isObject() const { return type == Type::Object; }

    // The numeric value as a double (Int or Double only).
    double asDouble() const {
        if (type == Type::Int) return static_cast<double>(integer);
        if (type == Type::Double) return real;
        throw std::runtime_error("JValue: not a number");
    }

    // ---- ordered-object helpers -----------------------------------------
    bool has(const std::string& key) const { return find(key) != nullptr; }

    const JValue* find(const std::string& key) const {
        for (const auto& kv : object)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
    JValue* find(const std::string& key) {
        for (auto& kv : object)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
    const JValue& at(const std::string& key) const {
        const JValue* v = find(key);
        if (!v) throw std::runtime_error("JValue: missing key '" + key + "'");
        return *v;
    }
    // Replace the value under key, or append (preserving insertion order).
    void set(const std::string& key, JValue v) {
        for (auto& kv : object)
            if (kv.first == key) { kv.second = std::move(v); return; }
        object.emplace_back(key, std::move(v));
    }
    // Insert only if the key is absent (Python dict.setdefault).
    void setDefault(const std::string& key, JValue v) {
        if (!has(key)) object.emplace_back(key, std::move(v));
    }
    void erase(const std::string& key) {
        for (size_t i = 0; i < object.size(); ++i)
            if (object[i].first == key) {
                object.erase(object.begin() + static_cast<long>(i));
                return;
            }
    }
    // The string under key, or "" when absent or not a string.
    std::string getString(const std::string& key) const {
        const JValue* v = find(key);
        return (v && v->isString()) ? v->str : std::string();
    }

    // Structural equality with Python semantics: numbers compare by value
    // across Int/Double, objects compare order-insensitively.
    bool equals(const JValue& o) const;
    bool operator==(const JValue& o) const { return equals(o); }
    bool operator!=(const JValue& o) const { return !equals(o); }
};

// Parse a complete JSON document; throws std::runtime_error on bad input.
JValue json_parse(const std::string& text);

}  // namespace co

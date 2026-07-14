// json.cpp - recursive-descent JSON parser and JValue equality.

#include "json.hpp"

#include <cstdlib>

namespace co {

bool JValue::equals(const JValue& o) const {
    // Numbers compare by value across the Int/Double boundary (Python: 1 == 1.0).
    if (isNumber() && o.isNumber()) {
        if (type == Type::Int && o.type == Type::Int)
            return integer == o.integer;
        return asDouble() == o.asDouble();
    }
    if (type != o.type) return false;
    switch (type) {
        case Type::Null: return true;
        case Type::Bool: return boolean == o.boolean;
        case Type::String: return str == o.str;
        case Type::Array: {
            if (array.size() != o.array.size()) return false;
            for (size_t i = 0; i < array.size(); ++i)
                if (!array[i].equals(o.array[i])) return false;
            return true;
        }
        case Type::Object: {
            // Order-insensitive, like Python dict equality.
            if (object.size() != o.object.size()) return false;
            for (const auto& kv : object) {
                const JValue* ov = o.find(kv.first);
                if (!ov || !kv.second.equals(*ov)) return false;
            }
            return true;
        }
        default: return false;  // unreachable (numbers handled above)
    }
}

namespace {

class Parser {
public:
    explicit Parser(const std::string& text) : s_(text), i_(0) {}

    JValue parseDocument() {
        JValue v = parseValue();
        skipWs();
        if (i_ != s_.size()) fail("trailing characters after JSON value");
        return v;
    }

private:
    const std::string& s_;
    size_t i_;

    [[noreturn]] void fail(const std::string& why) {
        throw std::runtime_error("JSON parse error at byte " +
                                 std::to_string(i_) + ": " + why);
    }

    void skipWs() {
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i_;
            else break;
        }
    }

    char peek() {
        if (i_ >= s_.size()) fail("unexpected end of input");
        return s_[i_];
    }

    void expect(char c) {
        if (peek() != c) fail(std::string("expected '") + c + "'");
        ++i_;
    }

    bool consumeLiteral(const char* lit) {
        size_t n = 0;
        while (lit[n]) ++n;
        if (s_.compare(i_, n, lit) == 0) { i_ += n; return true; }
        return false;
    }

    JValue parseValue() {
        skipWs();
        char c = peek();
        switch (c) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': return JValue::of(parseString());
            case 't':
                if (consumeLiteral("true")) return JValue::of(true);
                fail("bad literal");
            case 'f':
                if (consumeLiteral("false")) return JValue::of(false);
                fail("bad literal");
            case 'n':
                if (consumeLiteral("null")) return JValue::makeNull();
                fail("bad literal");
            default: return parseNumber();
        }
    }

    JValue parseObject() {
        expect('{');
        JValue v = JValue::makeObject();
        skipWs();
        if (peek() == '}') { ++i_; return v; }
        while (true) {
            skipWs();
            std::string key = parseString();
            skipWs();
            expect(':');
            v.object.emplace_back(key, parseValue());
            skipWs();
            char c = peek();
            if (c == ',') { ++i_; continue; }
            if (c == '}') { ++i_; break; }
            fail("expected ',' or '}' in object");
        }
        return v;
    }

    JValue parseArray() {
        expect('[');
        JValue v = JValue::makeArray();
        skipWs();
        if (peek() == ']') { ++i_; return v; }
        while (true) {
            v.array.push_back(parseValue());
            skipWs();
            char c = peek();
            if (c == ',') { ++i_; continue; }
            if (c == ']') { ++i_; break; }
            fail("expected ',' or ']' in array");
        }
        return v;
    }

    // Append a Unicode code point to out as UTF-8 bytes.
    static void appendUtf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    uint32_t parseHex4() {
        uint32_t v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = peek();
            ++i_;
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else fail("bad \\u escape");
        }
        return v;
    }

    std::string parseString() {
        expect('"');
        std::string out;
        while (true) {
            if (i_ >= s_.size()) fail("unterminated string");
            unsigned char c = static_cast<unsigned char>(s_[i_]);
            if (c == '"') { ++i_; break; }
            if (c == '\\') {
                ++i_;
                char e = peek();
                ++i_;
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp = parseHex4();
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            // A high surrogate must pair with \uDC00-\uDFFF.
                            if (i_ + 1 < s_.size() && s_[i_] == '\\' &&
                                s_[i_ + 1] == 'u') {
                                i_ += 2;
                                uint32_t lo = parseHex4();
                                if (lo >= 0xDC00 && lo <= 0xDFFF)
                                    cp = 0x10000 + ((cp - 0xD800) << 10) +
                                         (lo - 0xDC00);
                                else fail("unpaired surrogate");
                            } else fail("unpaired surrogate");
                        }
                        appendUtf8(out, cp);
                        break;
                    }
                    default: fail("bad escape character");
                }
                continue;
            }
            // Raw UTF-8 bytes pass through unchanged.
            out.push_back(static_cast<char>(c));
            ++i_;
        }
        return out;
    }

    JValue parseNumber() {
        size_t start = i_;
        if (peek() == '-') ++i_;
        while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') ++i_;
        bool decimal = false;
        if (i_ < s_.size() && s_[i_] == '.') {
            decimal = true;
            ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') ++i_;
        }
        if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            decimal = true;
            ++i_;
            if (i_ < s_.size() && (s_[i_] == '+' || s_[i_] == '-')) ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') ++i_;
        }
        if (i_ == start || (i_ == start + 1 && s_[start] == '-'))
            fail("bad number");
        std::string lit = s_.substr(start, i_ - start);
        // The literal decides the tag: no [.eE] means a JSON integer.
        if (!decimal) {
            errno = 0;
            char* end = nullptr;
            long long v = std::strtoll(lit.c_str(), &end, 10);
            if (errno == 0 && end && *end == '\0')
                return JValue::of(static_cast<int64_t>(v));
        }
        return JValue::of(std::strtod(lit.c_str(), nullptr));
    }
};

}  // namespace

JValue json_parse(const std::string& text) {
    return Parser(text).parseDocument();
}

}  // namespace co

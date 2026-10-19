// TypeMorph - small dependency-free JSON implementation.
//
// The CLI and the JSON-RPC bridge both speak JSON but the project must build in
// fully offline / air-gapped environments, so this file implements a strict
// RFC 8259 parser and a deterministic writer on top of the JsonValue contract.
// Object order is insertion order everywhere, which keeps emitted documents
// byte-for-byte stable across runs.

#include "typemorph/cli/json.hpp"

#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace typemorph::cli {
namespace {

// Bounds recursive descent (parser and writer) well below the default thread
// stack so hostile / accidentally deep documents can never overflow it.
constexpr int kMaxNestingDepth = 256;

[[nodiscard]] bool is_digit(char value) noexcept { return value >= '0' && value <= '9'; }

[[nodiscard]] int hex_value(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

void append_utf8(std::string& out, std::uint32_t code_point) {
    if (code_point <= 0x7FU) {
        out.push_back(static_cast<char>(code_point));
    } else if (code_point <= 0x7FFU) {
        out.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else if (code_point <= 0xFFFFU) {
        out.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else {
        out.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    }
}

[[nodiscard]] std::size_t utf8_sequence_length(unsigned char lead) noexcept {
    if ((lead & 0x80U) == 0) return 1;
    if ((lead & 0xE0U) == 0xC0U) return 2;
    if ((lead & 0xF0U) == 0xE0U) return 3;
    if ((lead & 0xF8U) == 0xF0U) return 4;
    return 0;  // Continuation byte or invalid leading byte.
}

// Validates one complete UTF-8 sequence, rejecting overlong encodings,
// surrogates and code points above U+10FFFF.
[[nodiscard]] bool valid_utf8_sequence(const char* data, std::size_t length) noexcept {
    if (length == 0 || length > 4) return false;
    const auto byte = [&](std::size_t index) {
        return static_cast<unsigned char>(data[index]);
    };
    for (std::size_t i = 1; i < length; ++i) {
        if ((byte(i) & 0xC0U) != 0x80U) return false;
    }
    std::uint32_t code_point = 0;
    switch (length) {
    case 1:
        return true;
    case 2:
        code_point = (static_cast<std::uint32_t>(byte(0) & 0x1FU) << 6U) |
                     static_cast<std::uint32_t>(byte(1) & 0x3FU);
        return code_point >= 0x80U;
    case 3:
        code_point = (static_cast<std::uint32_t>(byte(0) & 0x0FU) << 12U) |
                     (static_cast<std::uint32_t>(byte(1) & 0x3FU) << 6U) |
                     static_cast<std::uint32_t>(byte(2) & 0x3FU);
        if (code_point < 0x800U) return false;
        if (code_point >= 0xD800U && code_point <= 0xDFFFU) return false;
        return true;
    case 4:
        code_point = (static_cast<std::uint32_t>(byte(0) & 0x07U) << 18U) |
                     (static_cast<std::uint32_t>(byte(1) & 0x3FU) << 12U) |
                     (static_cast<std::uint32_t>(byte(2) & 0x3FU) << 6U) |
                     static_cast<std::uint32_t>(byte(3) & 0x3FU);
        return code_point >= 0x10000U && code_point <= 0x10FFFFU;
    default:
        return false;
    }
}

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    [[nodiscard]] core::Result<JsonValue> parse() {
        skip_byte_order_mark();
        skip_whitespace();
        auto value = parse_value(0);
        if (!value) return value.error();
        skip_whitespace();
        if (position_ != text_.size()) {
            return error("unexpected trailing characters after JSON value");
        }
        return value;
    }

private:
    [[nodiscard]] core::Error error(std::string message) const {
        return core::make_error(core::ErrorCode::parse_error, std::move(message),
                                "offset=" + std::to_string(position_));
    }

    void skip_whitespace() noexcept {
        while (position_ < text_.size()) {
            const char current = text_[position_];
            if (current == ' ' || current == '\t' || current == '\n' || current == '\r') {
                ++position_;
            } else {
                break;
            }
        }
    }

    void skip_byte_order_mark() noexcept {
        if (text_.size() >= 3 && static_cast<unsigned char>(text_[0]) == 0xEFU &&
            static_cast<unsigned char>(text_[1]) == 0xBBU &&
            static_cast<unsigned char>(text_[2]) == 0xBFU) {
            position_ = 3;
        }
    }

    [[nodiscard]] core::Result<JsonValue> parse_value(int depth) {
        if (depth > kMaxNestingDepth) return error("maximum JSON nesting depth exceeded");
        if (position_ >= text_.size()) return error("unexpected end of input");
        const char current = text_[position_];
        switch (current) {
        case '{': return parse_object(depth);
        case '[': return parse_array(depth);
        case '"': {
            auto string = parse_string();
            if (!string) return string.error();
            return JsonValue(std::move(string).value());
        }
        case 't': return parse_literal("true", JsonValue(true));
        case 'f': return parse_literal("false", JsonValue(false));
        case 'n': return parse_literal("null", JsonValue(nullptr));
        default:
            if (current == '-' || is_digit(current)) return parse_number();
            return error("unexpected character while parsing a JSON value");
        }
    }

    [[nodiscard]] core::Result<JsonValue> parse_literal(std::string_view literal,
                                                        JsonValue value) {
        if (text_.substr(position_, literal.size()) != literal) {
            return error("invalid JSON literal");
        }
        position_ += literal.size();
        return value;
    }

    [[nodiscard]] core::Result<std::uint32_t> parse_hex4() {
        if (position_ + 4 > text_.size()) return error("truncated \\u escape");
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            const int digit = hex_value(text_[position_ + static_cast<std::size_t>(i)]);
            if (digit < 0) return error("invalid hexadecimal digit in \\u escape");
            value = (value << 4U) | static_cast<std::uint32_t>(digit);
        }
        position_ += 4;
        return value;
    }

    [[nodiscard]] core::Result<void> parse_escape(std::string& out) {
        if (position_ >= text_.size()) return error("unterminated escape sequence");
        const char escaped = text_[position_++];
        switch (escaped) {
        case '"': out.push_back('"'); return {};
        case '\\': out.push_back('\\'); return {};
        case '/': out.push_back('/'); return {};
        case 'b': out.push_back('\b'); return {};
        case 'f': out.push_back('\f'); return {};
        case 'n': out.push_back('\n'); return {};
        case 'r': out.push_back('\r'); return {};
        case 't': out.push_back('\t'); return {};
        case 'u': {
            auto first = parse_hex4();
            if (!first) return first.error();
            std::uint32_t code_point = first.value();
            if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
                if (position_ + 6 > text_.size() || text_[position_] != '\\' ||
                    text_[position_ + 1] != 'u') {
                    return error("unpaired high surrogate in \\u escape");
                }
                position_ += 2;
                auto second = parse_hex4();
                if (!second) return second.error();
                const std::uint32_t low = second.value();
                if (low < 0xDC00U || low > 0xDFFFU) {
                    return error("invalid low surrogate in \\u escape");
                }
                code_point = 0x10000U + ((code_point - 0xD800U) << 10U) + (low - 0xDC00U);
            } else if (code_point >= 0xDC00U && code_point <= 0xDFFFU) {
                return error("unpaired low surrogate in \\u escape");
            }
            append_utf8(out, code_point);
            return {};
        }
        default:
            return error("invalid escape sequence in JSON string");
        }
    }

    [[nodiscard]] core::Result<std::string> parse_string() {
        if (position_ >= text_.size() || text_[position_] != '"') {
            return error("expected a JSON string");
        }
        ++position_;
        std::string out;
        while (true) {
            if (position_ >= text_.size()) return error("unterminated JSON string");
            const unsigned char current = static_cast<unsigned char>(text_[position_]);
            if (current == '"') {
                ++position_;
                return out;
            }
            if (current == '\\') {
                ++position_;
                auto escaped = parse_escape(out);
                if (!escaped) return escaped.error();
                continue;
            }
            if (current < 0x20U) {
                return error("unescaped control character in JSON string");
            }
            if (current < 0x80U) {
                out.push_back(static_cast<char>(current));
                ++position_;
                continue;
            }
            const std::size_t length = utf8_sequence_length(current);
            if (length == 0 || position_ + length > text_.size() ||
                !valid_utf8_sequence(text_.data() + position_, length)) {
                return error("invalid UTF-8 sequence in JSON string");
            }
            out.append(text_.data() + position_, length);
            position_ += length;
        }
    }

    [[nodiscard]] core::Result<JsonValue> parse_number() {
        const std::size_t start = position_;
        bool floating = false;

        if (text_[position_] == '-') ++position_;
        if (position_ >= text_.size()) return error("truncated JSON number");
        if (text_[position_] == '0') {
            ++position_;
            if (position_ < text_.size() && is_digit(text_[position_])) {
                return error("leading zeros are not allowed in JSON numbers");
            }
        } else if (is_digit(text_[position_])) {
            while (position_ < text_.size() && is_digit(text_[position_])) ++position_;
        } else {
            return error("invalid JSON number");
        }

        if (position_ < text_.size() && text_[position_] == '.') {
            floating = true;
            ++position_;
            if (position_ >= text_.size() || !is_digit(text_[position_])) {
                return error("missing fraction digits in JSON number");
            }
            while (position_ < text_.size() && is_digit(text_[position_])) ++position_;
        }

        if (position_ < text_.size() &&
            (text_[position_] == 'e' || text_[position_] == 'E')) {
            floating = true;
            ++position_;
            if (position_ < text_.size() &&
                (text_[position_] == '+' || text_[position_] == '-')) {
                ++position_;
            }
            if (position_ >= text_.size() || !is_digit(text_[position_])) {
                return error("missing exponent digits in JSON number");
            }
            while (position_ < text_.size() && is_digit(text_[position_])) ++position_;
        }

        const std::string_view token = text_.substr(start, position_ - start);
        if (!floating) {
            std::int64_t integer = 0;
            const auto result =
                std::from_chars(token.data(), token.data() + token.size(), integer);
            if (result.ec == std::errc() && result.ptr == token.data() + token.size()) {
                return JsonValue(integer);
            }
            // Large integers fall through to double (matching common JSON
            // tooling); the value is still accepted rather than rejected.
        }
        double number = 0.0;
        const auto result = std::from_chars(token.data(), token.data() + token.size(),
                                            number, std::chars_format::general);
        if (result.ec == std::errc::result_out_of_range) {
            return error("JSON number is out of range");
        }
        if (result.ec != std::errc() || result.ptr != token.data() + token.size()) {
            return error("invalid JSON number");
        }
        return JsonValue(number);
    }

    [[nodiscard]] core::Result<JsonValue> parse_object(int depth) {
        ++position_;  // Consume '{'.
        JsonValue object = JsonValue::object();
        skip_whitespace();
        if (position_ < text_.size() && text_[position_] == '}') {
            ++position_;
            return object;
        }
        while (true) {
            skip_whitespace();
            if (position_ >= text_.size()) return error("unterminated JSON object");
            if (text_[position_] != '"') return error("expected a JSON object key");
            auto key = parse_string();
            if (!key) return key.error();
            const std::string key_text = std::move(key).value();
            skip_whitespace();
            if (position_ >= text_.size() || text_[position_] != ':') {
                return error("expected ':' after JSON object key");
            }
            ++position_;
            skip_whitespace();
            auto value = parse_value(depth + 1);
            if (!value) return value.error();
            if (object.contains(key_text)) {
                return error("duplicate JSON object key");
            }
            object[key_text] = std::move(value).value();
            skip_whitespace();
            if (position_ >= text_.size()) return error("unterminated JSON object");
            if (text_[position_] == ',') {
                ++position_;
                continue;
            }
            if (text_[position_] == '}') {
                ++position_;
                return object;
            }
            return error("expected ',' or '}' in JSON object");
        }
    }

    [[nodiscard]] core::Result<JsonValue> parse_array(int depth) {
        ++position_;  // Consume '['.
        JsonValue array = JsonValue::array();
        skip_whitespace();
        if (position_ < text_.size() && text_[position_] == ']') {
            ++position_;
            return array;
        }
        while (true) {
            skip_whitespace();
            auto value = parse_value(depth + 1);
            if (!value) return value.error();
            array.push(std::move(value).value());
            skip_whitespace();
            if (position_ >= text_.size()) return error("unterminated JSON array");
            if (text_[position_] == ',') {
                ++position_;
                continue;
            }
            if (text_[position_] == ']') {
                ++position_;
                return array;
            }
            return error("expected ',' or ']' in JSON array");
        }
    }

    std::string_view text_;
    std::size_t position_ = 0;
};

// ---------------------------------------------------------------------------
// Writer helpers
// ---------------------------------------------------------------------------

void append_integer(std::string& out, std::int64_t value) {
    char buffer[32];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    out.append(buffer, static_cast<std::size_t>(result.ptr - buffer));
}

void append_double(std::string& out, double value) {
    if (!std::isfinite(value)) {
        // JSON has no representation for infinities / NaN; null keeps the
        // document valid and deterministic.
        out += "null";
        return;
    }
    char buffer[64];
    const auto result =
        std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::general);
    if (result.ec != std::errc()) {
        out += "null";
        return;
    }
    const std::string_view text(buffer, static_cast<std::size_t>(result.ptr - buffer));
    out += text;
    if (text.find_first_of(".eE") == std::string_view::npos) {
        // Preserve the distinction between the integer and number kinds when a
        // double happens to have an integral value.
        out += ".0";
    }
}

void dump_value(const JsonValue& value, std::string& out, int indent, int level);

void dump_indentation(std::string& out, int indent, int level) {
    out.append(static_cast<std::size_t>(indent) * static_cast<std::size_t>(level), ' ');
}

void dump_array(const JsonValue& value, std::string& out, int indent, int level) {
    const auto* array = value.as_array();
    if (array == nullptr || array->empty()) {
        out += "[]";
        return;
    }
    if (indent <= 0) {
        out.push_back('[');
        for (std::size_t i = 0; i < array->size(); ++i) {
            if (i != 0) out.push_back(',');
            dump_value((*array)[i], out, indent, level + 1);
        }
        out.push_back(']');
        return;
    }
    out += "[\n";
    for (std::size_t i = 0; i < array->size(); ++i) {
        dump_indentation(out, indent, level + 1);
        dump_value((*array)[i], out, indent, level + 1);
        out += (i + 1 == array->size()) ? "\n" : ",\n";
    }
    dump_indentation(out, indent, level);
    out.push_back(']');
}

void dump_object(const JsonValue& value, std::string& out, int indent, int level) {
    const auto* object = value.as_object();
    if (object == nullptr || object->empty()) {
        out += "{}";
        return;
    }
    if (indent <= 0) {
        out.push_back('{');
        for (std::size_t i = 0; i < object->size(); ++i) {
            if (i != 0) out.push_back(',');
            out.push_back('"');
            out += json_escape((*object)[i].first);
            out += "\":";
            dump_value((*object)[i].second, out, indent, level + 1);
        }
        out.push_back('}');
        return;
    }
    out += "{\n";
    for (std::size_t i = 0; i < object->size(); ++i) {
        dump_indentation(out, indent, level + 1);
        out.push_back('"');
        out += json_escape((*object)[i].first);
        out += "\": ";
        dump_value((*object)[i].second, out, indent, level + 1);
        out += (i + 1 == object->size()) ? "\n" : ",\n";
    }
    dump_indentation(out, indent, level);
    out.push_back('}');
}

void dump_value(const JsonValue& value, std::string& out, int indent, int level) {
    if (level > kMaxNestingDepth) {
        // The public JsonValue API can be used to build arbitrarily deep values;
        // refuse to recurse past the same limit the parser uses.
        out += "null";
        return;
    }
    switch (value.kind()) {
    case JsonValue::Kind::null:
        out += "null";
        return;
    case JsonValue::Kind::boolean: {
        const auto flag = value.as_bool();
        out += (flag.value_or(false) ? "true" : "false");
        return;
    }
    case JsonValue::Kind::integer: {
        append_integer(out, value.as_int().value_or(0));
        return;
    }
    case JsonValue::Kind::number: {
        append_double(out, value.as_double().value_or(0.0));
        return;
    }
    case JsonValue::Kind::string: {
        const auto* text = value.as_string();
        out.push_back('"');
        if (text != nullptr) out += json_escape(*text);
        out.push_back('"');
        return;
    }
    case JsonValue::Kind::array:
        dump_array(value, out, indent, level);
        return;
    case JsonValue::Kind::object:
        dump_object(value, out, indent, level);
        return;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// JsonValue
// ---------------------------------------------------------------------------

JsonValue::JsonValue(std::uint64_t value) {
    if (value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        storage_ = static_cast<std::int64_t>(value);
    } else {
        // Values above INT64_MAX cannot be represented exactly as integers;
        // 64-bit floats are the closest lossless kind available in the model.
        storage_ = static_cast<double>(value);
    }
}

JsonValue::JsonValue(std::initializer_list<std::pair<std::string, JsonValue>> values)
    : storage_(Object(values.begin(), values.end())) {}

JsonValue JsonValue::array() {
    JsonValue value;
    value.storage_ = Array{};
    return value;
}

JsonValue JsonValue::object() {
    JsonValue value;
    value.storage_ = Object{};
    return value;
}

JsonValue JsonValue::null() { return JsonValue(nullptr); }

JsonValue::Kind JsonValue::kind() const noexcept {
    switch (storage_.index()) {
    case 0: return Kind::null;
    case 1: return Kind::boolean;
    case 2: return Kind::integer;
    case 3: return Kind::number;
    case 4: return Kind::string;
    case 5: return Kind::array;
    case 6: return Kind::object;
    default: return Kind::null;
    }
}

bool JsonValue::is_number() const noexcept {
    return kind() == Kind::integer || kind() == Kind::number;
}

std::optional<bool> JsonValue::as_bool() const {
    if (const auto* value = std::get_if<bool>(&storage_)) return *value;
    return std::nullopt;
}

std::optional<std::int64_t> JsonValue::as_int() const {
    if (const auto* value = std::get_if<std::int64_t>(&storage_)) return *value;
    if (const auto* value = std::get_if<double>(&storage_)) {
        if (!std::isfinite(*value)) return std::nullopt;
        if (*value < -9223372036854775808.0 || *value >= 9223372036854775808.0) {
            return std::nullopt;
        }
        const double integral = std::trunc(*value);
        if (integral != *value) return std::nullopt;
        return static_cast<std::int64_t>(*value);
    }
    return std::nullopt;
}

std::optional<double> JsonValue::as_double() const {
    if (const auto* value = std::get_if<double>(&storage_)) return *value;
    if (const auto* value = std::get_if<std::int64_t>(&storage_)) {
        return static_cast<double>(*value);
    }
    return std::nullopt;
}

const std::string* JsonValue::as_string() const {
    return std::get_if<std::string>(&storage_);
}

const JsonValue::Array* JsonValue::as_array() const {
    return std::get_if<Array>(&storage_);
}

const JsonValue::Object* JsonValue::as_object() const {
    return std::get_if<Object>(&storage_);
}

bool JsonValue::contains(std::string_view key) const { return find(key) != nullptr; }

const JsonValue* JsonValue::find(std::string_view key) const {
    const auto* object = as_object();
    if (object == nullptr) return nullptr;
    for (const auto& entry : *object) {
        if (entry.first == key) return &entry.second;
    }
    return nullptr;
}

const JsonValue& JsonValue::at(std::string_view key) const {
    const JsonValue* value = find(key);
    if (value == nullptr) {
        throw std::out_of_range("JsonValue::at: key not found: " + std::string(key));
    }
    return *value;
}

JsonValue& JsonValue::operator[](std::string key) {
    if (!is_object()) storage_ = Object{};
    auto* object = std::get_if<Object>(&storage_);
    for (auto& entry : *object) {
        if (entry.first == key) return entry.second;
    }
    object->emplace_back(std::move(key), JsonValue{});
    return object->back().second;
}

JsonValue& JsonValue::push(JsonValue value) {
    if (!is_array()) storage_ = Array{};
    auto* array = std::get_if<Array>(&storage_);
    array->push_back(std::move(value));
    return array->back();
}

std::string JsonValue::dump(int indent) const {
    std::string out;
    out.reserve(64);
    dump_value(*this, out, indent, 0);
    return out;
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

std::string json_escape(std::string_view text) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() + 8);
    for (const char raw : text) {
        const auto current = static_cast<unsigned char>(raw);
        switch (current) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (current < 0x20U) {
                out += "\\u00";
                out.push_back(kHexDigits[(current >> 4U) & 0x0FU]);
                out.push_back(kHexDigits[current & 0x0FU]);
            } else {
                out.push_back(raw);
            }
            break;
        }
    }
    return out;
}

core::Result<JsonValue> parse_json(std::string_view text) { return Parser(text).parse(); }

}  // namespace typemorph::cli

// TypeMorph - small dependency-free JSON value used by the CLI and JSON-RPC.
#pragma once

#include "typemorph/core/result.hpp"

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace typemorph::cli {

class JsonValue {
public:
    using Array = std::vector<JsonValue>;
    using Object = std::vector<std::pair<std::string, JsonValue>>;

    enum class Kind : std::uint8_t { null, boolean, integer, number, string, array, object };

    JsonValue() = default;
    JsonValue(std::nullptr_t) {}
    JsonValue(bool value) : storage_(value) {}
    JsonValue(int value) : storage_(static_cast<std::int64_t>(value)) {}
    JsonValue(std::int64_t value) : storage_(value) {}
    JsonValue(std::uint64_t value);
    JsonValue(double value) : storage_(value) {}
    JsonValue(std::string value) : storage_(std::move(value)) {}
    JsonValue(const char* value) : storage_(std::string(value)) {}
    JsonValue(Array value) : storage_(std::move(value)) {}
    JsonValue(Object value) : storage_(std::move(value)) {}
    JsonValue(std::initializer_list<std::pair<std::string, JsonValue>> values);

    [[nodiscard]] static JsonValue array();
    [[nodiscard]] static JsonValue object();
    [[nodiscard]] static JsonValue null();

    [[nodiscard]] Kind kind() const noexcept;
    [[nodiscard]] bool is_null() const noexcept { return kind() == Kind::null; }
    [[nodiscard]] bool is_boolean() const noexcept { return kind() == Kind::boolean; }
    [[nodiscard]] bool is_number() const noexcept;
    [[nodiscard]] bool is_string() const noexcept { return kind() == Kind::string; }
    [[nodiscard]] bool is_array() const noexcept { return kind() == Kind::array; }
    [[nodiscard]] bool is_object() const noexcept { return kind() == Kind::object; }

    [[nodiscard]] std::optional<bool> as_bool() const;
    [[nodiscard]] std::optional<std::int64_t> as_int() const;
    [[nodiscard]] std::optional<double> as_double() const;
    [[nodiscard]] const std::string* as_string() const;
    [[nodiscard]] const Array* as_array() const;
    [[nodiscard]] const Object* as_object() const;

    [[nodiscard]] bool contains(std::string_view key) const;
    [[nodiscard]] const JsonValue* find(std::string_view key) const;
    [[nodiscard]] const JsonValue& at(std::string_view key) const;
    [[nodiscard]] JsonValue& operator[](std::string key);
    JsonValue& push(JsonValue value);

    [[nodiscard]] std::string dump(int indent = 4) const;

private:
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;
    Storage storage_{nullptr};
};

[[nodiscard]] core::Result<JsonValue> parse_json(std::string_view text);
[[nodiscard]] std::string json_escape(std::string_view text);

}  // namespace typemorph::cli

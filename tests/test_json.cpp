// TypeMorph - unit tests for the dependency-free JSON value, parser and writer.

#include "test_framework.hpp"

#include "typemorph/cli/json.hpp"

#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using typemorph::cli::JsonValue;
using typemorph::cli::json_escape;
using typemorph::cli::parse_json;
using typemorph::core::ErrorCode;

namespace {

[[nodiscard]] const JsonValue& value_of(const typemorph::core::Result<JsonValue>& result) {
    REQUIRE(result.has_value());
    return result.value();
}

[[nodiscard]] bool is_parse_error(const typemorph::core::Result<JsonValue>& result) {
    return !result.has_value() && result.error().code == ErrorCode::parse_error;
}

}  // namespace

TEST_CASE("json/parse scalar kinds") {
    const auto null_value = parse_json("null");
    REQUIRE(null_value.has_value());
    CHECK(null_value.value().is_null());
    CHECK(null_value.value().kind() == JsonValue::Kind::null);

    const auto true_value = parse_json(" true ");
    REQUIRE(true_value.has_value());
    CHECK(true_value.value().is_boolean());
    CHECK(true_value.value().as_bool().value_or(false));
    CHECK_EQ(true_value.value().kind() == JsonValue::Kind::boolean, true);

    const auto false_value = parse_json("false");
    REQUIRE(false_value.has_value());
    CHECK(false_value.value().as_bool().has_value());
    CHECK(!false_value.value().as_bool().value_or(true));

    const auto integer_value = parse_json("42");
    REQUIRE(integer_value.has_value());
    CHECK(integer_value.value().kind() == JsonValue::Kind::integer);
    CHECK(integer_value.value().is_number());
    CHECK_EQ(integer_value.value().as_int().value_or(0), 42);

    const auto negative_value = parse_json(" -7 ");
    REQUIRE(negative_value.has_value());
    CHECK_EQ(negative_value.value().as_int().value_or(0), -7);

    const auto double_value = parse_json("1.5");
    REQUIRE(double_value.has_value());
    CHECK(double_value.value().kind() == JsonValue::Kind::number);
    CHECK_NEAR(double_value.value().as_double().value_or(0.0), 1.5, 1e-12);

    const auto exponent_value = parse_json("2.5e2");
    REQUIRE(exponent_value.has_value());
    CHECK_NEAR(exponent_value.value().as_double().value_or(0.0), 250.0, 1e-9);

    const auto string_value = parse_json(R"("hello")");
    REQUIRE(string_value.has_value());
    REQUIRE(string_value.value().as_string() != nullptr);
    CHECK_EQ(*string_value.value().as_string(), std::string("hello"));
}

TEST_CASE("json/parse integer boundaries") {
    const auto int64_max = parse_json("9223372036854775807");
    REQUIRE(int64_max.has_value());
    CHECK(int64_max.value().kind() == JsonValue::Kind::integer);
    CHECK_EQ(int64_max.value().as_int().value_or(0),
             std::numeric_limits<std::int64_t>::max());

    const auto int64_min = parse_json("-9223372036854775808");
    REQUIRE(int64_min.has_value());
    CHECK(int64_min.value().kind() == JsonValue::Kind::integer);
    CHECK_EQ(int64_min.value().as_int().value_or(0),
             std::numeric_limits<std::int64_t>::min());

    // Larger than INT64_MAX: accepted as a double rather than rejected.
    const auto huge = parse_json("18446744073709551615");
    REQUIRE(huge.has_value());
    CHECK(huge.value().kind() == JsonValue::Kind::number);

    const auto zero = parse_json("0");
    REQUIRE(zero.has_value());
    CHECK_EQ(zero.value().as_int().value_or(-1), 0);

    const auto negative_zero = parse_json("-0");
    REQUIRE(negative_zero.has_value());
    CHECK_EQ(negative_zero.value().as_int().value_or(-1), 0);

    const auto fraction = parse_json("-0.5");
    REQUIRE(fraction.has_value());
    CHECK_NEAR(fraction.value().as_double().value_or(0.0), -0.5, 1e-12);

    const auto small_exponent = parse_json("1e-3");
    REQUIRE(small_exponent.has_value());
    CHECK_NEAR(small_exponent.value().as_double().value_or(0.0), 0.001, 1e-12);

    const auto upper_exponent = parse_json("1E+3");
    REQUIRE(upper_exponent.has_value());
    CHECK_NEAR(upper_exponent.value().as_double().value_or(0.0), 1000.0, 1e-9);
}

TEST_CASE("json/rejects malformed numbers") {
    for (const std::string_view text : {"01",   "-",    "1.",   ".5",   "1e",
                                        "+1",   "0x10", "nan",  "Infinity",
                                        "- 1",  "1.2.3"}) {
        const auto result = parse_json(text);
        CHECK(is_parse_error(result));
    }
    for (const std::string_view text : {"1e", "1e+", "1e-", "-", "00", "-01"}) {
        CHECK(is_parse_error(parse_json(text)));
    }
}

TEST_CASE("json/parse string escapes") {
    const auto escapes = parse_json(R"("\" \\ \/ \b \f \n \r \t")");
    REQUIRE(escapes.has_value());
    REQUIRE(escapes.value().as_string() != nullptr);
    CHECK_EQ(*escapes.value().as_string(), std::string("\" \\ / \b \f \n \r \t"));

    const auto unicode_a = parse_json(R"("\u0041\u0042")");
    REQUIRE(unicode_a.has_value());
    CHECK_EQ(*unicode_a.value().as_string(), std::string("AB"));

    const auto unicode_latin = parse_json(R"("\u00e9")");
    REQUIRE(unicode_latin.has_value());
    CHECK_EQ(*unicode_latin.value().as_string(), std::string("\xC3\xA9"));  // e-acute

    const auto surrogate_pair = parse_json(R"("\ud83d\ude00")");
    REQUIRE(surrogate_pair.has_value());
    CHECK_EQ(*surrogate_pair.value().as_string(), std::string("\xF0\x9F\x98\x80"));  // U+1F600

    const auto nul_escape = parse_json(R"("a\u0000b")");
    REQUIRE(nul_escape.has_value());
    REQUIRE(nul_escape.value().as_string() != nullptr);
    CHECK_EQ(nul_escape.value().as_string()->size(), static_cast<std::size_t>(3));
    CHECK_EQ((*nul_escape.value().as_string())[1], '\0');

    const auto raw_utf8 = parse_json("\"h\xC3\xA9llo \xE4\xB8\x96\xE7\x95\x8C\"");
    REQUIRE(raw_utf8.has_value());
    CHECK_EQ(raw_utf8.value().as_string()->size(), static_cast<std::size_t>(13));
}

TEST_CASE("json/rejects malformed strings") {
    for (const std::string_view text : {R"("\q")", R"("\u12")", R"("\ud800")",
                                        R"("\udc00")", R"("\ud800x")",
                                        R"("\ud800\ud800")", R"("\")", "\"abc"}) {
        CHECK(is_parse_error(parse_json(text)));
    }
    // Unescaped control character.
    const std::string control = "\"a\x01b\"";
    CHECK(is_parse_error(parse_json(control)));
    // Invalid UTF-8 raw byte in a string.
    const std::string invalid_utf8 = std::string("\"a") + static_cast<char>(0xFF) + "b\"";
    CHECK(is_parse_error(parse_json(invalid_utf8)));
}

TEST_CASE("json/parse arrays and objects") {
    const auto array = parse_json("[1, true, null, \"x\", [2, 3]]");
    REQUIRE(array.has_value());
    REQUIRE(array.value().as_array() != nullptr);
    CHECK_EQ(array.value().as_array()->size(), static_cast<std::size_t>(5));
    CHECK_EQ((*array.value().as_array())[0].as_int().value_or(0), 1);
    CHECK((*array.value().as_array())[1].as_bool().value_or(false));
    CHECK((*array.value().as_array())[2].is_null());
    CHECK_EQ(*(*array.value().as_array())[3].as_string(), std::string("x"));
    CHECK_EQ((*array.value().as_array())[4].as_array()->size(), static_cast<std::size_t>(2));

    const auto object = parse_json(R"({ "b": 1, "a": 2, "nested": { "ok": true } })");
    REQUIRE(object.has_value());
    REQUIRE(object.value().as_object() != nullptr);
    CHECK_EQ(object.value().as_object()->size(), static_cast<std::size_t>(3));
    // Insertion order is preserved verbatim.
    CHECK_EQ((*object.value().as_object())[0].first, std::string("b"));
    CHECK_EQ((*object.value().as_object())[1].first, std::string("a"));
    CHECK_EQ((*object.value().as_object())[2].first, std::string("nested"));
    CHECK(object.value().contains("nested"));
    CHECK(!object.value().contains("missing"));
    CHECK(object.value().at("a").as_int().value_or(0) == 2);

    const auto empty_object = parse_json("{}");
    REQUIRE(empty_object.has_value());
    CHECK(empty_object.value().is_object());
    CHECK(empty_object.value().as_object()->empty());

    const auto empty_array = parse_json("[ ]");
    REQUIRE(empty_array.has_value());
    CHECK(empty_array.value().is_array());
    CHECK(empty_array.value().as_array()->empty());

    CHECK(is_parse_error(parse_json(R"({"a": 1, "a": 2})")));  // Duplicate keys.
}

TEST_CASE("json/rejects malformed documents") {
    for (const std::string_view text : {"", "   ", "{", "[", "}", "]", "{\"a\"}",
                                        "{\"a\":}", "{\"a\":1,}", "[1,]", "{\"a\" 1}",
                                        "tru", "nulll", "[1 2]", "{\"a\":1} extra",
                                        "{\"a\":1}x", "/*comment*/null", "'single'"}) {
        CHECK(is_parse_error(parse_json(text)));
    }
}

TEST_CASE("json/nesting depth limit") {
    std::string shallow;
    for (int i = 0; i < 200; ++i) shallow.push_back('[');
    for (int i = 0; i < 200; ++i) shallow.push_back(']');
    CHECK(parse_json(shallow).has_value());

    std::string deep;
    for (int i = 0; i < 600; ++i) deep.push_back('[');
    for (int i = 0; i < 600; ++i) deep.push_back(']');
    CHECK(is_parse_error(parse_json(deep)));

    // Rapidly constructed values can also be deeper than the writer allows; the
    // dump must stay bounded instead of recursing until the stack overflows.
    JsonValue nested = JsonValue::array();
    JsonValue* cursor = &nested;
    for (int i = 0; i < 600; ++i) cursor = &cursor->push(JsonValue::array());
    const std::string dumped = nested.dump(0);
    CHECK(!dumped.empty());
    CHECK(dumped.find("null") != std::string::npos);
}

TEST_CASE("json/dump compact and pretty") {
    const auto parsed = parse_json(
        R"({"name":"typemorph","values":[1,true,null,"x"],"nested":{"ratio":2.5}})");
    REQUIRE(parsed.has_value());
    const JsonValue& value = parsed.value();

    CHECK_EQ(value.dump(0),
             std::string(R"({"name":"typemorph","values":[1,true,null,"x"],"nested":{"ratio":2.5}})"));
    CHECK_EQ(value.dump(-1),
             std::string(R"({"name":"typemorph","values":[1,true,null,"x"],"nested":{"ratio":2.5}})"));
    CHECK_EQ(value.dump(),
             std::string("{\n"
                         "    \"name\": \"typemorph\",\n"
                         "    \"values\": [\n"
                         "        1,\n"
                         "        true,\n"
                         "        null,\n"
                         "        \"x\"\n"
                         "    ],\n"
                         "    \"nested\": {\n"
                         "        \"ratio\": 2.5\n"
                         "    }\n"
                         "}"));

    // Deterministic: repeated dumps and parse/dump/parse round-trips are stable.
    CHECK_EQ(value.dump(2), value.dump(2));
    const auto reparsed = parse_json(value.dump(4));
    REQUIRE(reparsed.has_value());
    CHECK_EQ(reparsed.value().dump(4), value.dump(4));

    // Empty containers render compactly in both modes.
    CHECK_EQ(JsonValue::array().dump(4), std::string("[]"));
    CHECK_EQ(JsonValue::object().dump(4), std::string("{}"));
}

TEST_CASE("json/dump escapes and special numbers") {
    JsonValue object = JsonValue::object();
    object["line"] = std::string("a\nb\tc\"d\\e");
    object["control"] = std::string("\x01");
    CHECK_EQ(object.dump(0), std::string(R"({"line":"a\nb\tc\"d\\e","control":"\u0001"})"));

    CHECK_EQ(JsonValue(std::numeric_limits<double>::quiet_NaN()).dump(0), std::string("null"));
    CHECK_EQ(JsonValue(std::numeric_limits<double>::infinity()).dump(0), std::string("null"));
    CHECK_EQ(JsonValue(-std::numeric_limits<double>::infinity()).dump(0), std::string("null"));
    CHECK_EQ(JsonValue(2.0).dump(0), std::string("2.0"));
    CHECK_EQ(JsonValue(2).dump(0), std::string("2"));

    // Escaped output is valid JSON again.
    const auto roundtrip = parse_json(object.dump(0));
    REQUIRE(roundtrip.has_value());
    CHECK_EQ(*roundtrip.value().at("control").as_string(), std::string("\x01"));
}

TEST_CASE("json/value construction and accessors") {
    CHECK(JsonValue().is_null());
    CHECK(JsonValue(nullptr).is_null());
    CHECK(JsonValue::null().is_null());
    CHECK(JsonValue(true).as_bool().value_or(false));
    CHECK_EQ(JsonValue(7).as_int().value_or(0), 7);
    CHECK_EQ(JsonValue(std::int64_t{-7}).as_int().value_or(0), -7);
    CHECK_EQ(JsonValue(std::uint64_t{7}).as_int().value_or(0), 7);
    CHECK_NEAR(JsonValue(1.25).as_double().value_or(0.0), 1.25, 1e-12);
    const JsonValue literal_value("literal");
    CHECK_EQ(*literal_value.as_string(), std::string("literal"));
    CHECK(JsonValue(std::string("owned")).is_string());

    // Unsigned values above INT64_MAX degrade to the number kind.
    const JsonValue big(std::numeric_limits<std::uint64_t>::max());
    CHECK(big.kind() == JsonValue::Kind::number);
    CHECK(big.is_number());
    CHECK(!big.as_int().has_value());

    CHECK(JsonValue(1).as_bool() == std::nullopt);
    CHECK(!JsonValue("x").as_int().has_value());

    const JsonValue integer(3);
    CHECK(!integer.as_double().has_value() == false);
    CHECK_NEAR(integer.as_double().value_or(0.0), 3.0, 1e-12);

    // Arrays: push returns a reference and converts non-arrays.
    JsonValue list = JsonValue::array();
    list.push(JsonValue(1));
    list.push(JsonValue("two"));
    list.push(JsonValue::object());
    REQUIRE(list.as_array() != nullptr);
    CHECK_EQ(list.as_array()->size(), static_cast<std::size_t>(3));

    // Objects: operator[] inserts in order and is idempotent for existing keys.
    JsonValue record;
    record["z"] = JsonValue(1);
    record["a"] = JsonValue(2);
    record["z"] = JsonValue(3);
    REQUIRE(record.as_object() != nullptr);
    CHECK_EQ(record.as_object()->size(), static_cast<std::size_t>(2));
    CHECK_EQ(record.as_object()->at(0).first, std::string("z"));
    CHECK_EQ(record.as_object()->at(1).first, std::string("a"));
    CHECK_EQ(record.at("z").as_int().value_or(0), 3);

    // Initializer-list construction keeps the listed order.
    const JsonValue from_list{{"one", JsonValue(1)}, {"two", JsonValue(2)}};
    REQUIRE(from_list.as_object() != nullptr);
    CHECK_EQ(from_list.as_object()->at(0).first, std::string("one"));

    bool threw = false;
    try {
        (void)record.at("missing");
    } catch (const std::out_of_range&) {
        threw = true;
    }
    CHECK(threw);
    CHECK_EQ(record.find("missing"), static_cast<const JsonValue*>(nullptr));
    CHECK(record.find("z") != nullptr);
    CHECK(!record.contains("missing"));
}

TEST_CASE("json/json_escape") {
    CHECK_EQ(json_escape("plain"), std::string("plain"));
    CHECK_EQ(json_escape("quote\"slash\\"), std::string("quote\\\"slash\\\\"));
    CHECK_EQ(json_escape("a\nb\tc\r"), std::string("a\\nb\\tc\\r"));
    CHECK_EQ(json_escape("\b\f"), std::string("\\b\\f"));
    CHECK_EQ(json_escape(std::string("\x01\x1f", 2)), std::string("\\u0001\\u001f"));
    CHECK_EQ(json_escape("\xC3\xA9"), std::string("\xC3\xA9"));  // UTF-8 passes through
    CHECK_EQ(json_escape(""), std::string(""));
}

TEST_CASE("json/byte order mark is accepted") {
    const std::string with_bom = std::string("\xEF\xBB\xBF") + "{\"ok\":true}";
    const auto result = parse_json(with_bom);
    REQUIRE(result.has_value());
    CHECK(result.value().at("ok").as_bool().value_or(false));
}

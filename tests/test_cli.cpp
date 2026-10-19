// TypeMorph - CLI and integration tests.
//
// These exercise the same Application object used by main(), so option parsing,
// engine wiring, emitters and the dashboard render path are covered end to end.
#include "typemorph/cli/app.hpp"
#include "typemorph/cli/json.hpp"

#include "test_framework.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef TYPEMORPH_TEST_FIXTURES
#define TYPEMORPH_TEST_FIXTURES "tests/fixtures"
#endif

namespace {

using typemorph::cli::Application;
using typemorph::cli::JsonValue;
using typemorph::cli::parse_json;

std::string fixture_path(const std::string& name) {
    return (std::filesystem::path(TYPEMORPH_TEST_FIXTURES) / name).string();
}

struct Invocation {
    int exit_code = -1;
    std::string out;
    std::string err;
};

Invocation invoke(std::vector<std::string> args) {
    std::ostringstream out;
    std::ostringstream err;
    Application application(out, err);
    Invocation invocation;
    invocation.exit_code = application.run(args);
    invocation.out = out.str();
    invocation.err = err.str();
    return invocation;
}

const JsonValue* find_field_at(const JsonValue& document, std::uint64_t offset) {
    const auto* fields = document.find("fields");
    if (fields == nullptr || fields->as_array() == nullptr) return nullptr;
    for (const auto& field : *fields->as_array()) {
        const auto* value = field.find("offset");
        if (value == nullptr) continue;
        const auto number = value->as_int();
        if (number && static_cast<std::uint64_t>(*number) == offset) return &field;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("cli: version and help are scriptable") {
    const auto version = invoke({"version"});
    CHECK_EQ(version.exit_code, 0);
    CHECK(version.out.find("TypeMorph") != std::string::npos);

    const auto help = invoke({"help"});
    CHECK_EQ(help.exit_code, 0);
    CHECK(help.out.find("inspect") != std::string::npos);
    CHECK(help.out.find("serve") != std::string::npos);

    const auto unknown = invoke({"not-a-command"});
    CHECK_EQ(unknown.exit_code, 2);
    CHECK(unknown.err.find("unknown command") != std::string::npos);
}

TEST_CASE("cli: infer emits structurally valid Kaitai and JSON") {
    const std::string v1 = fixture_path("sample_v1.bin");
    const std::string v2 = fixture_path("sample_v2.bin");
    const std::string v3 = fixture_path("sample_v3.bin");
    REQUIRE(std::filesystem::exists(v1));

    const auto kaitai = invoke({"infer", v1, v2, v3, "--format=kaitai",
                                "--min-array-elements=3", "--confidence-threshold=0.85"});
    CHECK_EQ(kaitai.exit_code, 0);
    CHECK(kaitai.out.find("meta:") != std::string::npos);
    CHECK(kaitai.out.find("seq:") != std::string::npos);
    CHECK(kaitai.out.find("TMSX") != std::string::npos);

    const auto json = invoke({"infer", v1, v2, v3, "--format=json",
                              "--min-array-elements=3", "--confidence-threshold=0.50"});
    CHECK_EQ(json.exit_code, 0);
    auto parsed = parse_json(json.out);
    REQUIRE(parsed.has_value());
    const JsonValue& document = parsed.value();
    const auto* sample_count = document.find("sample_count");
    REQUIRE(sample_count != nullptr);
    CHECK_EQ(sample_count->as_int().value_or(0), std::int64_t{3});

    // The fixture's count field is at 0x10 and the record array has stride 12.
    const JsonValue* count = find_field_at(document, 0x10);
    REQUIRE(count != nullptr);
    REQUIRE(count->find("array_element_size") != nullptr);
    CHECK_EQ(count->find("array_element_size")->as_int().value_or(0), std::int64_t{12});
    REQUIRE(count->find("count_field_offset") != nullptr);
    CHECK_EQ(count->find("count_field_offset")->as_int().value_or(-1), std::int64_t{0x10});
}

TEST_CASE("cli: inspect renders a deterministic frame without a terminal") {
    const auto rendered = invoke({"inspect", fixture_path("sample_v1.bin"), "--render-once",
                                  "--width=110", "--height=30"});
    CHECK_EQ(rendered.exit_code, 0);
    CHECK(rendered.out.find("Hex") != std::string::npos);
    CHECK(rendered.out.find("AST") != std::string::npos);
    CHECK(rendered.out.find("Kaitai") != std::string::npos);

    const auto json = invoke({"inspect", fixture_path("sample_v1.bin"), "--json"});
    CHECK_EQ(json.exit_code, 0);
    auto parsed = parse_json(json.out);
    REQUIRE(parsed.has_value());
    CHECK(parsed.value().find("kaitai") != nullptr);
    CHECK(parsed.value().find("cpp") != nullptr);
}

TEST_CASE("cli: rust recovers strings and vtables from the ELF fixture") {
    const auto result = invoke({"rust", fixture_path("rust_sample.elf"), "--json"});
    CHECK_EQ(result.exit_code, 0);
    auto parsed = parse_json(result.out);
    REQUIRE(parsed.has_value());

    const auto* strings = parsed.value().find("strings");
    REQUIRE(strings != nullptr);
    REQUIRE(strings->as_array() != nullptr);
    CHECK(strings->as_array()->size() >= 3);

    const auto* vtables = parsed.value().find("vtables");
    REQUIRE(vtables != nullptr);
    REQUIRE(vtables->as_array() != nullptr);
    CHECK(vtables->as_array()->size() >= 1);
    if (!vtables->as_array()->empty()) {
        const auto& vtable = vtables->as_array()->front();
        const auto* size = vtable.find("object_size");
        REQUIRE(size != nullptr);
        CHECK_EQ(size->as_int().value_or(0), std::int64_t{24});
    }
}

TEST_CASE("cli: hybrid infers an embedded executable section") {
    const auto result = invoke({"hybrid", fixture_path("rust_sample.elf"), "--section=.rodata",
                                "--format=kaitai"});
    CHECK_EQ(result.exit_code, 0);
    CHECK(result.out.find("meta:") != std::string::npos);

    const auto json = invoke({"hybrid", fixture_path("rust_sample.elf"), "--section=.data",
                              "--format=json"});
    CHECK_EQ(json.exit_code, 0);
    auto parsed = parse_json(json.out);
    REQUIRE(parsed.has_value());
    CHECK(parsed.value().find("section") != nullptr);
}

TEST_CASE("cli: unxor cracks XOR encrypted file and supports --key and --out") {
    const std::string plain = "TypeMorph deobfuscation test string: reverse engineering binary structures!";
    const std::uint8_t key = 0x5a;
    std::vector<std::uint8_t> cipher(plain.size());
    for (std::size_t i = 0; i < plain.size(); ++i) {
        cipher[i] = static_cast<std::uint8_t>(plain[i]) ^ key;
    }
    const auto temp_in = std::filesystem::current_path() / "test_unxor_in.bin";
    const auto temp_out = std::filesystem::current_path() / "test_unxor_out.bin";
    {
        std::ofstream stream(temp_in, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
    }

    const auto cracked = invoke({"unxor", temp_in.string(), "--json"});
    CHECK_EQ(cracked.exit_code, 0);
    auto parsed = parse_json(cracked.out);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value().as_array() != nullptr);
    CHECK(!parsed.value().as_array()->empty());
    const auto& best = parsed.value().as_array()->front();
    REQUIRE(best.find("key") != nullptr);
    REQUIRE(best.find("key")->as_string() != nullptr);
    CHECK_EQ(*best.find("key")->as_string(), "5a");

    const auto direct = invoke({"unxor", temp_in.string(), "--key=5a", "--out=" + temp_out.string()});
    CHECK_EQ(direct.exit_code, 0);
    REQUIRE(std::filesystem::exists(temp_out));
    {
        std::ifstream stream(temp_out, std::ios::binary);
        std::ostringstream ss;
        ss << stream.rdbuf();
        CHECK_EQ(ss.str(), plain);
    }

    std::filesystem::remove(temp_in);
    std::filesystem::remove(temp_out);
}

TEST_CASE("cli: strings extracts strings from binary with json and text formats") {
    const auto text_res = invoke({"strings", fixture_path("sample_v1.bin"), "--min-len=3"});
    CHECK_EQ(text_res.exit_code, 0);
    CHECK(text_res.out.find("[ascii") != std::string::npos);

    const auto json_res = invoke({"strings", fixture_path("sample_v1.bin"), "--min-len=3", "--json"});
    CHECK_EQ(json_res.exit_code, 0);
    auto parsed = parse_json(json_res.out);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value().as_array() != nullptr);
    CHECK(!parsed.value().as_array()->empty());
}

TEST_CASE("cli: devirt analyzes executable and reports VM instances") {
    const auto json_res = invoke({"devirt", fixture_path("rust_sample.elf"), "--json"});
    CHECK_EQ(json_res.exit_code, 0);
    auto parsed = parse_json(json_res.out);
    REQUIRE(parsed.has_value());
    CHECK(parsed.value().find("instances") != nullptr);

    const auto text_res = invoke({"devirt", fixture_path("rust_sample.elf")});
    CHECK_EQ(text_res.exit_code, 0);
    CHECK(text_res.out.find("Devirtualizer") != std::string::npos);
}


#include "test_framework.hpp"

#include "typemorph/deobf/strings.hpp"

#include <string>
#include <vector>

using namespace typemorph::deobf;
using namespace typemorph::core;

TEST_CASE("strings: ascii extraction") {
    std::vector<std::uint8_t> buffer = {
        0x00, 0x01, 0x02,
        'H', 'e', 'l', 'l', 'o', 'W', 'o', 'r', 'l', 'd',
        0x00, 0xFF,
        'T', 'e', 's', 't', 'S', 't', 'r', 'i', 'n', 'g',
        0x00
    };
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    StringRevealer revealer;
    auto strings = revealer.extract(view);

    REQUIRE_EQ(strings.size(), std::size_t{2});
    CHECK_EQ(strings[0].value, std::string("HelloWorld"));
    CHECK_EQ(strings[0].offset, std::uint64_t{3});
    CHECK_EQ(strings[1].value, std::string("TestString"));
}

TEST_CASE("strings: utf16le extraction") {
    // UTF-16LE for "Kernel32.dll"
    std::vector<std::uint8_t> buffer = {
        0x00, 0x00,
        'K', 0x00, 'e', 0x00, 'r', 0x00, 'n', 0x00, 'e', 0x00, 'l', 0x00,
        '3', 0x00, '2', 0x00, '.', 0x00, 'd', 0x00, 'l', 0x00, 'l', 0x00,
        0x00, 0x00
    };
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    StringScanOptions options;
    options.scan_ascii = false; // isolate utf16
    options.scan_utf16le = true;
    StringRevealer revealer(options);
    auto strings = revealer.extract(view);

    REQUIRE_EQ(strings.size(), std::size_t{1});
    CHECK_EQ(strings[0].value, std::string("Kernel32.dll"));
    CHECK(strings[0].category == StringCategory::utf16le);
}

TEST_CASE("strings: stack string reconstruction") {
    // Synthetic bytecode mimicking:
    // mov byte ptr [rbp-0x10], 'p' (C6 45 F0 70)
    // mov byte ptr [rbp-0x0F], 'a' (C6 45 F1 61)
    // mov byte ptr [rbp-0x0E], 's' (C6 45 F2 73)
    // mov byte ptr [rbp-0x0D], 's' (C6 45 F3 73)
    // mov byte ptr [rbp-0x0C], 0x00 (C6 45 F4 00)
    std::vector<std::uint8_t> buffer = {
        0x90, 0x90,
        0xC6, 0x45, 0xF0, 'p',
        0xC6, 0x45, 0xF1, 'a',
        0xC6, 0x45, 0xF2, 's',
        0xC6, 0x45, 0xF3, 's',
        0xC6, 0x45, 0xF4, 0x00,
        0x90, 0x90
    };
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    StringScanOptions options;
    options.scan_ascii = false;
    options.scan_utf16le = false;
    options.scan_stack_strings = true;
    options.scan_xor_strings = false;
    StringRevealer revealer(options);
    auto strings = revealer.extract(view);

    REQUIRE_EQ(strings.size(), std::size_t{1});
    CHECK_EQ(strings[0].value, std::string("pass"));
    CHECK(strings[0].category == StringCategory::stack_string);
}

TEST_CASE("strings: base64 extraction") {
    // "aHR0cDovL2V2aWwuY29t" is base64 for "http://evil.com"
    std::string payload = "###aHR0cDovL2V2aWwuY29t###";
    std::vector<std::uint8_t> buffer(payload.begin(), payload.end());
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    StringScanOptions options;
    options.scan_ascii = false;
    options.scan_utf16le = false;
    options.scan_stack_strings = false;
    options.scan_xor_strings = false;
    options.scan_base64 = true;
    options.scan_rot13 = false;
    StringRevealer revealer(options);
    auto strings = revealer.extract(view);

    REQUIRE(strings.size() >= 1);
    CHECK(strings[0].value == "http://evil.com");
    CHECK(strings[0].category == StringCategory::decoded_base64);
}

TEST_CASE("strings: rot13 extraction") {
    // ROT13 of "powershell" is "cbjrefuryy"
    std::string payload = "###cbjrefuryy###";
    std::vector<std::uint8_t> buffer(payload.begin(), payload.end());
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    StringScanOptions options;
    options.scan_ascii = false;
    options.scan_utf16le = false;
    options.scan_stack_strings = false;
    options.scan_xor_strings = false;
    options.scan_base64 = false;
    options.scan_rot13 = true;
    StringRevealer revealer(options);
    auto strings = revealer.extract(view);

    REQUIRE(strings.size() >= 1);
    CHECK(strings[0].value == "powershell");
    CHECK(strings[0].category == StringCategory::decoded_rot13);
}

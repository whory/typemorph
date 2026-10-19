// TypeMorph - Rust demangler tests (legacy and v0 schemes).
#include "test_framework.hpp"

#include "typemorph/core/result.hpp"
#include "typemorph/derust/demangle.hpp"

#include <string>
#include <string_view>
#include <vector>

using typemorph::derust::DemangledSymbol;
using typemorph::derust::demangle;
using typemorph::derust::demangle_or_original;
using typemorph::derust::looks_like_rust_symbol;

namespace {

// Builds a syntactically correct legacy symbol from raw (escaped) segments and
// appends the 17h hash disambiguator that every real legacy symbol carries.
std::string legacy_symbol(const std::vector<std::string>& segments, bool with_hash = true) {
    std::string out = "_ZN";
    for (const std::string& segment : segments) {
        out += std::to_string(segment.size());
        out += segment;
    }
    if (with_hash) out += "17h0123456789abcdef";
    out += 'E';
    return out;
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

TEST_CASE("demangle: legacy path, crate and hash stripping") {
    const std::string symbol = legacy_symbol({"test", "foo"});
    const auto result = demangle(symbol);
    REQUIRE(result.has_value());
    const DemangledSymbol& demangled = result.value();
    CHECK_EQ(demangled.mangled, symbol);
    CHECK_EQ(demangled.demangled, std::string("test::foo"));
    CHECK_EQ(demangled.path, std::string("test::foo"));
    CHECK_EQ(demangled.crate, std::string("test"));
    CHECK(demangled.is_rust);
    CHECK(!demangled.is_v0);
    CHECK(demangled.generic_args.empty());
    CHECK(!contains(demangled.demangled, "17h"));
    CHECK(!contains(demangled.demangled, "0123456789abcdef"));
}

TEST_CASE("demangle: legacy keeps genuine leading underscores") {
    const auto result = demangle(legacy_symbol({"std", "io", "stdio", "_print"}));
    REQUIRE(result.has_value());
    CHECK_EQ(result.value().demangled, std::string("std::io::stdio::_print"));
    CHECK_EQ(result.value().crate, std::string("std"));

    const auto private_symbol = demangle(legacy_symbol({"mycrate", "__private"}));
    REQUIRE(private_symbol.has_value());
    CHECK_EQ(private_symbol.value().demangled, std::string("mycrate::__private"));
}

TEST_CASE("demangle: legacy escape decoding") {
    const auto special = demangle(
        legacy_symbol({"test", "x$LT$a$GT$y$RF$z$BP$w$C$v$u20$q$u27$r"}));
    REQUIRE(special.has_value());
    CHECK_EQ(special.value().demangled, std::string("test::x<a>y&z*w,v q'r"));

    const auto closure = demangle(legacy_symbol({"test", "main", "_$u7b$$u7b$closure$u7d$$u7d$"}));
    REQUIRE(closure.has_value());
    CHECK_EQ(closure.value().demangled, std::string("test::main::{{closure}}"));
    CHECK_EQ(closure.value().crate, std::string("test"));

    // Non-ASCII identifiers can be encoded as a run of UTF-8 bytes ($uC3$$uA9$)
    // or as one code point ($uE9$); both decode to the same character.
    const auto utf8_bytes = demangle(legacy_symbol({"test", "caf$uc3$$ua9$"}));
    REQUIRE(utf8_bytes.has_value());
    CHECK_EQ(utf8_bytes.value().demangled, std::string("test::caf\xc3\xa9"));

    const auto code_point = demangle(legacy_symbol({"test", "caf$ue9$"}));
    REQUIRE(code_point.has_value());
    CHECK_EQ(code_point.value().demangled, std::string("test::caf\xc3\xa9"));

    const auto emoji = demangle(legacy_symbol({"test", "x$u1f600$"}));
    REQUIRE(emoji.has_value());
    CHECK_EQ(emoji.value().demangled, std::string("test::x\xf0\x9f\x98\x80"));
}

TEST_CASE("demangle: legacy impl path (underscore prefix and `..` for `::`)") {
    const std::string impl_segment =
        "_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$";
    const auto result = demangle(legacy_symbol({impl_segment, "fmt"}));
    REQUIRE(result.has_value());
    CHECK_EQ(result.value().demangled,
             std::string("<alloc::string::String as core::fmt::Display>::fmt"));
    // The first segment is the impl path, so no crate can be attributed.
    CHECK(result.value().crate.empty());
    CHECK(result.value().is_rust);
}

TEST_CASE("demangle: legacy accepts a vendor suffix") {
    const std::string symbol = legacy_symbol({"test", "foo"}) + ".llvm.1234567";
    const auto result = demangle(symbol);
    REQUIRE(result.has_value());
    CHECK_EQ(result.value().demangled, std::string("test::foo"));
    CHECK_EQ(result.value().mangled, symbol);
}

TEST_CASE("demangle: legacy malformed input returns an error") {
    const std::vector<std::string> malformed = {
        "",                                        // empty
        "_ZN",                                     // nothing after the prefix
        "_Z",                                      // not a symbol at all
        "_ZN4test3foo17h0123456789abcdef",         // missing terminating E
        "_ZN4test3foo17h0123456789abcdefEv",       // C++ return type after E
        "_ZN4test3fo17h0123456789abcdefE",         // length prefix too long
        "_ZN0E",                                   // zero-length segment
        "_ZN4test3foo17h0123456789abcdeZ",         // hash is not hexadecimal
        legacy_symbol({"test", "foo"}, false),     // no Rust hash disambiguator
        "_ZN3foo3barE",                            // no hash at all
    };
    for (const std::string& symbol : malformed) {
        CHECK(!demangle(symbol).has_value());
        CHECK(!looks_like_rust_symbol(symbol));
    }
}

TEST_CASE("demangle: looks_like_rust_symbol rejects C++ itanium names") {
    const std::vector<std::string> cpp = {
        "_ZN3foo3barEv",
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "_ZN4core3fmt9Formatter9write_strE",
        "_Z3fooi",
        "_ZNK3Foo3barEv",
        "main",
        "malloc",
        "_start",
        "rust_sample_method_0",
        "_R",
        "_ZN",
        "__Z",
        "some random text",
    };
    for (const std::string& symbol : cpp) {
        CHECK(!looks_like_rust_symbol(symbol));
        CHECK(!demangle(symbol).has_value());
    }
    CHECK(!looks_like_rust_symbol(std::string(70000, 'A')));
}

TEST_CASE("demangle: looks_like_rust_symbol accepts real Rust names") {
    CHECK(looks_like_rust_symbol(legacy_symbol({"my_crate", "module", "function"})));
    CHECK(looks_like_rust_symbol("_RNvC7mycrate3foo"));
    CHECK(looks_like_rust_symbol("_RINvC7mycrate3fooReE"));
    // Mach-O adds one extra leading underscore.
    CHECK(looks_like_rust_symbol("__RNvC7mycrate3foo"));
    CHECK(looks_like_rust_symbol("__ZN4test3foo17h0123456789abcdefE"));
}

TEST_CASE("demangle: v0 crate root and nested paths") {
    const auto root = demangle("_RNvC7mycrate3foo");
    REQUIRE(root.has_value());
    CHECK_EQ(root.value().demangled, std::string("mycrate::foo"));
    CHECK_EQ(root.value().crate, std::string("mycrate"));
    CHECK(root.value().is_rust);
    CHECK(root.value().is_v0);

    const auto nested = demangle("_RNvNvC7mycrate3mod3foo");
    REQUIRE(nested.has_value());
    CHECK_EQ(nested.value().demangled, std::string("mycrate::mod::foo"));
    CHECK_EQ(nested.value().crate, std::string("mycrate"));
}

TEST_CASE("demangle: v0 identifier disambiguators") {
    const auto result = demangle("_RNvCs1234_7mycrate3foo");
    REQUIRE(result.has_value());
    CHECK_EQ(result.value().demangled, std::string("mycrate::foo"));
    CHECK_EQ(result.value().crate, std::string("mycrate"));

    // Leading digits force the `_` separator in the identifier encoding.
    const auto digits = demangle("_RNvC6_123foo3bar");
    REQUIRE(digits.has_value());
    CHECK_EQ(digits.value().demangled, std::string("123foo::bar"));
    CHECK_EQ(digits.value().crate, std::string("123foo"));
}

TEST_CASE("demangle: v0 generic arguments") {
    const auto one = demangle("_RINvC7mycrate3fooReE");
    REQUIRE(one.has_value());
    CHECK_EQ(one.value().demangled, std::string("mycrate::foo::<&str>"));
    REQUIRE_EQ(one.value().generic_args.size(), std::size_t{1});
    CHECK_EQ(one.value().generic_args[0], std::string("&str"));

    const auto two = demangle("_RINvC7mycrate3fooReyE");
    REQUIRE(two.has_value());
    CHECK_EQ(two.value().demangled, std::string("mycrate::foo::<&str, u64>"));
    REQUIRE_EQ(two.value().generic_args.size(), std::size_t{2});
    CHECK_EQ(two.value().generic_args[1], std::string("u64"));

    const auto basics = demangle("_RINvC7mycrate3fooahbE");
    REQUIRE(basics.has_value());
    CHECK_EQ(basics.value().demangled, std::string("mycrate::foo::<i8, u8, bool>"));
}

TEST_CASE("demangle: v0 backreferences expand earlier entities") {
    // Backref index 1 refers to the already-decoded `mycrate::foo` path (index 0
    // is the enclosing generic-instantiation path, which is still being built).
    const auto result = demangle("_RINvC7mycrate3fooReB1_E");
    REQUIRE(result.has_value());
    CHECK_EQ(result.value().demangled, std::string("mycrate::foo::<&str, mycrate::foo>"));
    REQUIRE_EQ(result.value().generic_args.size(), std::size_t{2});
    CHECK_EQ(result.value().generic_args[1], std::string("mycrate::foo"));
}

TEST_CASE("demangle: v0 closures, versions, crates and suffixes") {
    const auto closure = demangle("_RNCNvC7mycrate3foo0");
    REQUIRE(closure.has_value());
    CHECK_EQ(closure.value().demangled, std::string("mycrate::foo::{closure}"));

    const auto versioned = demangle("_R0NvC7mycrate3foo");
    REQUIRE(versioned.has_value());
    CHECK_EQ(versioned.value().demangled, std::string("mycrate::foo"));

    const auto instantiated = demangle("_RNvC7mycrate3fooC8consumer");
    REQUIRE(instantiated.has_value());
    CHECK_EQ(instantiated.value().demangled, std::string("mycrate::foo"));
    CHECK_EQ(instantiated.value().crate, std::string("mycrate"));

    const auto suffix = demangle("_RNvC7mycrate3foo.llvm.42");
    REQUIRE(suffix.has_value());
    CHECK_EQ(suffix.value().demangled, std::string("mycrate::foo"));
}

TEST_CASE("demangle: v0 malformed input returns an error") {
    const std::vector<std::string> malformed = {
        "_R",
        "_Rx",
        "_RNvC",
        "_RNvC7mycrate",
        "_RNvC7mycrate3fooZ",
        "_RINvC7mycrate3fooRe",
        "_RNvC7mycrate3fooB9_",
        "_R0",
    };
    for (const std::string& symbol : malformed) {
        CHECK(!demangle(symbol).has_value());
        CHECK(!looks_like_rust_symbol(symbol));
    }
}

TEST_CASE("demangle_or_original is best effort") {
    CHECK_EQ(demangle_or_original(legacy_symbol({"test", "foo"})), std::string("test::foo"));
    CHECK_EQ(demangle_or_original("_RNvC7mycrate3foo"), std::string("mycrate::foo"));
    CHECK_EQ(demangle_or_original("_ZN3foo3barEv"), std::string("_ZN3foo3barEv"));
    CHECK_EQ(demangle_or_original("plain_c_symbol"), std::string("plain_c_symbol"));
    CHECK_EQ(demangle_or_original(""), std::string(""));
}

// TypeMorph - Opaque Predicates Detector tests.
#include "test_framework.hpp"

#include "typemorph/deobf/opaque_predicates.hpp"

using namespace typemorph::deobf;
using namespace typemorph::core;

TEST_CASE("opaque: detects self-xor zero flag jump") {
    OpaquePredicateDetector detector;

    // Synthetic bytecode:
    // xor eax, eax (31 C0)
    // jz +0x10 (74 10) -> always true!
    std::vector<std::uint8_t> buffer = {
        0x90,
        0x31, 0xC0,
        0x74, 0x10,
        0x90, 0x90
    };
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto matches = detector.scan(view);

    REQUIRE_EQ(matches.size(), std::size_t{1});
    CHECK(matches[0].outcome == PredicateOutcome::always_true);
    CHECK(matches[0].offset == 1);
    CHECK(matches[0].pattern_name == "self_register_zero_flag");
}

TEST_CASE("opaque: detects clc carry flag jump") {
    OpaquePredicateDetector detector;

    // Synthetic bytecode:
    // clc (F8)
    // jc +0x08 (72 08) -> always false (never taken)!
    std::vector<std::uint8_t> buffer = {
        0x90, 0x90,
        0xF8,
        0x72, 0x08,
        0x90
    };
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto matches = detector.scan(view);

    REQUIRE_EQ(matches.size(), std::size_t{1});
    CHECK(matches[0].outcome == PredicateOutcome::always_false);
    CHECK(matches[0].offset == 2);
    CHECK(matches[0].pattern_name == "carry_flag_invariant");
}

TEST_CASE("opaque: detects stc carry flag near jump") {
    OpaquePredicateDetector detector;

    // Synthetic bytecode:
    // stc (F9)
    // jc near (0F 82 20 00 00 00) -> always true!
    std::vector<std::uint8_t> buffer = {
        0xF9,
        0x0F, 0x82, 0x20, 0x00, 0x00, 0x00
    };
    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto matches = detector.scan(view);

    REQUIRE_EQ(matches.size(), std::size_t{1});
    CHECK(matches[0].outcome == PredicateOutcome::always_true);
    CHECK(matches[0].offset == 0);
}

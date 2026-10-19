// TypeMorph - tests for structural and binary diff engine.
#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"
#include "typemorph/diff/binary_diff.hpp"

#include <vector>

namespace {

using typemorph::core::BinaryView;
using typemorph::diff::BinaryDiffEngine;

TEST_CASE("binary diff: identical views report 100% similarity") {
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto view_a = BinaryView::from_external(data, "a");
    auto view_b = BinaryView::from_external(data, "b");

    BinaryDiffEngine engine;
    auto res = engine.compare(view_a, view_b);

    CHECK_EQ(res.size_delta, 0);
    CHECK_EQ(res.similarity, 1.0);
    REQUIRE_EQ(res.ranges.size(), 1);
    CHECK_EQ(res.ranges[0].kind, "match");
    CHECK_EQ(res.ranges[0].size_a, 5);
}

TEST_CASE("binary diff: detects modified and inserted ranges") {
    std::vector<std::uint8_t> data_a = {0xAA, 0xAA, 0xAA, 0x11, 0x22};
    std::vector<std::uint8_t> data_b = {0xAA, 0xAA, 0xAA, 0x99, 0x88, 0x77};

    auto view_a = BinaryView::from_external(data_a, "a");
    auto view_b = BinaryView::from_external(data_b, "b");

    BinaryDiffEngine engine;
    auto res = engine.compare(view_a, view_b);

    CHECK_EQ(res.size_delta, 1);
    CHECK(res.similarity < 1.0);
    CHECK(res.similarity > 0.0);
    REQUIRE(res.ranges.size() >= 2);
    CHECK_EQ(res.ranges[0].kind, "match");
    CHECK_EQ(res.ranges[0].size_a, 3);
    CHECK_EQ(res.ranges[1].kind, "modified");
}

}  // namespace

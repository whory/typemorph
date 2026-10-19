#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <vector>

using typemorph::core::BinaryView;
using typemorph::core::ByteOrder;
using typemorph::core::ErrorCode;

TEST_CASE("binary view: owned bytes and bounds checked slices") {
    std::vector<std::uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    auto view = BinaryView::from_owned(bytes);
    CHECK(view.valid());
    CHECK_EQ(view.size(), std::size_t{6});
    CHECK_EQ(view.name(), std::string("<memory>"));

    auto slice = view.slice(2, 3);
    REQUIRE(slice.has_value());
    CHECK_EQ(slice.value().size(), std::size_t{3});
    CHECK_EQ(slice.value()[0], std::uint8_t{0x03});

    auto bad = view.slice(5, 2);
    CHECK(!bad.has_value());
    CHECK(bad.error().code == ErrorCode::out_of_range);
    CHECK(!view.slice(100, 1).has_value());
    CHECK(!view.tail(7).has_value());
}

TEST_CASE("binary view: endian aware primitive reads") {
    const std::vector<std::uint8_t> bytes = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                             0xFF, 0xFE};
    auto view = BinaryView::from_owned(bytes);
    CHECK_EQ(view.read_uint(0, 2, ByteOrder::big).value(), std::uint64_t{0x1234});
    CHECK_EQ(view.read_uint(0, 2, ByteOrder::little).value(), std::uint64_t{0x3412});
    CHECK_EQ(view.read_uint(0, 4, ByteOrder::big).value(), std::uint64_t{0x12345678});
    CHECK_EQ(view.read_uint(4, 4, ByteOrder::little).value(), std::uint64_t{0xF0DEBC9A});
    CHECK_EQ(view.read_uint(0, 8, ByteOrder::big).value(),
             std::uint64_t{0x123456789ABCDEF0ULL});

    CHECK_EQ(view.read_int(0, 1).value(), std::int64_t{0x12});
    CHECK_EQ(view.read_int(9, 1).value(), std::int64_t{-2});
    CHECK_EQ(view.read_int(8, 2).value(), std::int64_t{-257});  // 0xFEFF

    CHECK(!view.read_uint(9, 2).has_value());
    CHECK(!view.read_uint(0, 3).has_value());
}

TEST_CASE("binary view: starts_with, copy and external view") {
    const std::vector<std::uint8_t> bytes = {'T', 'M', 'O', 'R', 1, 2};
    auto view = BinaryView::from_external(bytes, "external");
    CHECK_EQ(view.name(), std::string("external"));
    const std::uint8_t magic[] = {'T', 'M', 'O', 'R'};
    CHECK(view.starts_with(std::span<const std::uint8_t>(magic, 4)));
    const std::uint8_t wrong[] = {'N', 'O'};
    CHECK(!view.starts_with(std::span<const std::uint8_t>(wrong, 2)));

    auto copied = view.copy(4, 2);
    REQUIRE(copied.has_value());
    CHECK_EQ(copied.value().size(), std::size_t{2});
    CHECK_EQ(copied.value()[0], std::uint8_t{1});
}

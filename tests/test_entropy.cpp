#include "test_framework.hpp"

#include "typemorph/core/entropy.hpp"

#include <cmath>
#include <cstdint>
#include <vector>

using typemorph::core::block_entropy;
using typemorph::core::entropy_intensity;
using typemorph::core::sliding_entropy;
using typemorph::core::shannon_entropy;

namespace {

std::vector<std::uint8_t> repeated(std::uint8_t value, std::size_t count) {
    return std::vector<std::uint8_t>(count, value);
}

}  // namespace

TEST_CASE("entropy: empty and uniform buffers are zero") {
    CHECK_NEAR(shannon_entropy({}), 0.0, 1e-12);
    const auto uniform = repeated(0x5A, 4096);
    CHECK_NEAR(shannon_entropy(uniform), 0.0, 1e-12);
}

TEST_CASE("entropy: all 256 byte values is eight bits") {
    std::vector<std::uint8_t> bytes(256);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(index);
    }
    CHECK_NEAR(shannon_entropy(bytes), 8.0, 1e-9);
}

TEST_CASE("entropy: two equiprobable symbols is one bit") {
    std::vector<std::uint8_t> bytes;
    for (int index = 0; index < 1024; ++index) {
        bytes.push_back(index % 2 == 0 ? 0xAA : 0x55);
    }
    CHECK_NEAR(shannon_entropy(bytes), 1.0, 1e-9);
}

TEST_CASE("entropy: sliding windows track offsets and values") {
    auto profile = sliding_entropy(repeated(0, 16), 4);
    REQUIRE(profile.has_value());
    CHECK_EQ(profile.value().offsets.size(), std::size_t{4});
    CHECK_EQ(profile.value().offsets[0], std::uint64_t{0});
    CHECK_EQ(profile.value().offsets[3], std::uint64_t{12});
    for (const double value : profile.value().entropy) CHECK_NEAR(value, 0.0, 1e-12);

    auto stride_one = sliding_entropy(repeated(0, 16), 8, 1);
    REQUIRE(stride_one.has_value());
    CHECK_EQ(stride_one.value().entropy.size(), std::size_t{9});
    CHECK_EQ(stride_one.value().stride, std::size_t{1});
}

TEST_CASE("entropy: sliding windows with disjoint strides are exact") {
    std::vector<std::uint8_t> bytes;
    for (int block = 0; block < 4; ++block) {
        for (int index = 0; index < 4; ++index) {
            bytes.push_back(static_cast<std::uint8_t>(block * 4 + index));
        }
    }
    auto profile = sliding_entropy(bytes, 4, 8);
    REQUIRE(profile.has_value());
    CHECK_EQ(profile.value().entropy.size(), std::size_t{2});
    CHECK_NEAR(profile.value().entropy[0], 2.0, 1e-9);
    CHECK_NEAR(profile.value().entropy[1], 2.0, 1e-9);
}

TEST_CASE("entropy: block entropy includes trailing partial block") {
    auto blocks = block_entropy(repeated(0, 10), 4);
    REQUIRE(blocks.has_value());
    CHECK_EQ(blocks.value().size(), std::size_t{3});
    for (const double value : blocks.value()) CHECK_NEAR(value, 0.0, 1e-12);

    auto invalid = block_entropy(repeated(0, 10), 0);
    CHECK(!invalid.has_value());
}

TEST_CASE("entropy: intensity and labels are bounded") {
    CHECK_EQ(entropy_intensity(-5.0), std::uint8_t{0});
    CHECK_EQ(entropy_intensity(0.0), std::uint8_t{0});
    CHECK_EQ(entropy_intensity(8.0), std::uint8_t{255});
    CHECK_EQ(entropy_intensity(100.0), std::uint8_t{255});
    CHECK(std::string(typemorph::core::entropy_label(0.1)) == "zero");
    CHECK(std::string(typemorph::core::entropy_label(7.9)) == "dense");
}

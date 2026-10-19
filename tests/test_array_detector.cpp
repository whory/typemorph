// TypeMorph - ArrayDetector unit tests.
//
// The stride inference function is exercised against exact, noisy and
// contradictory observations; detect() is exercised against synthetic samples
// with a known variable-length array layout.
#include "test_framework.hpp"

#include <cstdint>
#include <utility>
#include <vector>

#include "typemorph/core/binary_view.hpp"
#include "typemorph/infer/array_detector.hpp"

namespace {

using typemorph::core::BinaryView;
using typemorph::infer::ArrayBoundary;
using typemorph::infer::ArrayDetector;
using typemorph::infer::ArrayDetectorOptions;

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

// Layout: 16-byte header (magic, version, count at offset 8, flags) followed by
// `count` records of 12 bytes.
std::vector<std::uint8_t> make_sample(std::uint32_t count, std::uint32_t size_override = 0) {
    const std::size_t size = size_override != 0 ? size_override : 16 + count * 12;
    std::vector<std::uint8_t> bytes(size, 0);
    write_u32(bytes, 0, 0x5452414DU);  // "MART"
    write_u32(bytes, 4, 7);
    write_u32(bytes, 8, count);
    write_u32(bytes, 12, 0x01020304U);
    for (std::uint32_t i = 0; i < count && 16 + static_cast<std::size_t>(i) * 12 + 12 <= size; ++i) {
        const std::size_t base = 16 + static_cast<std::size_t>(i) * 12;
        write_u32(bytes, base + 0, i);
        write_u32(bytes, base + 4, i * 3);
        write_u32(bytes, base + 8, 1000 + i);
    }
    return bytes;
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> observations(
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& pairs) {
    return pairs;
}

}  // namespace

TEST_CASE("array detector: infer_stride recovers exact strides") {
    using Pairs = std::vector<std::pair<std::uint64_t, std::uint64_t>>;

    // size = 76 + 8 * count
    CHECK_EQ(ArrayDetector::infer_stride(observations(Pairs{{3, 100}, {5, 116}, {9, 148}})).value(),
             8ULL);
    // size = 47 + 1 * count
    CHECK_EQ(ArrayDetector::infer_stride(observations(Pairs{{3, 50}, {7, 54}, {11, 58}})).value(),
             1ULL);
    // size = 16 + 12 * count
    CHECK_EQ(ArrayDetector::infer_stride(observations(Pairs{{4, 64}, {6, 88}, {9, 124}})).value(),
             12ULL);
    // Unsorted input is fine.
    CHECK_EQ(ArrayDetector::infer_stride(observations(Pairs{{9, 124}, {4, 64}, {6, 88}})).value(),
             12ULL);
}

TEST_CASE("array detector: infer_stride rejects impossible or noisy data") {
    using Pairs = std::vector<std::pair<std::uint64_t, std::uint64_t>>;

    // Fewer than two observations.
    CHECK(!ArrayDetector::infer_stride(observations(Pairs{{3, 100}})).has_value());
    CHECK(!ArrayDetector::infer_stride(observations(Pairs{})).has_value());

    // Constant count: no size signal exists.
    CHECK(!ArrayDetector::infer_stride(observations(Pairs{{4, 100}, {4, 100}, {4, 100}})).has_value());

    // Same count but different size: contradictory.
    CHECK(!ArrayDetector::infer_stride(observations(Pairs{{3, 100}, {3, 104}, {5, 120}})).has_value());

    // Non-linear noise.
    CHECK(!ArrayDetector::infer_stride(observations(Pairs{{3, 100}, {5, 117}, {9, 151}})).has_value());

    // Negative correlation (size shrinks as count grows).
    CHECK(!ArrayDetector::infer_stride(observations(Pairs{{3, 100}, {5, 84}, {9, 52}})).has_value());
}

TEST_CASE("array detector: detects the variable-length array in synthetic samples") {
    const auto v1 = make_sample(3);
    const auto v2 = make_sample(5);
    const auto v3 = make_sample(8);
    const std::vector<BinaryView> samples = {BinaryView::from_owned(v1, "sample_v1"),
                                             BinaryView::from_owned(v2, "sample_v2"),
                                             BinaryView::from_owned(v3, "sample_v3")};

    ArrayDetectorOptions options;
    options.min_array_elements = 3;
    const ArrayDetector detector(options);
    const auto boundaries = detector.detect(samples);
    REQUIRE(!boundaries.empty());

    const ArrayBoundary& boundary = boundaries.front();
    CHECK_EQ(static_cast<int>(boundary.length_offset), 8);
    CHECK_EQ(static_cast<int>(boundary.length_width), 4);
    CHECK_EQ(static_cast<int>(boundary.data_offset), 16);
    CHECK_EQ(static_cast<int>(boundary.element_size), 12);
    CHECK_EQ(static_cast<int>(boundary.observed_count), 8);
    CHECK(boundary.confidence >= 0.6);
    CHECK(boundary.confidence <= 1.0);
    CHECK(boundary.rationale.find("stride 12") != std::string::npos);

    // The length field is outside the element data.
    CHECK(boundary.length_offset + boundary.length_width <= boundary.data_offset);
}

TEST_CASE("array detector: works with only two samples") {
    const auto v1 = make_sample(3);
    const auto v2 = make_sample(5);
    const std::vector<BinaryView> samples = {BinaryView::from_owned(v1), BinaryView::from_owned(v2)};

    const ArrayDetector detector;
    const auto boundaries = detector.detect(samples);
    REQUIRE(!boundaries.empty());
    CHECK_EQ(static_cast<int>(boundaries.front().element_size), 12);
    CHECK_EQ(static_cast<int>(boundaries.front().data_offset), 16);
}

TEST_CASE("array detector: no false positive without size correlation") {
    // Same total size, different declared counts: the model cannot hold.
    auto v1 = make_sample(3, 52);
    auto v2 = make_sample(5, 52);
    const std::vector<BinaryView> same_size = {BinaryView::from_owned(v1), BinaryView::from_owned(v2)};
    CHECK(ArrayDetector().detect(same_size).empty());

    // Sizes that are not an exact linear function of the count.
    auto noisy1 = make_sample(3);
    auto noisy2 = make_sample(5);
    noisy2.push_back(0);
    const std::vector<BinaryView> noisy = {BinaryView::from_owned(noisy1),
                                           BinaryView::from_owned(noisy2)};
    CHECK(ArrayDetector().detect(noisy).empty());

    // Correlated, but the element stride exceeds the configured ceiling.
    const auto s1 = make_sample(3);
    const auto s2 = make_sample(5);
    const std::vector<BinaryView> real = {BinaryView::from_owned(s1), BinaryView::from_owned(s2)};
    ArrayDetectorOptions tight;
    tight.max_element_size = 8;
    CHECK(ArrayDetector(tight).detect(real).empty());

    // Fewer than two samples: nothing can be correlated.
    const std::vector<BinaryView> single = {BinaryView::from_owned(make_sample(3))};
    CHECK(ArrayDetector().detect(single).empty());
}

TEST_CASE("array detector: invalid samples are rejected cleanly") {
    const std::vector<BinaryView> with_invalid = {BinaryView{}, BinaryView::from_owned(make_sample(3))};
    CHECK(ArrayDetector().detect(with_invalid).empty());

    const std::vector<BinaryView> with_empty = {BinaryView::from_owned(std::vector<std::uint8_t>{}),
                                                BinaryView::from_owned(make_sample(3))};
    CHECK(ArrayDetector().detect(with_empty).empty());
}

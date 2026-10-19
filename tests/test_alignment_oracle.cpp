// TypeMorph - AlignmentOracle unit tests.
//
// All fixtures are synthetic so the suite is fully self-contained.
#include "test_framework.hpp"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

#include "typemorph/core/binary_view.hpp"
#include "typemorph/infer/alignment_oracle.hpp"

namespace {

using typemorph::core::BinaryView;
using typemorph::core::ByteOrder;
using typemorph::core::PrimitiveKind;
using typemorph::infer::AlignmentField;
using typemorph::infer::AlignmentOptions;
using typemorph::infer::AlignmentOracle;

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void write_u64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

std::vector<std::uint8_t> make_word_struct() {
    std::vector<std::uint8_t> bytes(48, 0);
    write_u32(bytes, 0, 0x12345678U);
    write_u32(bytes, 4, 0x9ABCDEF0U);
    write_u32(bytes, 8, 0x01020304U);
    write_u32(bytes, 12, 0xFEDCBA98U);
    // 16..48 is zero padding.
    return bytes;
}

std::vector<std::uint8_t> make_u64_struct() {
    std::vector<std::uint8_t> bytes(40, 0);
    write_u64(bytes, 0, 0x1122334455667788ULL);
    write_u64(bytes, 8, 0x2233445566778899ULL);
    write_u64(bytes, 16, 0x33445566778899AAULL);
    write_u64(bytes, 24, 0x445566778899AABBULL);
    return bytes;
}

}  // namespace

TEST_CASE("alignment oracle: aligned fields outrank unaligned fields") {
    const auto bytes = make_word_struct();
    const BinaryView view = BinaryView::from_owned(bytes);
    const AlignmentOracle oracle(view);

    const double aligned = oracle.score(0, 4);
    const double unaligned = oracle.score(1, 4);
    CHECK(aligned > 0.6);
    CHECK(aligned > unaligned);
    CHECK(unaligned < 0.6);
    CHECK(aligned <= 1.0);
    CHECK(unaligned >= 0.0);

    // A wider hypothesis that spans an internal zero run (padding) is less
    // plausible than the narrow field it is really made of.
    std::vector<std::uint8_t> gapped(16, 0);
    write_u32(gapped, 0, 0x12345678U);
    const BinaryView gapped_view = BinaryView::from_owned(gapped);
    const AlignmentOracle gapped_oracle(gapped_view);
    CHECK(gapped_oracle.score(0, 4) > gapped_oracle.score(0, 8));
}

TEST_CASE("alignment oracle: zero padding and range checks") {
    const auto bytes = make_word_struct();
    const BinaryView view = BinaryView::from_owned(bytes);
    const AlignmentOracle oracle(view);

    const double data_score = oracle.score(0, 4);
    const double padding_score = oracle.score(32, 4);
    CHECK(padding_score < data_score);
    CHECK(padding_score >= 0.0);

    // Out of range hypotheses score zero and never index past the buffer.
    CHECK(oracle.score(view.size() - 2, 4) == 0.0);
    CHECK(oracle.score(view.size(), 1) == 0.0);
    CHECK(oracle.score(0, 16) == 0.0);  // max supported width is 8

    // Width bounds are honoured.
    AlignmentOptions narrow;
    narrow.max_width = 2;
    const AlignmentOracle limited(view, ByteOrder::little, narrow);
    CHECK(limited.score(0, 4) == 0.0);
    CHECK(limited.score(0, 2) > 0.0);
}

TEST_CASE("alignment oracle: classify recognises integers, floats and characters") {
    std::vector<std::uint8_t> bytes(64, 0);
    write_u32(bytes, 0, 1000U);          // plausible integer, not a float
    const std::uint32_t one_bits = 0x3F800000U;  // 1.0f
    write_u32(bytes, 8, one_bits);
    bytes[16] = static_cast<std::uint8_t>('A');
    bytes[17] = static_cast<std::uint8_t>(0x01);
    const BinaryView view = BinaryView::from_owned(bytes);
    const AlignmentOracle oracle(view);

    CHECK_EQ(static_cast<int>(oracle.classify(0, 4)),
             static_cast<int>(PrimitiveKind::u32));
    CHECK_EQ(static_cast<int>(oracle.classify(8, 4)),
             static_cast<int>(PrimitiveKind::f32));
    CHECK_EQ(static_cast<int>(oracle.classify(16, 1)),
             static_cast<int>(PrimitiveKind::character));
    CHECK_EQ(static_cast<int>(oracle.classify(17, 1)),
             static_cast<int>(PrimitiveKind::u8));
}

TEST_CASE("alignment oracle: greedy fields are non-overlapping and deterministic") {
    const auto bytes = make_u64_struct();
    const BinaryView view = BinaryView::from_owned(bytes);
    const AlignmentOracle oracle(view);

    const std::vector<AlignmentField> first = oracle.detect_fields();
    const std::vector<AlignmentField> second = oracle.detect_fields();
    REQUIRE(!first.empty());
    REQUIRE_EQ(first.size(), second.size());

    for (std::size_t i = 0; i < first.size(); ++i) {
        CHECK_EQ(static_cast<int>(first[i].offset), static_cast<int>(second[i].offset));
        CHECK_EQ(static_cast<int>(first[i].width), static_cast<int>(second[i].width));
        CHECK_EQ(static_cast<int>(first[i].kind), static_cast<int>(second[i].kind));
        CHECK(first[i].confidence == second[i].confidence);
        CHECK(first[i].confidence > 0.0);
        CHECK(first[i].confidence <= 1.0);
        CHECK(first[i].width >= 1);
        CHECK(first[i].width <= 8);
        CHECK(first[i].offset + first[i].width <= view.size());
        CHECK(!first[i].rationale.empty());
    }
    // Non-overlapping and produced highest-score-first.
    for (std::size_t i = 0; i < first.size(); ++i) {
        if (i + 1 < first.size()) {
            CHECK(first[i].confidence >= first[i + 1].confidence);
        }
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> intervals;
    for (const auto& field : first) {
        intervals.emplace_back(field.offset, field.offset + field.width);
    }
    std::sort(intervals.begin(), intervals.end());
    for (std::size_t i = 1; i < intervals.size(); ++i) {
        CHECK(intervals[i - 1].second <= intervals[i].first);
    }
}

TEST_CASE("alignment oracle: struct alignment is derived from field offsets") {
    const auto bytes = make_u64_struct();
    const BinaryView view = BinaryView::from_owned(bytes);
    const AlignmentOracle oracle(view);

    const std::uint64_t alignment = oracle.detect_alignment();
    CHECK(alignment == 8 || alignment == 16);
    CHECK(alignment >= 1);
    CHECK(alignment <= 16);

    // Only zero bytes: no structure to infer, alignment falls back to 1.
    const std::vector<std::uint8_t> zeros(64, 0);
    const BinaryView zero_view = BinaryView::from_owned(zeros);
    const AlignmentOracle zero_oracle(zero_view);
    CHECK_EQ(static_cast<int>(zero_oracle.detect_alignment()), 1);

    // Empty views are handled without crashing.
    const BinaryView invalid;
    const AlignmentOracle invalid_oracle(invalid);
    CHECK_EQ(static_cast<int>(invalid_oracle.detect_alignment()), 1);
    CHECK(invalid_oracle.detect_fields().empty());
    CHECK(invalid_oracle.score(0, 4) == 0.0);
}

TEST_CASE("alignment oracle: scan limits bound the field search") {
    const auto bytes = make_word_struct();
    const BinaryView view = BinaryView::from_owned(bytes);
    AlignmentOptions options;
    options.max_scan_bytes = 16;
    const AlignmentOracle oracle(view, ByteOrder::little, options);
    const auto fields = oracle.detect_fields();
    REQUIRE(!fields.empty());
    for (const auto& field : fields) {
        CHECK(field.offset < 16);
        CHECK(field.offset + field.width <= 16);
    }
}

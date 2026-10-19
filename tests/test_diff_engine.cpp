// TypeMorph - DiffEngine unit tests.
//
// The synthetic samples reproduce the committed fixture format (magic, header,
// counted fixed-stride record array, variable-length string table) so the core
// assertions do not depend on the fixture files.  A second test does assert on
// the committed tests/fixtures/sample_v*.bin files when they are present.
#include "test_framework.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/infer/diff_engine.hpp"

namespace {

using typemorph::core::BinaryView;
using typemorph::core::ByteOrder;
using typemorph::core::PrimitiveKind;
using typemorph::core::StructNode;
using typemorph::core::TypeNode;
using typemorph::infer::DiffEngine;
using typemorph::infer::DiffOptions;
using typemorph::infer::EvidenceKind;
using typemorph::infer::InferenceResult;
using typemorph::infer::InferredField;
using typemorph::infer::Sample;

void put_u16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    for (std::size_t i = 0; i < 2; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void put_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void put_u64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

// Fixture-shaped little-endian sample: 20-byte header, `count` 12-byte records,
// then a variable-length trailer of `footer` bytes.
std::vector<std::uint8_t> make_sample(std::uint32_t count, std::uint16_t version,
                                      std::uint64_t timestamp, std::size_t footer) {
    const std::size_t records_offset = 20;
    std::vector<std::uint8_t> bytes(records_offset + count * 12 + footer, 0);
    put_u32(bytes, 0, 0x58534D54U);  // "TMSX"
    put_u16(bytes, 4, version);
    put_u16(bytes, 6, static_cast<std::uint16_t>(2 * version - 1));
    put_u64(bytes, 8, timestamp);
    put_u32(bytes, 16, count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t base = records_offset + static_cast<std::size_t>(i) * 12;
        put_u32(bytes, base + 0, i + 1);
        put_u16(bytes, base + 4, static_cast<std::uint16_t>((3 * i + version) % 4));
        put_u16(bytes, base + 6, 0xABCDU);
        put_u32(bytes, base + 8, 0x1000U + 0x111U * i + 0x40U * version);
    }
    for (std::size_t i = 0; i < footer; ++i) {
        bytes[records_offset + count * 12 + i] =
            static_cast<std::uint8_t>(0xA0U + static_cast<unsigned>(i));
    }
    return bytes;
}

std::vector<Sample> make_samples(std::span<const std::vector<std::uint8_t>> buffers,
                                 const std::vector<std::string>& names) {
    std::vector<Sample> samples;
    samples.reserve(buffers.size());
    for (std::size_t i = 0; i < buffers.size(); ++i) {
        Sample sample;
        sample.view = BinaryView::from_owned(buffers[i], names[i]);
        sample.name = names[i];
        samples.push_back(std::move(sample));
    }
    return samples;
}

[[nodiscard]] const InferredField* find_field(const InferenceResult& result, std::uint64_t offset) {
    for (const auto& field : result.fields) {
        if (field.offset == offset) return &field;
    }
    return nullptr;
}

[[nodiscard]] const typemorph::core::TypeField* find_root_field(const InferenceResult& result,
                                                                std::uint64_t offset) {
    if (!result.root) return nullptr;
    const auto* structure = result.root->get_if<StructNode>();
    if (structure == nullptr) return nullptr;
    for (const auto& field : structure->fields) {
        if (field.offset == offset) return &field;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("diff engine: synthetic multi-sample layout") {
    const std::vector<std::uint8_t> v1 = make_sample(3, 1, 1700000000ULL, 5);
    const std::vector<std::uint8_t> v2 = make_sample(7, 2, 1700003600ULL, 9);
    const std::vector<std::uint8_t> v3 = make_sample(12, 3, 1700007200ULL, 13);
    const std::vector<std::uint8_t> buffers[] = {v1, v2, v3};
    const std::vector<std::string> names = {"v1", "v2", "v3"};
    const std::vector<Sample> samples = make_samples(buffers, names);

    const DiffEngine engine;
    const auto inferred = engine.infer(std::span<const Sample>(samples));
    REQUIRE(inferred.has_value());
    const InferenceResult& result = inferred.value();

    CHECK_EQ(static_cast<int>(result.sample_count), 3);
    CHECK_EQ(result.min_size, 61ULL);
    CHECK_EQ(result.max_size, 177ULL);
    CHECK_EQ(static_cast<int>(result.endian), static_cast<int>(ByteOrder::little));
    CHECK(result.confidence >= 0.8);
    CHECK(result.root != nullptr);

    // Invariant magic at offset 0.
    const InferredField* magic = find_field(result, 0);
    REQUIRE(magic != nullptr);
    CHECK(magic->invariant);
    CHECK_EQ(static_cast<int>(magic->kind), static_cast<int>(PrimitiveKind::u32));

    // Monotonic timestamp at offset 8.
    const InferredField* timestamp = find_field(result, 8);
    REQUIRE(timestamp != nullptr);
    CHECK(timestamp->name == "timestamp");
    CHECK_EQ(static_cast<int>(timestamp->kind), static_cast<int>(PrimitiveKind::u64));
    CHECK(timestamp->confidence >= 0.85);

    // Count field at offset 16, cross-linked with the record array.
    const InferredField* count = find_field(result, 16);
    REQUIRE(count != nullptr);
    CHECK_EQ(static_cast<int>(count->width), 4);
    CHECK_EQ(static_cast<int>(count->kind), static_cast<int>(PrimitiveKind::u32));
    REQUIRE(count->array_element_size.has_value());
    CHECK_EQ(count->array_element_size.value(), 12ULL);
    REQUIRE(count->count_field_offset.has_value());
    CHECK_EQ(count->count_field_offset.value(), 16ULL);
    REQUIRE(count->element_count.has_value());
    CHECK_EQ(count->element_count.value(), 12ULL);

    // Array at offset 20 with a 12-byte record stride.
    const InferredField* array = find_field(result, 20);
    REQUIRE(array != nullptr);
    REQUIRE(array->array_element_size.has_value());
    CHECK_EQ(array->array_element_size.value(), 12ULL);
    REQUIRE(array->count_field_offset.has_value());
    CHECK_EQ(array->count_field_offset.value(), 16ULL);
    CHECK(array->type_name.rfind("array<", 0) == 0);

    const auto* array_type = find_root_field(result, 20);
    REQUIRE(array_type != nullptr);
    const auto* array_node = array_type->type->get_if<typemorph::core::ArrayNode>();
    REQUIRE(array_node != nullptr);
    REQUIRE(array_node->element != nullptr);
    CHECK(array_node->element->is<StructNode>());
    CHECK_EQ(array_node->element_stride, 12ULL);
    CHECK_EQ(array_node->count_expression, "count_10");
    REQUIRE(array_node->count.has_value());
    CHECK_EQ(array_node->count.value(), 12ULL);
    const auto* element = array_node->element->get_if<StructNode>();
    REQUIRE(element != nullptr);
    CHECK(element->fields.size() >= 3);
    CHECK_EQ(array_node->element->size, 12ULL);
    for (const auto& field : element->fields) {
        CHECK(field.offset + (field.type ? field.type->size : 0) <= 12);
    }

    // The variable-length trailer stays opaque after the records.
    const auto* trailer = find_root_field(result, 164);
    REQUIRE(trailer != nullptr);
    CHECK(trailer->type->is<typemorph::core::UnknownNode>());
    CHECK_EQ(trailer->type->size, 13ULL);

    // Structural array evidence plus monotonic sequence evidence.
    bool array_evidence = false;
    bool monotonic_evidence = false;
    for (const auto& evidence : result.evidence) {
        if ((evidence.kind == EvidenceKind::structural_boundary ||
             evidence.kind == EvidenceKind::size_correlation) &&
            evidence.offset == 16) {
            array_evidence = true;
        }
        if (evidence.kind == EvidenceKind::monotonic_sequence && evidence.offset == 8) {
            monotonic_evidence = true;
        }
    }
    CHECK(array_evidence);
    CHECK(monotonic_evidence);

    // Fields are strictly ordered by offset.
    for (std::size_t i = 1; i < result.fields.size(); ++i) {
        CHECK(result.fields[i - 1].offset < result.fields[i].offset);
    }
}

TEST_CASE("diff engine: inference is deterministic") {
    const std::vector<std::uint8_t> v1 = make_sample(3, 1, 1700000000ULL, 5);
    const std::vector<std::uint8_t> v2 = make_sample(7, 2, 1700003600ULL, 9);
    const std::vector<std::uint8_t> v3 = make_sample(12, 3, 1700007200ULL, 13);
    const std::vector<std::uint8_t> buffers[] = {v1, v2, v3};
    const std::vector<std::string> names = {"v1", "v2", "v3"};
    const std::vector<Sample> samples = make_samples(buffers, names);
    const DiffEngine engine;

    const auto first = engine.infer(std::span<const Sample>(samples));
    const auto second = engine.infer(std::span<const Sample>(samples));
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    CHECK(first.value().root->describe() == second.value().root->describe());
    CHECK_EQ(first.value().confidence, second.value().confidence);
    REQUIRE_EQ(first.value().fields.size(), second.value().fields.size());
    for (std::size_t i = 0; i < first.value().fields.size(); ++i) {
        CHECK(first.value().fields[i].name == second.value().fields[i].name);
        CHECK_EQ(first.value().fields[i].offset, second.value().fields[i].offset);
    }
    REQUIRE_EQ(first.value().evidence.size(), second.value().evidence.size());
    for (std::size_t i = 0; i < first.value().evidence.size(); ++i) {
        CHECK_EQ(static_cast<int>(first.value().evidence[i].kind),
                 static_cast<int>(second.value().evidence[i].kind));
        CHECK_EQ(first.value().evidence[i].offset, second.value().evidence[i].offset);
    }
}

TEST_CASE("diff engine: committed fixtures recover count@0x10 and stride-12 records") {
#ifdef TYPEMORPH_TEST_FIXTURES
    const std::filesystem::path fixtures{TYPEMORPH_TEST_FIXTURES};
    const std::filesystem::path paths[3] = {fixtures / "sample_v1.bin", fixtures / "sample_v2.bin",
                                            fixtures / "sample_v3.bin"};
    for (const auto& path : paths) {
        if (!std::filesystem::exists(path)) return;  // fixtures not generated in this checkout
    }
    std::vector<Sample> samples;
    for (const auto& path : paths) {
        const auto view = BinaryView::open(path);
        REQUIRE(view.has_value());
        Sample sample;
        sample.view = view.value();
        sample.name = path.filename().string();
        samples.push_back(std::move(sample));
    }
    const DiffEngine engine;
    const auto inferred = engine.infer(std::span<const Sample>(samples));
    REQUIRE(inferred.has_value());
    const InferenceResult& result = inferred.value();
    CHECK_EQ(static_cast<int>(result.sample_count), 3);
    CHECK_EQ(result.min_size, 73ULL);
    CHECK_EQ(result.max_size, 202ULL);
    CHECK(result.confidence >= 0.85);

    const InferredField* count = find_field(result, 16);
    REQUIRE(count != nullptr);
    CHECK_EQ(static_cast<int>(count->width), 4);
    REQUIRE(count->array_element_size.has_value());
    CHECK_EQ(count->array_element_size.value(), 12ULL);
    REQUIRE(count->count_field_offset.has_value());
    CHECK_EQ(count->count_field_offset.value(), 16ULL);

    const InferredField* array = find_field(result, 20);
    REQUIRE(array != nullptr);
    REQUIRE(array->array_element_size.has_value());
    CHECK_EQ(array->array_element_size.value(), 12ULL);
    REQUIRE(array->element_count.has_value());
    CHECK_EQ(array->element_count.value(), 12ULL);

    const auto* array_type = find_root_field(result, 20);
    REQUIRE(array_type != nullptr);
    const auto* array_node = array_type->type->get_if<typemorph::core::ArrayNode>();
    REQUIRE(array_node != nullptr);
    CHECK(array_node->element->is<StructNode>());
    CHECK_EQ(array_node->element_stride, 12ULL);

    const InferredField* timestamp = find_field(result, 8);
    REQUIRE(timestamp != nullptr);
    CHECK(timestamp->name == "timestamp");
    CHECK_EQ(static_cast<int>(timestamp->kind), static_cast<int>(PrimitiveKind::u64));

    const InferredField* magic = find_field(result, 0);
    REQUIRE(magic != nullptr);
    CHECK(magic->invariant);

    bool array_evidence = false;
    for (const auto& evidence : result.evidence) {
        if ((evidence.kind == EvidenceKind::structural_boundary ||
             evidence.kind == EvidenceKind::size_correlation) &&
            evidence.offset == 16) {
            array_evidence = true;
        }
    }
    CHECK(array_evidence);
#else
    CHECK(true);
#endif
}

TEST_CASE("diff engine: variable-length trailer toy sample") {
    // 8-byte header (magic + count), 8-byte records, arbitrary trailer bytes.
    const auto build = [](std::uint32_t count, std::size_t footer) {
        std::vector<std::uint8_t> bytes(8 + count * 8 + footer, 0xAA);
        put_u32(bytes, 0, 0x58534D54U);
        put_u32(bytes, 4, count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t base = 8 + static_cast<std::size_t>(i) * 8;
            put_u32(bytes, base, i * 7 + 3);
            put_u16(bytes, base + 4, 0xBEEFU);
            put_u16(bytes, base + 6, 0);
        }
        return bytes;
    };
    const std::vector<std::uint8_t> v1 = build(3, 5);
    const std::vector<std::uint8_t> v2 = build(4, 9);
    const std::vector<std::uint8_t> v3 = build(6, 13);
    const std::vector<std::uint8_t> buffers[] = {v1, v2, v3};
    const std::vector<std::string> names = {"toy1", "toy2", "toy3"};
    const std::vector<Sample> samples = make_samples(buffers, names);

    const DiffEngine engine;
    const auto inferred = engine.infer(std::span<const Sample>(samples));
    REQUIRE(inferred.has_value());
    const InferenceResult& result = inferred.value();

    const InferredField* count = find_field(result, 4);
    REQUIRE(count != nullptr);
    REQUIRE(count->array_element_size.has_value());
    CHECK_EQ(count->array_element_size.value(), 8ULL);
    CHECK_EQ(count->count_field_offset.value(), 4ULL);

    const InferredField* array = find_field(result, 8);
    REQUIRE(array != nullptr);
    CHECK_EQ(array->array_element_size.value(), 8ULL);
    REQUIRE(array->element_count.has_value());
    CHECK_EQ(array->element_count.value(), 6ULL);

    const auto* array_type = find_root_field(result, 8);
    REQUIRE(array_type != nullptr);
    const auto* array_node = array_type->type->get_if<typemorph::core::ArrayNode>();
    REQUIRE(array_node != nullptr);
    CHECK(array_node->element->is<StructNode>());

    // 8 + 6*8 = 56, trailer starts there in the reference sample.
    const auto* trailer = find_root_field(result, 56);
    REQUIRE(trailer != nullptr);
    CHECK(trailer->type->is<typemorph::core::UnknownNode>());
    CHECK_EQ(trailer->type->size, 13ULL);
}

TEST_CASE("diff engine: big-endian samples") {
    const auto build = [](std::uint32_t count, std::uint64_t timestamp) {
        std::vector<std::uint8_t> bytes(16 + count * 4, 0);
        put_u32(bytes, 0, 0);  // placeholder, rewritten below big-endian
        bytes[0] = 0x42;
        bytes[1] = 0x49;
        bytes[2] = 0x47;
        bytes[3] = 0x45;
        bytes[4] = 0;
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = static_cast<std::uint8_t>(count);
        for (int i = 0; i < 8; ++i) {
            bytes[8 + i] = static_cast<std::uint8_t>((timestamp >> (56 - 8 * i)) & 0xFFU);
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint32_t value = (i + 1) * 0x01010101U;
            const std::size_t base = 16 + static_cast<std::size_t>(i) * 4;
            bytes[base] = static_cast<std::uint8_t>(value >> 24);
            bytes[base + 1] = static_cast<std::uint8_t>(value >> 16);
            bytes[base + 2] = static_cast<std::uint8_t>(value >> 8);
            bytes[base + 3] = static_cast<std::uint8_t>(value);
        }
        return bytes;
    };
    const std::vector<std::uint8_t> v1 = build(3, 1700000000ULL);
    const std::vector<std::uint8_t> v2 = build(4, 1700003600ULL);
    const std::vector<std::uint8_t> v3 = build(5, 1700007200ULL);
    const std::vector<std::uint8_t> buffers[] = {v1, v2, v3};
    const std::vector<std::string> names = {"be1", "be2", "be3"};
    const std::vector<Sample> samples = make_samples(buffers, names);

    DiffOptions options;
    options.endian = ByteOrder::big;
    const DiffEngine engine(options);
    const auto inferred = engine.infer(std::span<const Sample>(samples));
    REQUIRE(inferred.has_value());
    const InferenceResult& result = inferred.value();
    CHECK_EQ(static_cast<int>(result.endian), static_cast<int>(ByteOrder::big));

    const InferredField* count = find_field(result, 4);
    REQUIRE(count != nullptr);
    REQUIRE(count->array_element_size.has_value());
    CHECK_EQ(count->array_element_size.value(), 4ULL);
    CHECK_EQ(count->count_field_offset.value(), 4ULL);

    const InferredField* array = find_field(result, 16);
    REQUIRE(array != nullptr);
    CHECK_EQ(array->array_element_size.value(), 4ULL);
    REQUIRE(array->element_count.has_value());
    CHECK_EQ(array->element_count.value(), 5ULL);

    const InferredField* timestamp = find_field(result, 8);
    REQUIRE(timestamp != nullptr);
    CHECK(timestamp->name == "timestamp");
}

TEST_CASE("diff engine: single sample is capped but structural") {
    const std::vector<std::uint8_t> buffer = make_sample(2, 1, 1700000000ULL, 3);
    Sample sample;
    sample.view = BinaryView::from_owned(buffer, "single");
    const std::vector<Sample> samples{sample};

    const DiffEngine engine;
    const auto inferred = engine.infer(std::span<const Sample>(samples));
    REQUIRE(inferred.has_value());
    const InferenceResult& result = inferred.value();
    CHECK_EQ(static_cast<int>(result.sample_count), 1);
    CHECK(result.confidence <= 0.55);
    CHECK(result.root != nullptr);
    for (const auto& field : result.fields) {
        CHECK(!field.array_element_size.has_value());
    }
}

TEST_CASE("diff engine: empty and short samples fail cleanly") {
    const DiffEngine engine;

    const std::vector<Sample> none;
    const auto empty_result = engine.infer(std::span<const Sample>(none));
    REQUIRE(!empty_result.has_value());
    CHECK_EQ(static_cast<int>(empty_result.error().code),
             static_cast<int>(typemorph::core::ErrorCode::invalid_argument));

    Sample invalid;
    const std::vector<Sample> invalid_samples{invalid};
    const auto invalid_result = engine.infer(std::span<const Sample>(invalid_samples));
    REQUIRE(!invalid_result.has_value());
    CHECK_EQ(static_cast<int>(invalid_result.error().code),
             static_cast<int>(typemorph::core::ErrorCode::invalid_argument));

    Sample empty_view;
    empty_view.view = BinaryView::from_owned(std::vector<std::uint8_t>{}, "empty");
    const std::vector<Sample> empty_samples{empty_view};
    const auto empty_view_result = engine.infer(std::span<const Sample>(empty_samples));
    REQUIRE(!empty_view_result.has_value());
    CHECK_EQ(static_cast<int>(empty_view_result.error().code),
             static_cast<int>(typemorph::core::ErrorCode::invalid_argument));

    Sample short_view;
    short_view.view = BinaryView::from_owned(std::vector<std::uint8_t>{1, 2}, "short");
    const std::vector<Sample> short_samples{short_view};
    const auto short_result = engine.infer(std::span<const Sample>(short_samples));
    REQUIRE(!short_result.has_value());
    CHECK_EQ(static_cast<int>(short_result.error().code),
             static_cast<int>(typemorph::core::ErrorCode::invalid_argument));

    // The BinaryView span overload validates the same way.
    const std::vector<BinaryView> invalid_views{BinaryView{}};
    const auto view_result = engine.infer(std::span<const BinaryView>(invalid_views));
    REQUIRE(!view_result.has_value());
}

TEST_CASE("diff engine: options are honoured") {
    const std::vector<std::uint8_t> v1 = make_sample(3, 1, 1700000000ULL, 5);
    const std::vector<std::uint8_t> v2 = make_sample(7, 2, 1700003600ULL, 9);
    const std::vector<std::uint8_t> v3 = make_sample(12, 3, 1700007200ULL, 13);
    const std::vector<std::uint8_t> buffers[] = {v1, v2, v3};
    const std::vector<std::string> names = {"v1", "v2", "v3"};
    const std::vector<Sample> samples = make_samples(buffers, names);

    {
        DiffOptions options;
        options.detect_arrays = false;
        const DiffEngine engine(options);
        const auto inferred = engine.infer(std::span<const Sample>(samples));
        REQUIRE(inferred.has_value());
        for (const auto& field : inferred.value().fields) {
            CHECK(!field.array_element_size.has_value());
        }
    }
    {
        DiffOptions options;
        options.detect_timestamps = false;
        const DiffEngine engine(options);
        const auto inferred = engine.infer(std::span<const Sample>(samples));
        REQUIRE(inferred.has_value());
        bool timestamp_field = false;
        for (const auto& field : inferred.value().fields) {
            if (field.name == "timestamp") timestamp_field = true;
        }
        CHECK(!timestamp_field);
    }
    {
        DiffOptions options;
        options.confidence_threshold = 0.995;
        const DiffEngine engine(options);
        const auto inferred = engine.infer(std::span<const Sample>(samples));
        REQUIRE(inferred.has_value());
        for (const auto& field : inferred.value().fields) {
            CHECK(!field.array_element_size.has_value());
        }
    }
    {
        DiffOptions options;
        options.max_fields = 3;
        const DiffEngine engine(options);
        const auto inferred = engine.infer(std::span<const Sample>(samples));
        REQUIRE(inferred.has_value());
        CHECK(inferred.value().fields.size() <= 3);
        const auto* structure = inferred.value().root->get_if<StructNode>();
        REQUIRE(structure != nullptr);
        CHECK(structure->fields.size() <= 3);
    }
}

TEST_CASE("diff engine: supplied sample timestamps identify a clock field") {
    const auto build = [](std::uint32_t value) {
        std::vector<std::uint8_t> bytes(12, 0);
        put_u32(bytes, 0, 0x54494D45U);  // "TIME"
        put_u32(bytes, 4, value);
        put_u32(bytes, 8, 0);
        return bytes;
    };
    const std::vector<std::uint8_t> v1 = build(10);
    const std::vector<std::uint8_t> v2 = build(20);
    const std::vector<std::uint8_t> v3 = build(40);
    const std::vector<std::uint8_t> buffers[] = {v1, v2, v3};
    const std::vector<std::string> names = {"c1", "c2", "c3"};
    std::vector<Sample> samples = make_samples(buffers, names);
    samples[0].timestamp = 1000;
    samples[1].timestamp = 2000;
    samples[2].timestamp = 4000;

    const DiffEngine engine;
    const auto inferred = engine.infer(std::span<const Sample>(samples));
    REQUIRE(inferred.has_value());
    const InferredField* timestamp = find_field(inferred.value(), 4);
    REQUIRE(timestamp != nullptr);
    CHECK(timestamp->name == "timestamp");
    CHECK(timestamp->confidence >= 0.85);
}

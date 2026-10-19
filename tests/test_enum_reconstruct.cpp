// TypeMorph - Rust tagged-union / niche reconstruction tests.
#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/derust/enum_reconstruct.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

using namespace typemorph;
using derust::EnumReconstructor;
using derust::EnumReconstructOptions;
using derust::NicheCandidate;
using derust::NicheKind;
using derust::TaggedUnionCandidate;

#ifndef TYPEMORPH_TEST_FIXTURES
#define TYPEMORPH_TEST_FIXTURES "tests/fixtures"
#endif

namespace {

constexpr std::uint64_t kTextVa = 0x1000;
constexpr std::uint64_t kRodataVa = 0x1100;
constexpr std::uint64_t kDataVa = 0x1300;

constexpr std::size_t kTextOff = 0x000;
constexpr std::size_t kRodataOff = 0x100;
constexpr std::size_t kDataOff = 0x300;
constexpr std::size_t kBufferSize = 0x500;

void put_u16(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint16_t value) {
    for (std::size_t i = 0; i < 2; ++i) {
        buffer[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void put_u32(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        buffer[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void put_u64(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        buffer[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

core::Section make_section(std::string name, std::uint64_t virtual_address, std::uint64_t file_offset,
                           std::uint64_t size, core::SectionFlag flags) {
    core::Section section;
    section.name = std::move(name);
    section.virtual_address = virtual_address;
    section.virtual_size = size;
    section.file_offset = file_offset;
    section.file_size = size;
    section.flags = flags;
    return section;
}

core::ImageParts make_parts(std::vector<core::Section> sections) {
    core::ImageParts parts;
    parts.format = core::ImageFormat::elf;
    parts.bits = 64;
    parts.endian = core::ByteOrder::little;
    parts.entry_point = sections.empty() ? 0 : sections.front().virtual_address;
    parts.sections = std::move(sections);
    return parts;
}

std::vector<core::Section> default_sections64() {
    return {
        make_section(".text", kTextVa, kTextOff, 0x100,
                     core::SectionFlag::executable | core::SectionFlag::code |
                         core::SectionFlag::readable),
        make_section(".rodata", kRodataVa, kRodataOff, 0x200,
                     core::SectionFlag::data | core::SectionFlag::read_only |
                         core::SectionFlag::readable),
        make_section(".data", kDataVa, kDataOff, 0x200,
                     core::SectionFlag::data | core::SectionFlag::writable |
                         core::SectionFlag::readable),
    };
}

core::ExecutableImage make_image(std::vector<std::uint8_t> bytes, core::ImageParts parts) {
    auto view = core::BinaryView::from_owned(std::move(bytes), "<synthetic-enum>");
    return core::ExecutableImage::from_parts(view, std::move(parts));
}

const TaggedUnionCandidate* find_union(const std::vector<TaggedUnionCandidate>& unions,
                                       std::uint64_t offset) {
    for (const auto& candidate : unions) {
        if (candidate.offset == offset) return &candidate;
    }
    return nullptr;
}

const NicheCandidate* find_niche(const std::vector<NicheCandidate>& niches, std::uint64_t offset,
                                 NicheKind kind) {
    for (const auto& candidate : niches) {
        if (candidate.offset == offset && candidate.kind == kind) return &candidate;
    }
    return nullptr;
}

// Builds an image with only a .text and a tiny .rodata section, which keeps the
// scanned range exactly as large as the crafted pattern.
core::ExecutableImage make_minimal_image(std::vector<std::uint8_t> rodata_bytes) {
    const std::size_t rodata_size = rodata_bytes.size();
    std::vector<std::uint8_t> buffer(kTextOff + 0x100 + rodata_size, 0);
    for (std::size_t i = 0; i < rodata_size; ++i) buffer[kRodataOff + i] = rodata_bytes[i];
    std::vector<core::Section> sections = {
        make_section(".text", kTextVa, kTextOff, 0x100,
                     core::SectionFlag::executable | core::SectionFlag::code |
                         core::SectionFlag::readable),
        make_section(".rodata", kRodataVa, kRodataOff, rodata_size,
                     core::SectionFlag::data | core::SectionFlag::read_only |
                         core::SectionFlag::readable),
    };
    return make_image(std::move(buffer), make_parts(std::move(sections)));
}

}  // namespace

TEST_CASE("enum reconstructor: detects a tagged union array with u32 payload") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    const std::uint64_t tags[6] = {0, 1, 2, 0, 1, 2};
    const std::uint32_t payloads[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    for (std::size_t i = 0; i < 6; ++i) {
        const std::size_t offset = kRodataOff + i * 8;
        buffer[offset] = static_cast<std::uint8_t>(tags[i]);
        put_u32(buffer, offset + 4, payloads[i]);
    }
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto unions = reconstructor.scan_tagged_unions(image.view(), &image);
    const TaggedUnionCandidate* candidate = find_union(unions, kRodataOff);
    REQUIRE(candidate != nullptr);
    CHECK_EQ(candidate->tag_width, std::uint8_t{1});
    CHECK_EQ(candidate->payload_offset, std::uint64_t{1});
    REQUIRE_EQ(candidate->variants.size(), std::size_t{3});
    CHECK_EQ(candidate->variants[0].tag, std::uint64_t{0});
    CHECK_EQ(candidate->variants[1].tag, std::uint64_t{1});
    CHECK_EQ(candidate->variants[2].tag, std::uint64_t{2});
    for (const auto& variant : candidate->variants) {
        CHECK_EQ(variant.payload_offset, std::uint64_t{1});
        CHECK_EQ(variant.payload_size, std::uint64_t{7});
        CHECK(!variant.hint.empty());
    }
    CHECK(candidate->confidence > 0.9);
    CHECK(!candidate->rationale.empty());
    CHECK(candidate->rationale.find("stride 8") != std::string::npos);
}

TEST_CASE("enum reconstructor: detects a narrower tag with a small payload window") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    for (std::size_t i = 0; i < 6; ++i) {
        const std::size_t offset = kRodataOff + i * 4;
        put_u16(buffer, offset, static_cast<std::uint16_t>(i % 3));
        put_u16(buffer, offset + 2, static_cast<std::uint16_t>(0x31 + i));
    }
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto unions = reconstructor.scan_tagged_unions(image.view(), &image);
    const TaggedUnionCandidate* candidate = find_union(unions, kRodataOff);
    REQUIRE(candidate != nullptr);
    REQUIRE_EQ(candidate->variants.size(), std::size_t{3});
    CHECK_EQ(candidate->variants[2].tag, std::uint64_t{2});
    CHECK_EQ(candidate->variants[0].payload_size, std::uint64_t{3});
    CHECK(candidate->confidence > 0.8);
}

TEST_CASE("enum reconstructor: tagged union scan is section aware") {
    // The same pattern is placed in the executable .text section.
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    for (std::size_t i = 0; i < 6; ++i) {
        buffer[kTextOff + i * 8] = static_cast<std::uint8_t>(i % 3);
        put_u32(buffer, kTextOff + i * 8 + 4, static_cast<std::uint32_t>(0x40 + i));
    }
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto with_image = reconstructor.scan_tagged_unions(image.view(), &image);
    CHECK(find_union(with_image, kTextOff) == nullptr);

    // Without section metadata the raw view is scanned, so the pattern shows up.
    const auto view_only = reconstructor.scan_tagged_unions(image.view(), nullptr);
    const TaggedUnionCandidate* candidate = find_union(view_only, kTextOff);
    REQUIRE(candidate != nullptr);
    CHECK_EQ(candidate->variants.size(), std::size_t{3});
}

TEST_CASE("enum reconstructor: max_scan_bytes bounds tagged union scanning") {
    std::vector<std::uint8_t> rodata(6 * 8, 0);
    for (std::size_t i = 0; i < 6; ++i) {
        rodata[i * 8] = static_cast<std::uint8_t>(i % 3);
        put_u32(rodata, i * 8 + 4, static_cast<std::uint32_t>(0x50 + i));
    }
    const core::ExecutableImage image = make_minimal_image(rodata);

    EnumReconstructor full;
    const auto full_results = full.scan_tagged_unions(image.view(), &image);
    CHECK(find_union(full_results, kRodataOff) != nullptr);

    EnumReconstructOptions bounded_options;
    bounded_options.max_scan_bytes = 0x10;  // fewer than two entries
    EnumReconstructor bounded(bounded_options);
    const auto bounded_results = bounded.scan_tagged_unions(image.view(), &image);
    CHECK(find_union(bounded_results, kRodataOff) == nullptr);
}

TEST_CASE("enum reconstructor: nullable pointer niche") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    const std::uint64_t words[8] = {kRodataVa, 0, kRodataVa, kRodataVa + 8, 0, kRodataVa + 0x10, 0, 0};
    for (std::size_t i = 0; i < 8; ++i) put_u64(buffer, kDataOff + i * 8, words[i]);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto niches = reconstructor.scan_niches(image.view(), &image);
    const NicheCandidate* candidate = find_niche(niches, kDataOff, NicheKind::nullable_pointer);
    REQUIRE(candidate != nullptr);
    CHECK_EQ(candidate->width, std::uint8_t{8});
    CHECK_EQ(candidate->non_niche_bit_mask, ~std::uint64_t{0});
    CHECK(candidate->confidence > 0.5);
    CHECK(candidate->rationale.find("null") != std::string::npos);
}

TEST_CASE("enum reconstructor: non-zero integer niche") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    const std::uint64_t words[8] = {0, 42, 7, 0, 9, 123, 0, 55};
    for (std::size_t i = 0; i < 8; ++i) put_u64(buffer, kDataOff + i * 8, words[i]);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto niches = reconstructor.scan_niches(image.view(), &image);
    const NicheCandidate* candidate = find_niche(niches, kDataOff, NicheKind::non_zero_integer);
    REQUIRE(candidate != nullptr);
    CHECK_EQ(candidate->width, std::uint8_t{8});
    CHECK(candidate->confidence > 0.5);
    CHECK(candidate->rationale.find("zero") != std::string::npos);
}

TEST_CASE("enum reconstructor: invalid enum value niche") {
    // Exactly dense values 1..3 and nothing after them: an unused encoding space
    // remains available for niche optimisation.
    const core::ExecutableImage image = make_minimal_image({1, 2, 3, 1, 2, 3});
    EnumReconstructor reconstructor;
    const auto niches = reconstructor.scan_niches(image.view(), &image);
    const NicheCandidate* candidate = find_niche(niches, kRodataOff, NicheKind::invalid_enum_value);
    REQUIRE(candidate != nullptr);
    CHECK_EQ(candidate->width, std::uint8_t{1});
    CHECK(candidate->confidence > 0.5);
    CHECK_EQ(candidate->non_niche_bit_mask, std::uint64_t{3});
    CHECK(candidate->rationale.find("unused encodings") != std::string::npos);
}

TEST_CASE("enum reconstructor: pointer alignment hole niche") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    const std::uint64_t words[5] = {kRodataVa + 1, kRodataVa + 3, kRodataVa + 5, kRodataVa + 7,
                                    kRodataVa + 9};
    for (std::size_t i = 0; i < 5; ++i) put_u64(buffer, kRodataOff + i * 8, words[i]);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto niches = reconstructor.scan_niches(image.view(), &image);
    const NicheCandidate* candidate = find_niche(niches, kRodataOff, NicheKind::pointer_alignment_hole);
    REQUIRE(candidate != nullptr);
    CHECK_EQ(candidate->width, std::uint8_t{8});
    CHECK_EQ(candidate->non_niche_bit_mask, ~std::uint64_t{7});
    CHECK(candidate->confidence > 0.5);
}

TEST_CASE("enum reconstructor: niche scan is section aware") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    const std::uint64_t words[8] = {kRodataVa, 0, kRodataVa, kRodataVa + 8, 0, kRodataVa + 0x10, 0, 0};
    for (std::size_t i = 0; i < 8; ++i) put_u64(buffer, kTextOff + i * 8, words[i]);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    EnumReconstructor reconstructor;
    const auto with_image = reconstructor.scan_niches(image.view(), &image);
    CHECK(find_niche(with_image, kTextOff, NicheKind::nullable_pointer) == nullptr);

    const auto view_only = reconstructor.scan_niches(image.view(), nullptr);
    CHECK(find_niche(view_only, kTextOff, NicheKind::nullable_pointer) != nullptr);
}

TEST_CASE("enum reconstructor: hostile metadata and tiny views are safe") {
    // Section claims more bytes than the view actually contains.
    std::vector<std::uint8_t> tiny(0x10, 0);
    std::vector<core::Section> bogus_sections = {
        make_section(".rodata", kRodataVa, 0x8000, 0x200,
                     core::SectionFlag::data | core::SectionFlag::read_only),
    };
    const core::ExecutableImage bogus_image =
        make_image(std::move(tiny), make_parts(std::move(bogus_sections)));
    EnumReconstructor reconstructor;
    const auto unions = reconstructor.scan_tagged_unions(bogus_image.view(), &bogus_image);
    CHECK(unions.empty());
    const auto niches = reconstructor.scan_niches(bogus_image.view(), &bogus_image);
    CHECK(niches.empty());

    // Views shorter than a pointer must not be over-read.
    std::vector<std::uint8_t> two_bytes = {0x01, 0x02};
    const core::BinaryView tiny_view =
        core::BinaryView::from_owned(std::move(two_bytes), "<tiny>");
    CHECK(reconstructor.scan_tagged_unions(tiny_view, nullptr).empty());
    CHECK(reconstructor.scan_niches(tiny_view, nullptr).empty());

    const core::BinaryView empty_view = core::BinaryView::from_owned({}, "<empty>");
    CHECK(reconstructor.scan_tagged_unions(empty_view, nullptr).empty());
    CHECK(reconstructor.scan_niches(empty_view, nullptr).empty());
}

TEST_CASE("enum reconstructor: options are applied") {
    std::vector<std::uint8_t> rodata(4 * 8, 0);
    for (std::size_t i = 0; i < 4; ++i) {
        rodata[i * 8] = static_cast<std::uint8_t>(i);
        put_u32(rodata, i * 8 + 4, static_cast<std::uint32_t>(0x60 + i));
    }
    const core::ExecutableImage image = make_minimal_image(rodata);

    EnumReconstructOptions strict_options;
    strict_options.min_repeated_tags = 8;  // only four entries exist
    EnumReconstructor strict(strict_options);
    CHECK(find_union(strict.scan_tagged_unions(image.view(), &image), kRodataOff) == nullptr);

    EnumReconstructOptions defaults;
    EnumReconstructor defaults_scanner(defaults);
    CHECK(find_union(defaults_scanner.scan_tagged_unions(image.view(), &image), kRodataOff) !=
          nullptr);
    CHECK_EQ(defaults_scanner.options().max_discriminant, std::uint64_t{0xFFFF});
}

#ifdef TYPEMORPH_TEST_FIXTURES
TEST_CASE("enum reconstructor: committed rust_sample.elf fixture is handled safely") {
    const std::filesystem::path path =
        std::filesystem::path(TYPEMORPH_TEST_FIXTURES) / "rust_sample.elf";
    if (!std::filesystem::exists(path)) return;  // fixture is optional for this suite

    const auto view = core::BinaryView::open(path);
    REQUIRE(view.has_value());
    const auto parsed = core::ExecutableImage::parse(view.value());
    REQUIRE(parsed.has_value());
    const core::ExecutableImage& image = parsed.value();

    EnumReconstructor reconstructor;
    const auto unions = reconstructor.scan_tagged_unions(image.view(), &image);
    const auto niches = reconstructor.scan_niches(image.view(), &image);
    CHECK(unions.size() <= 4096);
    CHECK(niches.size() <= 4096);

    // Section awareness: the fixture's .text is file range [0x1000, 0x1060).
    const auto in_code = [](std::uint64_t offset) {
        return offset >= 0x1000 && offset < 0x1060;
    };
    for (const auto& candidate : unions) CHECK(!in_code(candidate.offset));
    for (const auto& candidate : niches) CHECK(!in_code(candidate.offset));
}
#endif

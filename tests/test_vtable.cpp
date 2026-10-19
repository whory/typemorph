// TypeMorph - Rust trait object vtable analyzer tests.
#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/derust/vtable_analyzer.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

using namespace typemorph;
using derust::VTableAnalyzer;
using derust::VTableCandidate;
using derust::VTableOptions;

#ifndef TYPEMORPH_TEST_FIXTURES
#define TYPEMORPH_TEST_FIXTURES "tests/fixtures"
#endif

namespace {

constexpr std::uint64_t kTextVa = 0x1000;
constexpr std::uint64_t kRodataVa = 0x1200;
constexpr std::uint64_t kDataVa = 0x1400;

constexpr std::size_t kTextOff = 0x000;
constexpr std::size_t kRodataOff = 0x100;
constexpr std::size_t kDataOff = 0x300;
constexpr std::size_t kBufferSize = 0x500;

constexpr std::uint64_t kDrop = 0x1000;
constexpr std::uint64_t kMethod0 = 0x1010;
constexpr std::uint64_t kMethod1 = 0x1020;
constexpr std::uint64_t kMethod2 = 0x1030;

void write_bytes(std::vector<std::uint8_t>& buffer, std::size_t offset,
                 std::initializer_list<unsigned> bytes) {
    std::size_t i = 0;
    for (const unsigned value : bytes) {
        buffer[offset + i] = static_cast<std::uint8_t>(value);
        ++i;
    }
}

void fill(std::vector<std::uint8_t>& buffer, std::size_t offset, std::size_t size,
          std::uint8_t value) {
    for (std::size_t i = 0; i < size; ++i) buffer[offset + i] = value;
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

void put_words(std::vector<std::uint8_t>& buffer, std::size_t offset,
               std::initializer_list<std::uint64_t> words) {
    std::size_t i = 0;
    for (const std::uint64_t word : words) {
        put_u64(buffer, offset + i * 8, word);
        ++i;
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

core::ImageParts make_parts(std::vector<core::Section> sections, std::uint16_t bits = 64) {
    core::ImageParts parts;
    parts.format = core::ImageFormat::elf;
    parts.bits = bits;
    parts.endian = core::ByteOrder::little;
    parts.image_base = 0;
    parts.entry_point = sections.empty() ? 0 : sections.front().virtual_address;
    parts.sections = std::move(sections);
    return parts;
}

core::ExecutableImage make_image(std::vector<std::uint8_t> bytes, core::ImageParts parts) {
    auto view = core::BinaryView::from_owned(std::move(bytes), "<synthetic-vtable>");
    return core::ExecutableImage::from_parts(view, std::move(parts));
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

// Fills .text with a NOP sled and writes plausible function prologues at the
// four well-known entry points.
void write_text(std::vector<std::uint8_t>& buffer) {
    fill(buffer, kTextOff, 0x100, 0x90U);
    for (const std::uint64_t address : {kDrop, kMethod0, kMethod1, kMethod2}) {
        const std::size_t offset = kTextOff + static_cast<std::size_t>(address - kTextVa);
        write_bytes(buffer, offset, {0xF3U, 0x0FU, 0x1EU, 0xFAU});  // endbr64
        write_bytes(buffer, offset + 4, {0x55U, 0x48U, 0x89U, 0xE5U});  // push rbp; mov rbp, rsp
    }
}

core::Symbol make_function_symbol(std::string name, std::uint64_t address, bool rust) {
    core::Symbol symbol;
    symbol.name = std::move(name);
    symbol.address = address;
    symbol.size = 0x20;
    symbol.kind = core::SymbolKind::function;
    symbol.rust = rust;
    return symbol;
}

const VTableCandidate* find_table(const std::vector<VTableCandidate>& tables, std::uint64_t address) {
    for (const auto& table : tables) {
        if (table.address == address) return &table;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("vtable analyzer: resolves a Rust trait object vtable") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_text(buffer);
    put_words(buffer, kRodataOff + 0x00, {kDrop, 0x18, 8, kMethod0, kMethod1, 0});

    core::ImageParts parts = make_parts(default_sections64());
    parts.symbols.push_back(
        make_function_symbol("_ZN10rust_crate13drop_in_place17h0123456789abcdefE", kDrop, true));
    parts.symbols.push_back(
        make_function_symbol("_ZN10rust_crate8method_017h0123456789abcdefE", kMethod0, true));
    const core::ExecutableImage image = make_image(std::move(buffer), std::move(parts));

    VTableAnalyzer analyzer;
    const auto results = analyzer.analyze(image);
    REQUIRE(results.has_value());
    REQUIRE_EQ(results.value().size(), std::size_t{1});

    const VTableCandidate& table = results.value().front();
    CHECK_EQ(table.address, kRodataVa);
    CHECK_EQ(table.file_offset, kRodataOff);
    CHECK_EQ(table.drop_in_place, kDrop);
    CHECK_EQ(table.object_size, std::uint64_t{0x18});
    CHECK_EQ(table.object_align, std::uint64_t{8});
    REQUIRE_EQ(table.entries.size(), std::size_t{5});
    CHECK_EQ(table.entries[0].index, std::size_t{0});
    CHECK(table.entries[0].points_to_code);
    CHECK_EQ(table.entries[0].symbol, std::string("rust_crate::drop_in_place"));
    CHECK_EQ(table.entries[1].address, std::uint64_t{0x18});
    CHECK(!table.entries[1].points_to_code);
    CHECK_EQ(table.entries[2].address, std::uint64_t{8});
    CHECK(!table.entries[2].points_to_code);
    CHECK_EQ(table.entries[3].address, kMethod0);
    CHECK_EQ(table.entries[3].file_offset, kRodataOff + 0x18);
    CHECK(table.entries[3].points_to_code);
    CHECK_EQ(table.entries[3].symbol, std::string("rust_crate::method_0"));
    CHECK_EQ(table.entries[4].address, kMethod1);
    CHECK(table.confidence > 0.85);
    CHECK(table.confidence <= 1.0);
    CHECK(table.rationale.find("drop_in_place") != std::string::npos);
    CHECK(table.rationale.find("object_size=24") != std::string::npos);
    CHECK(table.rationale.find("Rust mangled") != std::string::npos);
}

TEST_CASE("vtable analyzer: tolerates a null drop function only in lenient mode") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_text(buffer);
    put_words(buffer, kRodataOff + 0x00, {0, 0x10, 8, kMethod0, kMethod1, 0});
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    VTableAnalyzer strict;
    const auto strict_results = strict.analyze(image);
    REQUIRE(strict_results.has_value());
    CHECK(strict_results.value().empty());

    VTableOptions lenient_options;
    lenient_options.require_drop_function = false;
    VTableAnalyzer lenient(lenient_options);
    const auto lenient_results = lenient.analyze(image);
    REQUIRE(lenient_results.has_value());
    REQUIRE_EQ(lenient_results.value().size(), std::size_t{1});
    const VTableCandidate& table = lenient_results.value().front();
    CHECK_EQ(table.drop_in_place, std::uint64_t{0});
    REQUIRE_EQ(table.entries.size(), std::size_t{5});
    CHECK(!table.entries[0].points_to_code);
    CHECK(table.rationale.find("null drop_in_place") != std::string::npos);
}

TEST_CASE("vtable analyzer: rejects implausible size and alignment headers") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_text(buffer);
    // align is not a power of two
    put_words(buffer, kRodataOff + 0x00, {kDrop, 0x18, 3, kMethod0, kMethod1, 0});
    // size is not a multiple of align
    put_words(buffer, kRodataOff + 0x40, {kDrop, 20, 8, kMethod0, kMethod1, 0});
    // absurd size (larger than any real object)
    put_words(buffer, kRodataOff + 0x80, {kDrop, 0x2000000, 8, kMethod0, kMethod1, 0});
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    VTableAnalyzer analyzer;
    const auto results = analyzer.analyze(image);
    REQUIRE(results.has_value());
    CHECK(results.value().empty());

    // Without the size/align sanity checks the raw layouts are still reported,
    // which keeps the analyzer usable for layout probing.
    VTableOptions raw_options;
    raw_options.require_size_align = false;
    VTableAnalyzer raw(raw_options);
    const auto raw_results = raw.analyze(image);
    REQUIRE(raw_results.has_value());
    REQUIRE_EQ(raw_results.value().size(), std::size_t{3});
    CHECK_EQ(raw_results.value()[0].address, kRodataVa);
    CHECK_EQ(raw_results.value()[1].address, kRodataVa + 0x40);
    CHECK_EQ(raw_results.value()[2].address, kRodataVa + 0x80);
}

TEST_CASE("vtable analyzer: min_methods, max_methods and empty tables") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_text(buffer);
    put_words(buffer, kRodataOff + 0x00, {kDrop, 0x10, 8, kMethod0, kMethod1, kMethod2, 0});
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    VTableAnalyzer analyzer;
    const auto defaults = analyzer.analyze(image);
    REQUIRE(defaults.has_value());
    REQUIRE_EQ(defaults.value().size(), std::size_t{1});
    CHECK_EQ(defaults.value().front().entries.size(), std::size_t{6});

    VTableOptions strict_options;
    strict_options.min_methods = 5;
    VTableAnalyzer strict(strict_options);
    const auto strict_results = strict.analyze(image);
    REQUIRE(strict_results.has_value());
    CHECK(strict_results.value().empty());

    VTableOptions capped_options;
    capped_options.max_methods = 2;
    VTableAnalyzer capped(capped_options);
    const auto capped_results = capped.analyze(image);
    REQUIRE(capped_results.has_value());
    REQUIRE_EQ(capped_results.value().size(), std::size_t{1});
    CHECK_EQ(capped_results.value().front().entries.size(), std::size_t{5});

    // A table without any method pointer is only reported in tolerant mode.
    std::vector<std::uint8_t> empty_buffer(kBufferSize, 0);
    write_text(empty_buffer);
    put_words(empty_buffer, kRodataOff + 0x00, {kDrop, 0x10, 8, 0});
    const core::ExecutableImage empty_image =
        make_image(std::move(empty_buffer), make_parts(default_sections64()));
    VTableAnalyzer empty_default;
    const auto empty_default_results = empty_default.analyze(empty_image);
    REQUIRE(empty_default_results.has_value());
    CHECK(empty_default_results.value().empty());

    VTableOptions no_methods_options;
    no_methods_options.min_methods = 0;
    VTableAnalyzer no_methods(no_methods_options);
    const auto no_methods_results = no_methods.analyze(empty_image);
    REQUIRE(no_methods_results.has_value());
    REQUIRE_EQ(no_methods_results.value().size(), std::size_t{1});
    CHECK_EQ(no_methods_results.value().front().entries.size(), std::size_t{3});
}

TEST_CASE("vtable analyzer: max_scan_bytes bounds the scan") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_text(buffer);
    put_words(buffer, kRodataOff + 0x40, {kDrop, 0x10, 8, kMethod0, 0});
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    VTableAnalyzer analyzer;
    const auto defaults = analyzer.analyze(image);
    REQUIRE(defaults.has_value());
    CHECK_EQ(defaults.value().size(), std::size_t{1});

    VTableOptions small_scan;
    small_scan.max_scan_bytes = 0x20;
    VTableAnalyzer limited(small_scan);
    const auto limited_results = limited.analyze(image);
    REQUIRE(limited_results.has_value());
    CHECK(limited_results.value().empty());
}

TEST_CASE("vtable analyzer: supports 32-bit images") {
    constexpr std::size_t buffer_size = 0x300;
    std::vector<std::uint8_t> buffer(buffer_size, 0);
    fill(buffer, 0x000, 0x100, 0x90U);
    put_u32(buffer, 0x000, 0x1000);
    put_u32(buffer, 0x010, 0x1010);
    write_bytes(buffer, 0x000, {0xF3U, 0x0FU, 0x1EU, 0xFAU});
    write_bytes(buffer, 0x010, {0xF3U, 0x0FU, 0x1EU, 0xFAU});
    put_u32(buffer, 0x100, 0x1000);  // drop
    put_u32(buffer, 0x104, 12);      // size
    put_u32(buffer, 0x108, 4);       // align
    put_u32(buffer, 0x10C, 0x1010);  // method_0
    put_u32(buffer, 0x110, 0);

    std::vector<core::Section> sections = {
        make_section(".text", 0x1000, 0x000, 0x100,
                     core::SectionFlag::executable | core::SectionFlag::code |
                         core::SectionFlag::readable),
        make_section(".rodata", 0x1200, 0x100, 0x100,
                     core::SectionFlag::data | core::SectionFlag::read_only |
                         core::SectionFlag::readable),
    };
    const core::ExecutableImage image =
        make_image(std::move(buffer), make_parts(std::move(sections), 32));
    CHECK_EQ(image.bits(), std::uint16_t{32});

    VTableAnalyzer analyzer;
    const auto results = analyzer.analyze(image);
    REQUIRE(results.has_value());
    REQUIRE_EQ(results.value().size(), std::size_t{1});
    const VTableCandidate& table = results.value().front();
    CHECK_EQ(table.address, std::uint64_t{0x1200});
    CHECK_EQ(table.drop_in_place, std::uint64_t{0x1000});
    CHECK_EQ(table.object_size, std::uint64_t{12});
    CHECK_EQ(table.object_align, std::uint64_t{4});
    REQUIRE_EQ(table.entries.size(), std::size_t{4});
    CHECK_EQ(table.entries[3].address, std::uint64_t{0x1010});
    CHECK(table.entries[3].points_to_code);
}

TEST_CASE("vtable analyzer: function preamble plausibility") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_text(buffer);
    // Non-code fill regions inside .text: int3 padding and zero padding.
    fill(buffer, kTextOff + 0x40, 0x40, 0xCCU);
    fill(buffer, kTextOff + 0x80, 0x40, 0x00U);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    VTableAnalyzer analyzer;
    CHECK(analyzer.looks_like_function_start(image, kDrop));
    CHECK(analyzer.looks_like_function_start(image, kMethod2));
    CHECK(!analyzer.looks_like_function_start(image, 0));                  // null
    CHECK(!analyzer.looks_like_function_start(image, kTextVa + 0x40));     // 0xCC fill
    CHECK(!analyzer.looks_like_function_start(image, kTextVa + 0x80));     // zero fill
    CHECK(!analyzer.looks_like_function_start(image, kRodataVa));          // data, not code
    CHECK(!analyzer.looks_like_function_start(image, 0x9000));             // unmapped
}

TEST_CASE("vtable analyzer: tolerates images without vtables") {
    std::vector<std::uint8_t> buffer(0x100, 0);
    fill(buffer, 0, 0x100, 0x90U);
    std::vector<core::Section> text_only = {
        make_section(".text", kTextVa, 0x000, 0x100,
                     core::SectionFlag::executable | core::SectionFlag::code),
    };
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(std::move(text_only)));
    VTableAnalyzer analyzer;
    const auto results = analyzer.analyze(image);
    REQUIRE(results.has_value());
    CHECK(results.value().empty());

    // Random data in a data section cannot pass the header checks.
    std::vector<std::uint8_t> noise_buffer(kBufferSize, 0);
    fill(noise_buffer, kRodataOff, 0x200, 0x41U);
    fill(noise_buffer, kDataOff, 0x200, 0x42U);
    const core::ExecutableImage noise_image =
        make_image(std::move(noise_buffer), make_parts(default_sections64()));
    const auto noise_results = analyzer.analyze(noise_image);
    REQUIRE(noise_results.has_value());
    CHECK(noise_results.value().empty());

    const core::ExecutableImage empty_image =
        make_image(std::vector<std::uint8_t>{}, make_parts({}));
    const auto empty_results = analyzer.analyze(empty_image);
    REQUIRE(empty_results.has_value());
    CHECK(empty_results.value().empty());
}

#ifdef TYPEMORPH_TEST_FIXTURES
TEST_CASE("vtable analyzer: committed rust_sample.elf fixture") {
    const std::filesystem::path path =
        std::filesystem::path(TYPEMORPH_TEST_FIXTURES) / "rust_sample.elf";
    if (!std::filesystem::exists(path)) return;  // fixture is optional for this suite

    const auto view = core::BinaryView::open(path);
    REQUIRE(view.has_value());
    const auto image = core::ExecutableImage::parse(view.value());
    REQUIRE(image.has_value());

    VTableAnalyzer analyzer;
    const auto results = analyzer.analyze(image.value());
    REQUIRE(results.has_value());
    REQUIRE_EQ(results.value().size(), std::size_t{1});

    const VTableCandidate& table = results.value().front();
    CHECK_EQ(table.address, std::uint64_t{0x403040});
    CHECK_EQ(table.file_offset, std::uint64_t{0x3040});
    CHECK_EQ(table.drop_in_place, std::uint64_t{0x401000});
    CHECK_EQ(table.object_size, std::uint64_t{0x18});
    CHECK_EQ(table.object_align, std::uint64_t{8});
    REQUIRE_EQ(table.entries.size(), std::size_t{5});
    CHECK_EQ(table.entries[0].symbol, std::string("rust_sample_drop_in_place"));
    CHECK_EQ(table.entries[3].address, std::uint64_t{0x401020});
    CHECK_EQ(table.entries[3].symbol, std::string("rust_sample_method_0"));
    CHECK_EQ(table.entries[4].address, std::uint64_t{0x401040});
    CHECK_EQ(table.entries[4].symbol, std::string("rust_sample_method_1"));
    CHECK(table.confidence > 0.9);
    CHECK(analyzer.looks_like_function_start(image.value(), 0x401000));
    CHECK(analyzer.looks_like_function_start(image.value(), 0x401020));
    CHECK(!analyzer.looks_like_function_start(image.value(), 0x403040));
}
#endif

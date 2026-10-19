// TypeMorph - Rust fat-pointer (slice / &str) scanner tests.
#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/derust/slice_scanner.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace typemorph;
using derust::RustString;
using derust::SliceScanner;
using derust::SliceScannerOptions;

// CMake supplies an absolute path; the relative fallback keeps a standalone
// compile working when the macro is not defined.
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

std::string bytes_to_string(std::initializer_list<unsigned> bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (const unsigned value : bytes) out.push_back(static_cast<char>(value));
    return out;
}

void write_bytes(std::vector<std::uint8_t>& buffer, std::size_t offset, std::string_view bytes) {
    for (std::size_t i = 0; i < bytes.size(); ++i) buffer[offset + i] = static_cast<std::uint8_t>(bytes[i]);
}

void write_bytes(std::vector<std::uint8_t>& buffer, std::size_t offset,
                 std::initializer_list<unsigned> bytes) {
    std::size_t i = 0;
    for (const unsigned value : bytes) {
        buffer[offset + i] = static_cast<std::uint8_t>(value);
        ++i;
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
    auto view = core::BinaryView::from_owned(std::move(bytes), "<synthetic-slice>");
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

const RustString* find_slice(const std::vector<RustString>& slices, std::uint64_t data_address,
                             std::uint64_t length) {
    for (const auto& slice : slices) {
        if (slice.data_address == data_address && slice.length == length) return &slice;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("slice scanner: finds UTF-8 fat pointers in data sections") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_bytes(buffer, kRodataOff + 0x00, std::string_view("hello world"));
    write_bytes(buffer, kRodataOff + 0x20, std::string_view("h\xc3\xa9llo"));
    write_bytes(buffer, kRodataOff + 0x40, {0xFFU, 0xFEU});

    // Valid fat pointers.
    put_u64(buffer, kDataOff + 0x00, kRodataVa + 0x00);
    put_u64(buffer, kDataOff + 0x08, 11);
    put_u64(buffer, kDataOff + 0x10, kRodataVa + 0x06);  // "world"
    put_u64(buffer, kDataOff + 0x18, 5);
    put_u64(buffer, kDataOff + 0x20, kRodataVa + 0x20);  // "héllo"
    put_u64(buffer, kDataOff + 0x28, 6);
    // Invalid entries: empty (rejected by default), null pointer, absurd length,
    // invalid UTF-8, hostile pointer, length crossing the section end.
    put_u64(buffer, kDataOff + 0x30, kRodataVa + 0x00);
    put_u64(buffer, kDataOff + 0x38, 0);
    put_u64(buffer, kDataOff + 0x40, 0);
    put_u64(buffer, kDataOff + 0x48, 11);
    put_u64(buffer, kDataOff + 0x50, kRodataVa + 0x00);
    put_u64(buffer, kDataOff + 0x58, 0x200000);
    put_u64(buffer, kDataOff + 0x60, kRodataVa + 0x40);
    put_u64(buffer, kDataOff + 0x68, 2);
    put_u64(buffer, kDataOff + 0x70, 0xFFFFFFFFFFFFFFFFULL);
    put_u64(buffer, kDataOff + 0x78, 1);
    put_u64(buffer, kDataOff + 0x80, kRodataVa + 0x00);
    put_u64(buffer, kDataOff + 0x88, 0x1000);

    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));
    SliceScanner scanner;
    const auto results = scanner.scan(image);
    REQUIRE(results.has_value());
    const auto& slices = results.value();
    REQUIRE_EQ(slices.size(), std::size_t{3});

    const RustString* hello = find_slice(slices, kRodataVa, 11);
    REQUIRE(hello != nullptr);
    CHECK_EQ(hello->pair_address, kDataVa + 0x00);
    CHECK_EQ(hello->pair_file_offset, kDataOff + 0x00);
    CHECK_EQ(hello->data_file_offset, kRodataOff + 0x00);
    CHECK_EQ(hello->value, std::string("hello world"));
    CHECK(hello->confidence > 0.5);
    CHECK(hello->confidence <= 1.0);

    const RustString* world = find_slice(slices, kRodataVa + 0x06, 5);
    REQUIRE(world != nullptr);
    CHECK_EQ(world->value, std::string("world"));
    CHECK_EQ(world->pair_address, kDataVa + 0x10);

    const RustString* accented = find_slice(slices, kRodataVa + 0x20, 6);
    REQUIRE(accented != nullptr);
    CHECK_EQ(accented->value, bytes_to_string({0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F}));

    // Results are ordered by pair address.
    CHECK(slices[0].pair_address < slices[1].pair_address);
    CHECK(slices[1].pair_address < slices[2].pair_address);
}

TEST_CASE("slice scanner: deduplicates repeated fat pointers") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_bytes(buffer, kRodataOff, std::string_view("deduplicated"));
    put_u64(buffer, kDataOff + 0x00, kRodataVa);
    put_u64(buffer, kDataOff + 0x08, 12);
    // Same (pointer, length) pair stored at a second location.
    put_u64(buffer, kDataOff + 0x20, kRodataVa);
    put_u64(buffer, kDataOff + 0x28, 12);
    // A genuinely different sub-slice must survive.
    put_u64(buffer, kDataOff + 0x40, kRodataVa + 6);
    put_u64(buffer, kDataOff + 0x48, 6);

    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));
    SliceScanner scanner;
    const auto results = scanner.scan(image);
    REQUIRE(results.has_value());
    REQUIRE_EQ(results.value().size(), std::size_t{2});
    const RustString* full = find_slice(results.value(), kRodataVa, 12);
    REQUIRE(full != nullptr);
    CHECK_EQ(full->pair_address, kDataVa);  // lowest (and equal-confidence) pair is kept
    CHECK_EQ(full->value, std::string("deduplicated"));
    const RustString* tail = find_slice(results.value(), kRodataVa + 6, 6);
    REQUIRE(tail != nullptr);
    CHECK_EQ(tail->value, std::string("icated"));
}

TEST_CASE("slice scanner: writable sections are optional") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_bytes(buffer, kRodataOff, std::string_view("writable scan"));
    put_u64(buffer, kDataOff + 0x00, kRodataVa);
    put_u64(buffer, kDataOff + 0x08, 13);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    SliceScannerOptions writable_only;
    writable_only.scan_writable_sections = false;
    SliceScanner disabled(writable_only);
    const auto disabled_results = disabled.scan(image);
    REQUIRE(disabled_results.has_value());
    CHECK(disabled_results.value().empty());

    SliceScanner enabled;
    const auto enabled_results = enabled.scan(image);
    REQUIRE(enabled_results.has_value());
    REQUIRE_EQ(enabled_results.value().size(), std::size_t{1});
    CHECK_EQ(enabled_results.value().front().value, std::string("writable scan"));
}

TEST_CASE("slice scanner: supports 32-bit images") {
    constexpr std::size_t buffer_size = 0x300;
    std::vector<std::uint8_t> buffer(buffer_size, 0);
    write_bytes(buffer, 0x100, std::string_view("32-bit slice"));
    put_u32(buffer, 0x200, 0x1100);
    put_u32(buffer, 0x204, 12);
    put_u32(buffer, 0x210, 0x1107);
    put_u32(buffer, 0x214, 5);

    std::vector<core::Section> sections = {
        make_section(".text", 0x1000, 0x000, 0x100,
                     core::SectionFlag::executable | core::SectionFlag::code |
                         core::SectionFlag::readable),
        make_section(".rodata", 0x1100, 0x100, 0x100,
                     core::SectionFlag::data | core::SectionFlag::read_only |
                         core::SectionFlag::readable),
        make_section(".data", 0x1200, 0x200, 0x100,
                     core::SectionFlag::data | core::SectionFlag::writable |
                         core::SectionFlag::readable),
    };
    const core::ExecutableImage image =
        make_image(std::move(buffer), make_parts(std::move(sections), 32));
    CHECK_EQ(image.bits(), std::uint16_t{32});

    SliceScanner scanner;
    const auto results = scanner.scan(image);
    REQUIRE(results.has_value());
    REQUIRE_EQ(results.value().size(), std::size_t{2});
    const RustString* full = find_slice(results.value(), 0x1100, 12);
    REQUIRE(full != nullptr);
    CHECK_EQ(full->pair_address, std::uint64_t{0x1200});
    CHECK_EQ(full->value, std::string("32-bit slice"));
    const RustString* middle = find_slice(results.value(), 0x1107, 5);
    REQUIRE(middle != nullptr);
    CHECK_EQ(middle->value, std::string("slice"));
}

TEST_CASE("slice scanner: hostile lengths and addresses are rejected safely") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_bytes(buffer, kRodataOff, std::string_view("hostile"));
    // Absurd length.
    put_u64(buffer, kDataOff + 0x00, kRodataVa);
    put_u64(buffer, kDataOff + 0x08, 0xFFFFFFFFFFFFFFFFULL);
    // Absurd pointer with wraparound-looking length.
    put_u64(buffer, kDataOff + 0x10, 0xFFFFFFFFFFFFFFFFULL);
    put_u64(buffer, kDataOff + 0x18, 1);
    // Length that would run past the end of the mapped section.
    put_u64(buffer, kDataOff + 0x20, kRodataVa + 0x1F0);
    put_u64(buffer, kDataOff + 0x28, 0x40);
    // Pointer that is not mapped at all.
    put_u64(buffer, kDataOff + 0x30, 0x9000);
    put_u64(buffer, kDataOff + 0x38, 4);
    // Pair data at the very end of a section must not be read past the end.
    put_u64(buffer, kDataOff + 0x1F8, kRodataVa);

    const core::ExecutableImage image =
        make_image(std::move(buffer), make_parts(default_sections64()));
    SliceScanner scanner;
    const auto results = scanner.scan(image);
    REQUIRE(results.has_value());
    CHECK(results.value().empty());

    std::vector<std::uint8_t> tiny(0x10, 0);
    std::vector<core::Section> bogus_sections = {
        make_section(".data", kDataVa, 0x300, 0x200,
                     core::SectionFlag::data | core::SectionFlag::writable),
    };
    const core::ExecutableImage bogus_image =
        make_image(std::move(tiny), make_parts(std::move(bogus_sections)));
    const auto bogus_results = scanner.scan(bogus_image);
    REQUIRE(bogus_results.has_value());
    CHECK(bogus_results.value().empty());
}

TEST_CASE("slice scanner: allow_empty and min_length options") {
    std::vector<std::uint8_t> buffer(kBufferSize, 0);
    write_bytes(buffer, kRodataOff, std::string_view("abcdefghij"));
    put_u64(buffer, kDataOff + 0x00, kRodataVa + 0x00);
    put_u64(buffer, kDataOff + 0x08, 10);
    put_u64(buffer, kDataOff + 0x10, kRodataVa + 0x04);
    put_u64(buffer, kDataOff + 0x18, 6);
    put_u64(buffer, kDataOff + 0x20, kRodataVa + 0x08);
    put_u64(buffer, kDataOff + 0x28, 0);
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(default_sections64()));

    SliceScanner default_scanner;
    const auto defaults = default_scanner.scan(image);
    REQUIRE(defaults.has_value());
    REQUIRE_EQ(defaults.value().size(), std::size_t{2});  // empty slice rejected

    SliceScannerOptions long_only_options;
    long_only_options.min_length = 8;
    SliceScanner long_only(long_only_options);
    const auto long_results = long_only.scan(image);
    REQUIRE(long_results.has_value());
    REQUIRE_EQ(long_results.value().size(), std::size_t{1});
    CHECK_EQ(long_results.value().front().length, std::uint64_t{10});

    SliceScannerOptions empty_options;
    empty_options.allow_empty = true;
    empty_options.min_length = 0;
    SliceScanner empty_scanner(empty_options);
    const auto empty_results = empty_scanner.scan(image);
    REQUIRE(empty_results.has_value());
    REQUIRE_EQ(empty_results.value().size(), std::size_t{3});
    const RustString* empty = find_slice(empty_results.value(), kRodataVa + 0x08, 0);
    REQUIRE(empty != nullptr);
    CHECK(empty->value.empty());
    CHECK(empty->confidence > 0.0);
}

TEST_CASE("slice scanner: accepts images without data sections") {
    std::vector<std::uint8_t> buffer(0x100, 0);
    std::vector<core::Section> text_only = {
        make_section(".text", kTextVa, 0x000, 0x100,
                     core::SectionFlag::executable | core::SectionFlag::code),
    };
    const core::ExecutableImage image = make_image(std::move(buffer), make_parts(std::move(text_only)));
    SliceScanner scanner;
    const auto results = scanner.scan(image);
    REQUIRE(results.has_value());
    CHECK(results.value().empty());

    // Zero-fill (BSS) sections have no file bytes and must be skipped.
    std::vector<std::uint8_t> bss_buffer(0x200, 0);
    std::vector<core::Section> bss_sections = {
        make_section(".bss", kDataVa, 0x100, 0x100,
                     core::SectionFlag::data | core::SectionFlag::writable |
                         core::SectionFlag::zero_fill),
    };
    const core::ExecutableImage bss_image =
        make_image(std::move(bss_buffer), make_parts(std::move(bss_sections)));
    const auto bss_results = scanner.scan(bss_image);
    REQUIRE(bss_results.has_value());
    CHECK(bss_results.value().empty());

    // Completely empty views are fine.
    const core::ExecutableImage empty_image =
        make_image(std::vector<std::uint8_t>{}, make_parts({}));
    const auto empty_results = scanner.scan(empty_image);
    REQUIRE(empty_results.has_value());
    CHECK(empty_results.value().empty());
}

TEST_CASE("slice scanner: valid_utf8 classification") {
    const auto check = [](std::initializer_list<unsigned> bytes, bool expected) {
        const std::string storage = bytes_to_string(bytes);
        const std::span<const std::uint8_t> span(
            reinterpret_cast<const std::uint8_t*>(storage.data()), storage.size());
        CHECK_EQ(SliceScanner::valid_utf8(span), expected);
    };
    check({}, true);
    check({'h', 'e', 'l', 'l', 'o'}, true);
    check({0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F}, true);                  // héllo
    check({0xE4, 0xB8, 0x96, 0xE7, 0x95, 0x8C}, true);                  // 世界
    check({0xF0, 0x9F, 0x98, 0x80}, true);                              // emoji
    check({0x80}, false);                                               // stray continuation
    check({0xC0, 0x80}, false);                                         // overlong
    check({0xE0, 0x80, 0x80}, false);                                   // overlong
    check({0xED, 0xA0, 0x80}, false);                                   // surrogate
    check({0xF4, 0x90, 0x80, 0x80}, false);                             // > U+10FFFF
    check({0xE2, 0x82}, false);                                         // truncated
    check({0xFF}, false);
}

#ifdef TYPEMORPH_TEST_FIXTURES
TEST_CASE("slice scanner: committed rust_sample.elf fixture") {
    const std::filesystem::path path =
        std::filesystem::path(TYPEMORPH_TEST_FIXTURES) / "rust_sample.elf";
    if (!std::filesystem::exists(path)) return;  // fixture is optional for this suite

    const auto view = core::BinaryView::open(path);
    REQUIRE(view.has_value());
    const auto image = core::ExecutableImage::parse(view.value());
    REQUIRE(image.has_value());
    CHECK(image.value().format() == core::ImageFormat::elf);

    SliceScanner scanner;
    const auto results = scanner.scan(image.value());
    REQUIRE(results.has_value());
    const auto& slices = results.value();
    REQUIRE_EQ(slices.size(), std::size_t{3});

    const RustString* hello = find_slice(slices, 0x402000, 26);
    REQUIRE(hello != nullptr);
    CHECK_EQ(hello->pair_address, std::uint64_t{0x403000});
    CHECK_EQ(hello->data_file_offset, std::uint64_t{0x2000});
    CHECK_EQ(hello->value, std::string("hello from rust_sample.elf"));

    const RustString* demo = find_slice(slices, 0x402020, 31);
    REQUIRE(demo != nullptr);
    CHECK_EQ(demo->value, std::string("TypeMorph Rust fat-pointer demo"));

    const RustString* unicode = find_slice(slices, 0x402040, 15);
    REQUIRE(unicode != nullptr);
    CHECK_EQ(unicode->value,
             bytes_to_string({0x67, 0x72, 0xC3, 0xBC, 0xC3, 0x9F, 0x65, 0x2C, 0x20, 0xE4, 0xB8,
                              0x96, 0xE7, 0x95, 0x8C}));

    for (const auto& slice : slices) {
        CHECK(slice.confidence > 0.5);
    }
}
#endif

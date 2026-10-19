// TypeMorph - dependency-free ELF / PE / Mach-O executable introspection.
//
// LIEF is used when it is available, but the analysis engines must also work in
// air-gapped and CI builds.  This header defines the small platform-neutral
// image model that both the built-in parser and the optional LIEF adapter fill.
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::core {

enum class ImageFormat : std::uint8_t { unknown, elf, pe, macho };

[[nodiscard]] constexpr std::string_view to_string(ImageFormat format) noexcept {
    switch (format) {
    case ImageFormat::elf: return "ELF";
    case ImageFormat::pe: return "PE";
    case ImageFormat::macho: return "Mach-O";
    case ImageFormat::unknown: return "unknown";
    }
    return "unknown";
}

enum class SectionFlag : std::uint32_t {
    none = 0,
    readable = 1U << 0U,
    writable = 1U << 1U,
    executable = 1U << 2U,
    code = 1U << 3U,
    data = 1U << 4U,
    read_only = 1U << 5U,
    zero_fill = 1U << 6U,
};

[[nodiscard]] constexpr SectionFlag operator|(SectionFlag a, SectionFlag b) noexcept {
    return static_cast<SectionFlag>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
[[nodiscard]] constexpr SectionFlag operator&(SectionFlag a, SectionFlag b) noexcept {
    return static_cast<SectionFlag>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}
constexpr SectionFlag& operator|=(SectionFlag& a, SectionFlag b) noexcept { return a = a | b; }

[[nodiscard]] constexpr bool has_flag(SectionFlag value, SectionFlag flag) noexcept {
    return static_cast<std::uint32_t>(value & flag) != 0;
}

struct Section {
    std::string name;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    SectionFlag flags = SectionFlag::none;

    [[nodiscard]] bool contains(std::uint64_t address, std::uint64_t length = 1) const noexcept {
        if (address < virtual_address) return false;
        const std::uint64_t delta = address - virtual_address;
        return delta <= virtual_size && length <= virtual_size - delta;
    }
    [[nodiscard]] std::uint64_t end() const noexcept { return virtual_address + virtual_size; }
    [[nodiscard]] bool executable() const noexcept { return has_flag(flags, SectionFlag::executable); }
    [[nodiscard]] bool writable() const noexcept { return has_flag(flags, SectionFlag::writable); }
    [[nodiscard]] bool read_only() const noexcept { return has_flag(flags, SectionFlag::read_only); }
};

enum class SymbolKind : std::uint8_t { unknown, function, object, section, file };

struct Symbol {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    SymbolKind kind = SymbolKind::unknown;
    bool rust = false;
};

struct ImageParts {
    ImageFormat format = ImageFormat::unknown;
    std::uint16_t bits = 64;
    ByteOrder endian = ByteOrder::little;
    std::uint64_t image_base = 0;
    std::uint64_t entry_point = 0;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
};

class ExecutableImage {
public:
    ExecutableImage() = default;

    // Parse an ELF, PE or Mach-O image from a file-backed/in-memory view.  The
    // view is retained (copies share the mapping), so sections remain valid.
    [[nodiscard]] static Result<ExecutableImage> parse(const BinaryView& view);

    // Construct an image from already normalised parts.  Primarily used by unit
    // tests and by the optional LIEF adapter.
    [[nodiscard]] static ExecutableImage from_parts(BinaryView view, ImageParts parts);

    [[nodiscard]] bool valid() const noexcept { return format_ != ImageFormat::unknown; }
    [[nodiscard]] ImageFormat format() const noexcept { return format_; }
    [[nodiscard]] std::uint16_t bits() const noexcept { return bits_; }
    [[nodiscard]] ByteOrder endian() const noexcept { return endian_; }
    [[nodiscard]] std::uint64_t image_base() const noexcept { return image_base_; }
    [[nodiscard]] std::uint64_t entry_point() const noexcept { return entry_point_; }
    [[nodiscard]] const BinaryView& view() const noexcept { return view_; }
    [[nodiscard]] const std::vector<Section>& sections() const noexcept { return sections_; }
    [[nodiscard]] const std::vector<Symbol>& symbols() const noexcept { return symbols_; }

    [[nodiscard]] const Section* find_section(std::string_view name) const noexcept;
    [[nodiscard]] const Section* section_for_address(std::uint64_t address,
                                                     std::uint64_t length = 1) const noexcept;
    [[nodiscard]] bool contains_address(std::uint64_t address) const noexcept;
    [[nodiscard]] bool is_executable_address(std::uint64_t address) const noexcept;

    // Translate a virtual address to a file offset.  BSS / zero-fill ranges are
    // rejected with out_of_range because they have no file bytes.
    [[nodiscard]] Result<std::uint64_t> va_to_offset(std::uint64_t address,
                                                     std::uint64_t length = 1) const;
    [[nodiscard]] Result<std::span<const std::uint8_t>> span_at_va(std::uint64_t address,
                                                                   std::uint64_t length) const;
    [[nodiscard]] Result<std::span<const std::uint8_t>> section_bytes(const Section& section) const;

    [[nodiscard]] std::vector<const Section*> sections_with(SectionFlag required) const;
    [[nodiscard]] std::string format_name() const { return std::string(to_string(format_)); }

private:
    BinaryView view_{};
    ImageFormat format_ = ImageFormat::unknown;
    std::uint16_t bits_ = 0;
    ByteOrder endian_ = ByteOrder::little;
    std::uint64_t image_base_ = 0;
    std::uint64_t entry_point_ = 0;
    std::vector<Section> sections_;
    std::vector<Symbol> symbols_;
};

}  // namespace typemorph::core

// TypeMorph - dependency-free ELF / PE / Mach-O executable image parsing.
//
// The analysis engines must work in air-gapped and CI builds where LIEF and
// friends are unavailable, so this translation unit contains a deliberately
// self-contained parser for the three relevant container formats.  Every read
// is bounds checked against the owning BinaryView and any malformed input is
// reported as a Result error instead of being allowed to produce undefined
// behaviour.  Parsed file offsets are always absolute offsets into the retained
// BinaryView, including when the parsed image is a slice of a fat Mach-O.

#include "typemorph/core/executable.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace typemorph::core {
namespace {

// Hard caps which keep malformed headers from driving pathological allocation
// or iteration counts.  They are far above anything a real image contains.
constexpr std::uint64_t kMaxSections = 1U << 16U;
constexpr std::uint64_t kMaxSymbols = 1U << 20U;
constexpr std::size_t kMaxNameLength = 4096;

[[nodiscard]] bool in_range(std::uint64_t offset, std::uint64_t length,
                            std::uint64_t size) noexcept {
    return offset <= size && length <= size - offset;
}

[[nodiscard]] std::string range_context(std::uint64_t offset, std::uint64_t length,
                                        std::uint64_t size) {
    std::string context;
    context.reserve(64);
    context += "offset=";
    context += std::to_string(offset);
    context += " length=";
    context += std::to_string(length);
    context += " size=";
    context += std::to_string(size);
    return context;
}

[[nodiscard]] Error parse_error(std::string message, std::string context = {}) {
    return make_error(ErrorCode::parse_error, std::move(message), std::move(context));
}

[[nodiscard]] Error unsupported_error(std::string message, std::string context = {}) {
    return make_error(ErrorCode::unsupported, std::move(message), std::move(context));
}

// Bounds-checked scalar read at an absolute offset into the view.
template <typename T>
[[nodiscard]] Result<T> read_at(const BinaryView& view, std::uint64_t offset,
                                ByteOrder order) {
    static_assert(std::is_unsigned_v<T>, "read_at only supports unsigned types");
    if (!in_range(offset, sizeof(T), view.size())) {
        return parse_error("truncated binary image",
                           range_context(offset, sizeof(T), view.size()));
    }
    return static_cast<T>(detail::load_unsigned<T>(view.data() + offset, order));
}

// Convenience helpers over already validated ranges.  Callers must have checked
// the range first; this keeps the parsers readable without hiding unchecked
// reads from the auditing reader.
[[nodiscard]] inline std::uint16_t load16(const std::uint8_t* data, std::uint64_t offset,
                                          ByteOrder order) {
    return detail::load_unsigned<std::uint16_t>(data + offset, order);
}
[[nodiscard]] inline std::uint32_t load32(const std::uint8_t* data, std::uint64_t offset,
                                          ByteOrder order) {
    return detail::load_unsigned<std::uint32_t>(data + offset, order);
}
[[nodiscard]] inline std::uint64_t load64(const std::uint8_t* data, std::uint64_t offset,
                                          ByteOrder order) {
    return detail::load_unsigned<std::uint64_t>(data + offset, order);
}

// Fixed-width, NUL padded name field (ELF / Mach-O names, PE 8-byte names).
[[nodiscard]] std::string_view fixed_name(const std::uint8_t* data,
                                          std::size_t width) noexcept {
    std::size_t length = 0;
    while (length < width && data[length] != 0) ++length;
    return std::string_view(reinterpret_cast<const char*>(data), length);
}

// Reads a NUL terminated string out of a validated string table.  Names longer
// than kMaxNameLength are truncated; a missing terminator simply ends at the
// end of the table.
[[nodiscard]] std::string cstring_at(std::span<const std::uint8_t> table,
                                     std::uint64_t offset) {
    if (offset >= table.size()) return {};
    const char* base = reinterpret_cast<const char*>(table.data());
    const std::size_t start = static_cast<std::size_t>(offset);
    const std::size_t limit = table.size() - start;
    std::size_t length = 0;
    while (length < limit && base[start + length] != '\0') ++length;
    length = std::min(length, kMaxNameLength);
    return std::string(base + start, length);
}

[[nodiscard]] bool is_hex_digit(char value) noexcept {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

// Recognises the common Rust symbol manglings without needing the full demangler
// (which lives in the derust engine): legacy `_ZN...17h<16 hex>E` and v0
// `_R...`, plus the `rust_` / `$LT$` conventions.
[[nodiscard]] bool looks_like_rust_symbol(std::string_view name) noexcept {
    if (name.rfind("_R", 0) == 0) return true;
    if (name.rfind("rust_", 0) == 0) return true;
    if (name.find("$LT$") != std::string_view::npos) return true;
    if (name.rfind("_ZN", 0) == 0 || name.rfind("__ZN", 0) == 0) {
        for (std::size_t i = 0; i + 19U <= name.size(); ++i) {
            if (name.compare(i, 3, "17h") != 0) continue;
            bool hex = true;
            for (std::size_t j = i + 3U; j < i + 19U; ++j) {
                hex = hex && is_hex_digit(name[j]);
            }
            if (hex) return true;
        }
    }
    return false;
}

// Stable de-duplication of symbols (symtab + dynsym / COFF + exports can report
// the same entry twice).  Insertion order is preserved for deterministic output.
void dedupe_symbols(std::vector<Symbol>& symbols) {
    std::set<std::pair<std::string, std::uint64_t>> seen;
    std::vector<Symbol> unique;
    unique.reserve(symbols.size());
    for (auto& symbol : symbols) {
        if (seen.emplace(symbol.name, symbol.address).second) {
            unique.push_back(std::move(symbol));
        }
    }
    symbols = std::move(unique);
}

void add_symbol(std::vector<Symbol>& symbols, std::string name, std::uint64_t address,
                std::uint64_t size, SymbolKind kind) {
    if (name.empty()) return;
    if (symbols.size() >= kMaxSymbols) return;
    Symbol symbol;
    symbol.name = std::move(name);
    symbol.address = address;
    symbol.size = size;
    symbol.kind = kind;
    symbol.rust = looks_like_rust_symbol(symbol.name);
    symbols.push_back(std::move(symbol));
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

constexpr std::uint8_t kElfClass32 = 1;
constexpr std::uint8_t kElfClass64 = 2;
constexpr std::uint8_t kElfDataLsb = 1;
constexpr std::uint8_t kElfDataMsb = 2;

constexpr std::uint32_t kShtNull = 0;
constexpr std::uint32_t kShtProgbits = 1;
constexpr std::uint32_t kShtSymtab = 2;
constexpr std::uint32_t kShtStrtab = 3;
constexpr std::uint32_t kShtNobits = 8;
constexpr std::uint32_t kShtDynsym = 11;

constexpr std::uint64_t kShfWrite = 0x1U;
constexpr std::uint64_t kShfAlloc = 0x2U;
constexpr std::uint64_t kShfExecInstr = 0x4U;

constexpr std::uint8_t kSttObject = 1;
constexpr std::uint8_t kSttFunc = 2;
constexpr std::uint8_t kSttSection = 3;
constexpr std::uint8_t kSttFile = 4;
constexpr std::uint16_t kShnUndef = 0;
constexpr std::uint16_t kShnXindex = 0xFFFFU;

struct ElfSectionHeader {
    std::uint32_t name = 0;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t alignment = 0;
    std::uint64_t entry_size = 0;
};

[[nodiscard]] SectionFlag elf_section_flags(const ElfSectionHeader& header) noexcept {
    SectionFlag flags = SectionFlag::none;
    const bool alloc = (header.flags & kShfAlloc) != 0;
    const bool write = (header.flags & kShfWrite) != 0;
    const bool exec = (header.flags & kShfExecInstr) != 0;
    if (alloc) flags |= SectionFlag::readable;
    if (write) flags |= SectionFlag::writable;
    if (exec) {
        flags |= SectionFlag::executable;
        flags |= SectionFlag::readable;
    }
    if (alloc && !write) flags |= SectionFlag::read_only;
    if (exec) flags |= SectionFlag::code;
    if (alloc && !exec) flags |= SectionFlag::data;
    if (header.type == kShtNobits) flags |= SectionFlag::zero_fill;
    return flags;
}

[[nodiscard]] SymbolKind elf_symbol_kind(std::uint8_t type) noexcept {
    switch (type) {
    case kSttObject: return SymbolKind::object;
    case kSttFunc: return SymbolKind::function;
    case kSttSection: return SymbolKind::section;
    case kSttFile: return SymbolKind::file;
    default: return SymbolKind::unknown;
    }
}

[[nodiscard]] Result<ImageParts> parse_elf(const BinaryView& view) {
    const std::uint64_t size = view.size();
    const std::uint8_t* data = view.data();

    if (size < 16) return parse_error("truncated ELF identification", range_context(0, 16, size));
    const std::uint8_t elf_class = data[4];
    const std::uint8_t elf_data = data[5];
    if (elf_class != kElfClass32 && elf_class != kElfClass64) {
        return unsupported_error("unsupported ELF class", "ei_class=" + std::to_string(elf_class));
    }
    if (elf_data != kElfDataLsb && elf_data != kElfDataMsb) {
        return parse_error("invalid ELF data encoding", "ei_data=" + std::to_string(elf_data));
    }

    const bool is64 = elf_class == kElfClass64;
    const ByteOrder order = elf_data == kElfDataLsb ? ByteOrder::little : ByteOrder::big;
    const std::uint64_t minimum_header = is64 ? 64U : 52U;
    if (!in_range(0, minimum_header, size)) {
        return parse_error("truncated ELF header", range_context(0, minimum_header, size));
    }

    const std::uint64_t entry = is64 ? load64(data, 24, order) : load32(data, 24, order);
    const std::uint64_t program_offset = is64 ? load64(data, 32, order) : load32(data, 28, order);
    const std::uint64_t section_offset = is64 ? load64(data, 40, order) : load32(data, 32, order);
    const std::uint16_t section_entry_size =
        is64 ? load16(data, 58, order) : load16(data, 46, order);
    std::uint64_t section_count = is64 ? load16(data, 60, order) : load16(data, 48, order);
    std::uint64_t string_table_index = is64 ? load16(data, 62, order) : load16(data, 50, order);

    (void)program_offset;  // Program headers are not needed for the neutral model.
    const std::uint64_t expected_section_size = is64 ? 64U : 40U;
    if (section_count != 0 && section_entry_size < expected_section_size) {
        return parse_error("ELF section header entry is too small",
                           "entsize=" + std::to_string(section_entry_size));
    }

    std::vector<ElfSectionHeader> headers;
    if (section_offset != 0) {
        if (!in_range(section_offset, expected_section_size, size)) {
            return parse_error("ELF section header table out of range",
                               range_context(section_offset, expected_section_size, size));
        }
        // Extended numbering: e_shnum == 0 stores the real count in section 0.
        if (section_count == 0) {
            section_count = is64 ? load64(data, static_cast<std::uint64_t>(section_offset) + 32, order)
                                 : load32(data, static_cast<std::uint64_t>(section_offset) + 20, order);
        }
        if (section_count > kMaxSections) {
            return parse_error("ELF section count exceeds sanity limit",
                               "count=" + std::to_string(section_count));
        }
        if (section_count != 0 &&
            (section_entry_size == 0 ||
             section_count > (size - section_offset) / section_entry_size)) {
            return parse_error("ELF section header table out of range",
                               range_context(section_offset, section_count * section_entry_size,
                                             size));
        }
        headers.reserve(static_cast<std::size_t>(section_count));
        for (std::uint64_t i = 0; i < section_count; ++i) {
            const std::uint64_t base = section_offset + i * section_entry_size;
            ElfSectionHeader header;
            header.name = load32(data, base, order);
            header.type = load32(data, base + 4, order);
            if (is64) {
                header.flags = load64(data, base + 8, order);
                header.address = load64(data, base + 16, order);
                header.offset = load64(data, base + 24, order);
                header.size = load64(data, base + 32, order);
                header.link = load32(data, base + 40, order);
                header.info = load32(data, base + 44, order);
                header.alignment = load64(data, base + 48, order);
                header.entry_size = load64(data, base + 56, order);
            } else {
                header.flags = load32(data, base + 8, order);
                header.address = load32(data, base + 12, order);
                header.offset = load32(data, base + 16, order);
                header.size = load32(data, base + 20, order);
                header.link = load32(data, base + 24, order);
                header.info = load32(data, base + 28, order);
                header.alignment = load32(data, base + 32, order);
                header.entry_size = load32(data, base + 36, order);
            }
            headers.push_back(header);
        }
        // Extended numbering: e_shstrndx == SHN_XINDEX stores the index in
        // section 0's sh_link field.
        if (string_table_index == kShnXindex && !headers.empty()) {
            string_table_index = headers[0].link;
        }
    } else if (section_count != 0) {
        return parse_error("ELF declares sections without a section header table");
    }

    // Resolve the section header string table (if any) before naming sections.
    std::span<const std::uint8_t> section_names{};
    if (string_table_index != 0 && section_offset != 0) {
        if (string_table_index >= headers.size()) {
            return parse_error("ELF section name table index out of range",
                               "index=" + std::to_string(string_table_index));
        }
        const ElfSectionHeader& names = headers[static_cast<std::size_t>(string_table_index)];
        if (!in_range(names.offset, names.size, size)) {
            return parse_error("ELF section name table out of range",
                               range_context(names.offset, names.size, size));
        }
        auto slice = view.slice(names.offset, names.size);
        if (!slice) return slice.error();
        section_names = slice.value();
    }

    ImageParts parts;
    parts.format = ImageFormat::elf;
    parts.bits = is64 ? 64 : 32;
    parts.endian = order;
    parts.image_base = 0;  // ELF has no load base; addresses are absolute.
    parts.entry_point = entry;
    parts.sections.reserve(headers.size());

    for (std::size_t i = 0; i < headers.size(); ++i) {
        const ElfSectionHeader& header = headers[i];
        if (header.type == kShtNull) continue;  // Section 0 is a placeholder.

        Section section;
        section.name = cstring_at(section_names, header.name);
        section.virtual_address = header.address;
        section.virtual_size = header.size;
        section.file_offset = header.offset;
        section.flags = elf_section_flags(header);

        const bool zero_fill = header.type == kShtNobits;
        if (zero_fill) {
            // NOBITS sections (.bss, .tbss) occupy no file bytes; their content
            // is zero filled at load time and must never be read from the file.
            section.file_size = 0;
        } else {
            section.file_size = header.size;
            if (section.file_size != 0 && !in_range(header.offset, header.size, size)) {
                return parse_error("ELF section exceeds file bounds",
                                   "section='" + section.name + "' " +
                                       range_context(header.offset, header.size, size));
            }
        }
        parts.sections.push_back(std::move(section));
    }

    // Symbols from .symtab and .dynsym.  Missing or stripped symbol tables are
    // perfectly normal; malformed ones are rejected because the offsets matter.
    for (const auto& header : headers) {
        if (header.type != kShtSymtab && header.type != kShtDynsym) continue;
        if (header.link >= headers.size()) {
            return parse_error("ELF symbol table links to an invalid string table",
                               "sh_link=" + std::to_string(header.link));
        }
        const ElfSectionHeader& strings = headers[header.link];
        if (!in_range(strings.offset, strings.size, size)) {
            return parse_error("ELF symbol string table out of range",
                               range_context(strings.offset, strings.size, size));
        }
        auto string_slice = view.slice(strings.offset, strings.size);
        if (!string_slice) return string_slice.error();
        const std::span<const std::uint8_t> string_table = string_slice.value();

        const std::uint64_t expected = is64 ? 24U : 16U;
        std::uint64_t stride = header.entry_size == 0 ? expected : header.entry_size;
        if (stride < expected) stride = expected;
        if (header.size == 0) continue;
        if (!in_range(header.offset, header.size, size)) {
            return parse_error("ELF symbol table out of range",
                               range_context(header.offset, header.size, size));
        }
        const std::uint64_t count = header.size / stride;
        for (std::uint64_t i = 0; i < count; ++i) {
            const std::uint64_t base = header.offset + i * stride;
            const std::uint32_t name_offset = load32(data, base, order);
            if (name_offset == 0) continue;
            std::string name = cstring_at(string_table, name_offset);
            if (name.empty()) continue;
            const std::uint16_t section_index = load16(data, base + (is64 ? 6 : 14), order);
            if (section_index == kShnUndef) continue;
            const std::uint8_t info = data[base + (is64 ? 4 : 12)];
            const std::uint64_t value = is64 ? load64(data, base + 8, order)
                                             : load32(data, base + 4, order);
            const std::uint64_t symbol_size = is64 ? load64(data, base + 16, order)
                                                   : load32(data, base + 8, order);
            add_symbol(parts.symbols, std::move(name), value, symbol_size,
                       elf_symbol_kind(static_cast<std::uint8_t>(info & 0x0FU)));
        }
    }
    dedupe_symbols(parts.symbols);
    return parts;
}

// ---------------------------------------------------------------------------
// PE / COFF
// ---------------------------------------------------------------------------

constexpr std::uint32_t kPeSectionMemExecute = 0x20000000U;
constexpr std::uint32_t kPeSectionMemRead = 0x40000000U;
constexpr std::uint32_t kPeSectionMemWrite = 0x80000000U;
constexpr std::uint32_t kPeSectionCntCode = 0x00000020U;
constexpr std::uint32_t kPeSectionCntUninitializedData = 0x00000080U;

struct PeSectionInfo {
    std::uint32_t virtual_address = 0;  // RVA
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t characteristics = 0;
};

[[nodiscard]] Result<ImageParts> parse_pe(const BinaryView& view) {
    const std::uint64_t size = view.size();
    const std::uint8_t* data = view.data();
    if (size < 0x40) return parse_error("truncated DOS header", range_context(0, 0x40, size));
    if (data[0] != 'M' || data[1] != 'Z') return parse_error("missing MZ signature");

    const std::uint32_t pe_offset = load32(data, 0x3C, ByteOrder::little);
    if (!in_range(pe_offset, 24, size)) {
        return parse_error("PE header offset out of range", range_context(pe_offset, 24, size));
    }
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' || data[pe_offset + 2] != 0 ||
        data[pe_offset + 3] != 0) {
        return parse_error("missing PE signature");
    }

    const std::uint16_t number_of_sections = load16(data, pe_offset + 6, ByteOrder::little);
    const std::uint32_t symbol_table_offset = load32(data, pe_offset + 12, ByteOrder::little);
    const std::uint32_t number_of_symbols = load32(data, pe_offset + 16, ByteOrder::little);
    const std::uint16_t optional_header_size = load16(data, pe_offset + 20, ByteOrder::little);

    const std::uint64_t optional_offset = static_cast<std::uint64_t>(pe_offset) + 24U;
    if (optional_header_size < 2 || !in_range(optional_offset, optional_header_size, size)) {
        return parse_error("PE optional header out of range",
                           range_context(optional_offset, optional_header_size, size));
    }
    if (optional_header_size < 64) {
        return parse_error("PE optional header is too small",
                           "size=" + std::to_string(optional_header_size));
    }
    const std::uint16_t optional_magic = load16(data, optional_offset, ByteOrder::little);
    if (optional_magic != 0x10BU && optional_magic != 0x20BU) {
        return unsupported_error("unsupported PE optional header magic",
                                 "magic=" + std::to_string(optional_magic));
    }
    const bool pe32plus = optional_magic == 0x20BU;

    const std::uint32_t entry_rva = load32(data, optional_offset + 16, ByteOrder::little);
    const std::uint64_t image_base = pe32plus
                                         ? load64(data, optional_offset + 24, ByteOrder::little)
                                         : load32(data, optional_offset + 28, ByteOrder::little);
    const std::uint32_t size_of_image = load32(data, optional_offset + 56, ByteOrder::little);
    const std::uint32_t size_of_headers = load32(data, optional_offset + 60, ByteOrder::little);
    const std::uint64_t data_directory_offset = optional_offset + (pe32plus ? 112U : 96U);
    const std::uint64_t number_of_directories_offset = optional_offset + (pe32plus ? 108U : 92U);
    std::uint32_t number_of_directories = 0;
    if (optional_header_size >= (pe32plus ? 112U : 96U) &&
        in_range(number_of_directories_offset, 4, size)) {
        number_of_directories = load32(data, number_of_directories_offset, ByteOrder::little);
        number_of_directories = std::min<std::uint32_t>(number_of_directories, 64U);
    }

    if (number_of_sections > kMaxSections) {
        return parse_error("PE section count exceeds sanity limit",
                           "count=" + std::to_string(number_of_sections));
    }
    const std::uint64_t section_table_offset = optional_offset + optional_header_size;
    constexpr std::uint64_t kPeSectionHeaderSize = 40;
    if (number_of_sections != 0 && !in_range(section_table_offset,
                                             static_cast<std::uint64_t>(number_of_sections) *
                                                 kPeSectionHeaderSize,
                                             size)) {
        return parse_error("PE section table out of range",
                           range_context(section_table_offset,
                                         static_cast<std::uint64_t>(number_of_sections) *
                                             kPeSectionHeaderSize,
                                         size));
    }

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = pe32plus ? 64 : 32;
    parts.endian = ByteOrder::little;
    parts.image_base = image_base;
    parts.entry_point = entry_rva == 0 ? 0 : image_base + entry_rva;
    parts.sections.reserve(number_of_sections);

    std::vector<PeSectionInfo> section_info;
    section_info.reserve(number_of_sections);
    for (std::uint16_t i = 0; i < number_of_sections; ++i) {
        const std::uint64_t base = section_table_offset + static_cast<std::uint64_t>(i) * 40U;
        const std::uint32_t virtual_size = load32(data, base + 8, ByteOrder::little);
        const std::uint32_t virtual_address = load32(data, base + 12, ByteOrder::little);
        const std::uint32_t raw_size = load32(data, base + 16, ByteOrder::little);
        const std::uint32_t raw_offset = load32(data, base + 20, ByteOrder::little);
        const std::uint32_t characteristics = load32(data, base + 36, ByteOrder::little);

        if (raw_size != 0 && !in_range(raw_offset, raw_size, size)) {
            return parse_error("PE section raw data out of range",
                               "index=" + std::to_string(i) + " " +
                                   range_context(raw_offset, raw_size, size));
        }

        const bool uninitialized = (characteristics & kPeSectionCntUninitializedData) != 0;
        const bool zero_fill = uninitialized && raw_size == 0;
        const bool executable = (characteristics & kPeSectionMemExecute) != 0 ||
                                (characteristics & kPeSectionCntCode) != 0;
        const bool writable = (characteristics & kPeSectionMemWrite) != 0;
        const bool readable = (characteristics & kPeSectionMemRead) != 0 || !writable;

        SectionFlag flags = SectionFlag::none;
        if (readable) flags |= SectionFlag::readable;
        if (writable) flags |= SectionFlag::writable;
        if (executable) {
            flags |= SectionFlag::executable;
            flags |= SectionFlag::code;
        } else {
            flags |= SectionFlag::data;
        }
        if (readable && !writable) flags |= SectionFlag::read_only;
        if (zero_fill) flags |= SectionFlag::zero_fill;

        Section section;
        section.name = std::string(fixed_name(data + base, 8));
        section.virtual_address = image_base + virtual_address;
        section.virtual_size = virtual_size != 0 ? virtual_size : raw_size;
        section.file_offset = raw_offset;
        section.file_size = zero_fill ? 0 : raw_size;
        section.flags = flags;
        parts.sections.push_back(std::move(section));
        section_info.push_back(PeSectionInfo{virtual_address, virtual_size, raw_size, raw_offset,
                                             characteristics});
    }

    const auto rva_to_offset = [&](std::uint32_t rva) -> std::optional<std::uint64_t> {
        if (rva < size_of_headers && rva < size) return static_cast<std::uint64_t>(rva);
        for (const auto& info : section_info) {
            if (rva < info.virtual_address) continue;
            const std::uint32_t delta = rva - info.virtual_address;
            if (delta < info.raw_size) {
                return static_cast<std::uint64_t>(info.raw_offset) + delta;
            }
        }
        return std::nullopt;
    };

    // COFF symbol table (only present in unstripped / debug images).
    if (symbol_table_offset != 0 && number_of_symbols != 0 &&
        number_of_symbols <= kMaxSymbols) {
        constexpr std::uint64_t kCoffSymbolSize = 18;
        if (!in_range(symbol_table_offset, static_cast<std::uint64_t>(number_of_symbols) *
                                               kCoffSymbolSize,
                      size)) {
            return parse_error("PE COFF symbol table out of range",
                               range_context(symbol_table_offset,
                                             static_cast<std::uint64_t>(number_of_symbols) *
                                                 kCoffSymbolSize,
                                             size));
        }
        const std::uint64_t string_table_offset =
            static_cast<std::uint64_t>(symbol_table_offset) +
            static_cast<std::uint64_t>(number_of_symbols) * kCoffSymbolSize;
        std::uint64_t string_table_size = 0;
        if (in_range(string_table_offset, 4, size)) {
            string_table_size = load32(data, string_table_offset, ByteOrder::little);
            if (string_table_size < 4 ||
                !in_range(string_table_offset, string_table_size, size)) {
                string_table_size = 0;
            }
        }
        std::uint64_t index = 0;
        while (index < number_of_symbols) {
            const std::uint64_t base = static_cast<std::uint64_t>(symbol_table_offset) +
                                       index * kCoffSymbolSize;
            std::string name;
            // COFF name union: when the first four bytes are zero the next four
            // are an offset into the string table, otherwise the name is inline.
            const std::uint32_t first_name_word = load32(data, base, ByteOrder::little);
            if (first_name_word == 0) {
                const std::uint32_t long_name_offset =
                    load32(data, base + 4, ByteOrder::little);
                if (string_table_size != 0 && long_name_offset >= 4 &&
                    long_name_offset < string_table_size) {
                    const std::uint64_t absolute = string_table_offset + long_name_offset;
                    const std::size_t available = static_cast<std::size_t>(size - absolute);
                    const char* text = reinterpret_cast<const char*>(data + absolute);
                    std::size_t length = 0;
                    while (length < available && text[length] != '\0' &&
                           length < kMaxNameLength) {
                        ++length;
                    }
                    name.assign(text, length);
                }
            } else {
                name = std::string(fixed_name(data + base, 8));
            }
            const std::uint32_t value = load32(data, base + 8, ByteOrder::little);
            const std::int16_t section_number =
                static_cast<std::int16_t>(load16(data, base + 12, ByteOrder::little));
            const std::uint16_t type = load16(data, base + 14, ByteOrder::little);
            const std::uint8_t storage_class = data[base + 16];
            const std::uint8_t auxiliary_count = data[base + 17];

            if (!name.empty() && section_number > 0 &&
                static_cast<std::size_t>(section_number) <= section_info.size()) {
                const PeSectionInfo& info =
                    section_info[static_cast<std::size_t>(section_number) - 1];
                SymbolKind kind = SymbolKind::unknown;
                if ((type & 0x20U) != 0 || storage_class == 101U) {
                    kind = SymbolKind::function;
                } else if (storage_class == 2U || storage_class == 3U) {
                    kind = SymbolKind::object;
                }
                if (kind != SymbolKind::unknown) {
                    add_symbol(parts.symbols, std::move(name),
                               image_base + info.virtual_address + value, 0, kind);
                }
            }
            const std::uint64_t advance = static_cast<std::uint64_t>(auxiliary_count) + 1U;
            index += advance;
        }
    }

    // Export directory (data directory index 0) gives named code entry points.
    if (number_of_directories > 0 &&
        optional_header_size >= (pe32plus ? 112U : 96U)) {
        const std::uint32_t export_rva =
            load32(data, data_directory_offset, ByteOrder::little);
        const std::uint32_t export_size =
            load32(data, data_directory_offset + 4, ByteOrder::little);
        if (export_rva != 0 && export_size >= 40) {
            const auto export_offset = rva_to_offset(export_rva);
            if (export_offset && in_range(*export_offset, 40, size)) {
                const std::uint64_t base = *export_offset;
                const std::uint32_t number_of_functions =
                    load32(data, base + 20, ByteOrder::little);
                const std::uint32_t number_of_names =
                    load32(data, base + 24, ByteOrder::little);
                const std::uint32_t functions_rva =
                    load32(data, base + 28, ByteOrder::little);
                const std::uint32_t names_rva = load32(data, base + 32, ByteOrder::little);
                const std::uint32_t ordinals_rva = load32(data, base + 36, ByteOrder::little);
                if (number_of_names <= kMaxSymbols && number_of_functions <= kMaxSymbols &&
                    names_rva != 0 && ordinals_rva != 0 && functions_rva != 0) {
                    const auto names_offset = rva_to_offset(names_rva);
                    const auto ordinals_offset = rva_to_offset(ordinals_rva);
                    const auto functions_offset = rva_to_offset(functions_rva);
                    if (names_offset && ordinals_offset && functions_offset &&
                        in_range(*names_offset,
                                 static_cast<std::uint64_t>(number_of_names) * 4U, size) &&
                        in_range(*ordinals_offset,
                                 static_cast<std::uint64_t>(number_of_names) * 2U, size)) {
                        for (std::uint32_t i = 0; i < number_of_names; ++i) {
                            const std::uint32_t name_rva =
                                load32(data, *names_offset + i * 4U, ByteOrder::little);
                            const std::uint16_t ordinal = load16(
                                data, *ordinals_offset + i * 2U, ByteOrder::little);
                            if (ordinal >= number_of_functions) continue;
                            if (!in_range(*functions_offset,
                                          static_cast<std::uint64_t>(ordinal) * 4U + 4U,
                                          size)) {
                                continue;
                            }
                            const std::uint32_t function_rva = load32(
                                data, *functions_offset + ordinal * 4U, ByteOrder::little);
                            if (function_rva == 0) continue;
                            // Forwarder strings live inside the export directory
                            // range; they are not code addresses.
                            if (function_rva >= export_rva &&
                                function_rva - export_rva < export_size) {
                                continue;
                            }
                            const auto name_offset = rva_to_offset(name_rva);
                            if (!name_offset || *name_offset >= size) continue;
                            const std::size_t available =
                                static_cast<std::size_t>(size - *name_offset);
                            const char* text =
                                reinterpret_cast<const char*>(data + *name_offset);
                            std::size_t length = 0;
                            while (length < available && text[length] != '\0' &&
                                   length < kMaxNameLength) {
                                ++length;
                            }
                            if (length == 0) continue;
                            add_symbol(parts.symbols, std::string(text, length),
                                       image_base + function_rva, 0,
                                       SymbolKind::function);
                        }
                    }
                }
            }
        }
    }

    dedupe_symbols(parts.symbols);
    (void)size_of_image;
    return parts;
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

constexpr std::uint32_t kMachMagic32 = 0xFEEDFACEU;
constexpr std::uint32_t kMachMagic64 = 0xFEEDFACFU;
constexpr std::uint32_t kMachMagicBig32 = 0xCEFAEDFEU;
constexpr std::uint32_t kMachMagicBig64 = 0xCFFAEDFEU;

constexpr std::uint32_t kLcSegment = 0x1U;
constexpr std::uint32_t kLcSymtab = 0x2U;
constexpr std::uint32_t kLcMain = 0x80000028U;
constexpr std::uint32_t kLcSegment64 = 0x19U;

constexpr std::uint8_t kMachSectionZerofill = 0x1U;
constexpr std::uint8_t kMachSectionGbZerofill = 0x0CU;
constexpr std::uint8_t kMachSectionThreadLocalZerofill = 0x12U;

[[nodiscard]] bool mach_section_is_zero_fill(std::uint32_t flags) noexcept {
    const auto type = static_cast<std::uint8_t>(flags & 0xFFU);
    return type == kMachSectionZerofill || type == kMachSectionGbZerofill ||
           type == kMachSectionThreadLocalZerofill;
}

[[nodiscard]] SectionFlag mach_section_flags(std::uint32_t section_flags,
                                             std::uint32_t init_protection,
                                             bool zero_fill) noexcept {
    SectionFlag flags = SectionFlag::none;
    const bool read = (init_protection & 0x1U) != 0 || init_protection == 0;
    const bool write = (init_protection & 0x2U) != 0;
    const bool instructions = (section_flags & 0x80000000U) != 0 ||
                              (section_flags & 0x00000400U) != 0;
    const bool execute = (init_protection & 0x4U) != 0 || instructions;
    if (read || write || execute) flags |= SectionFlag::readable;
    if (write) flags |= SectionFlag::writable;
    if (execute) {
        flags |= SectionFlag::executable;
        flags |= SectionFlag::code;
    } else {
        flags |= SectionFlag::data;
    }
    if (read && !write) flags |= SectionFlag::read_only;
    if (zero_fill) flags |= SectionFlag::zero_fill;
    return flags;
}

struct MachSliceHeader {
    std::uint32_t magic = 0;
    std::uint16_t bits = 64;
    ByteOrder endian = ByteOrder::little;
    std::uint64_t header_size = 32;
};

// Parses a Mach-O header (already positioned at `base`, bounded by `limit`).
// `base`/`limit` are absolute offsets into the retaining view so that a fat
// slice's file offsets remain directly usable against `image.view()`.
[[nodiscard]] Result<ImageParts> parse_macho_slice(const BinaryView& view,
                                                   std::uint64_t base,
                                                   std::uint64_t limit) {
    const std::uint64_t size = view.size();
    const std::uint8_t* data = view.data();
    if (base > size || limit > size || limit < base) {
        return parse_error("invalid Mach-O slice bounds",
                           "base=" + std::to_string(base) +
                               " limit=" + std::to_string(limit) +
                               " size=" + std::to_string(size));
    }
    if (!in_range(base, 4, size)) return parse_error("truncated Mach-O header");
    const std::uint32_t magic_be = detail::load_unsigned<std::uint32_t>(data + base,
                                                                        ByteOrder::big);
    MachSliceHeader slice;
    slice.magic = magic_be;
    switch (magic_be) {
    case kMachMagic32:
        slice.bits = 32;
        slice.endian = ByteOrder::big;
        slice.header_size = 28;
        break;
    case kMachMagic64:
        slice.bits = 64;
        slice.endian = ByteOrder::big;
        slice.header_size = 32;
        break;
    case kMachMagicBig32:
        slice.bits = 32;
        slice.endian = ByteOrder::little;
        slice.header_size = 28;
        break;
    case kMachMagicBig64:
        slice.bits = 64;
        slice.endian = ByteOrder::little;
        slice.header_size = 32;
        break;
    default:
        return unsupported_error("unsupported Mach-O magic", "magic=" + std::to_string(magic_be));
    }
    const ByteOrder order = slice.endian;
    if (base > limit || limit - base < slice.header_size) {
        return parse_error("truncated Mach-O header",
                           range_context(base, slice.header_size, limit));
    }
    if (!in_range(base, slice.header_size, size)) {
        return parse_error("truncated Mach-O header",
                           range_context(base, slice.header_size, size));
    }

    const std::uint32_t number_of_commands = load32(data, base + 16, order);
    const std::uint32_t command_bytes = load32(data, base + 20, order);
    if (number_of_commands > 100000U) {
        return parse_error("Mach-O load command count exceeds sanity limit",
                           "count=" + std::to_string(number_of_commands));
    }
    if (!in_range(base + slice.header_size, command_bytes, size) ||
        base + slice.header_size + command_bytes > limit) {
        return parse_error("Mach-O load commands out of range",
                           range_context(base + slice.header_size, command_bytes, limit - base));
    }

    struct MachSegment {
        std::string name;
        std::uint64_t vm_address = 0;
        std::uint64_t vm_size = 0;
        std::uint64_t file_offset = 0;  // relative to the Mach-O image start
        std::uint64_t file_size = 0;
        std::uint32_t init_protection = 0;
        std::uint32_t number_of_sections = 0;
        bool page_zero = false;
        bool has_sections = false;
    };

    ImageParts parts;
    parts.format = ImageFormat::macho;
    parts.bits = slice.bits;
    parts.endian = order;

    std::vector<MachSegment> segments;
    struct PendingSymbolTable {
        std::uint32_t command_offset = 0;
    };
    std::optional<PendingSymbolTable> symbol_table;
    std::optional<std::uint64_t> entry_off;
    std::uint64_t text_vm_address = 0;
    std::uint64_t text_file_offset = 0;
    bool have_text_segment = false;
    std::vector<Section> real_sections;
    std::vector<bool> real_section_executable;

    std::uint64_t command = base + slice.header_size;
    const std::uint64_t command_limit = base + slice.header_size + command_bytes;
    for (std::uint32_t command_index = 0; command_index < number_of_commands;
         ++command_index) {
        if (!in_range(command, 8, size) || command + 8 > command_limit) {
            return parse_error("truncated Mach-O load command",
                               range_context(command, 8, command_limit));
        }
        const std::uint32_t cmd = load32(data, command, order);
        const std::uint32_t cmd_size = load32(data, command + 4, order);
        if (cmd_size < 8 || command + cmd_size > command_limit) {
            return parse_error("invalid Mach-O load command size",
                               "cmd=" + std::to_string(cmd) + " size=" +
                                   std::to_string(cmd_size));
        }

        if (cmd == kLcSegment || cmd == kLcSegment64) {
            const bool is64 = cmd == kLcSegment64;
            const std::uint64_t fixed = is64 ? 72U : 56U;
            const std::uint64_t section_size = is64 ? 80U : 68U;
            if (cmd_size < fixed) {
                return parse_error("truncated Mach-O segment command",
                                   "cmd_size=" + std::to_string(cmd_size));
            }
            MachSegment segment;
            segment.name = std::string(fixed_name(data + command + 8, 16));
            if (is64) {
                segment.vm_address = load64(data, command + 24, order);
                segment.vm_size = load64(data, command + 32, order);
                segment.file_offset = load64(data, command + 40, order);
                segment.file_size = load64(data, command + 48, order);
                segment.init_protection = load32(data, command + 60, order);
                segment.number_of_sections = load32(data, command + 64, order);
            } else {
                segment.vm_address = load32(data, command + 24, order);
                segment.vm_size = load32(data, command + 28, order);
                segment.file_offset = load32(data, command + 32, order);
                segment.file_size = load32(data, command + 36, order);
                segment.init_protection = load32(data, command + 44, order);
                segment.number_of_sections = load32(data, command + 48, order);
            }
            if (segment.number_of_sections > kMaxSections ||
                cmd_size < fixed + static_cast<std::uint64_t>(segment.number_of_sections) *
                                         section_size) {
                return parse_error("invalid Mach-O segment section count",
                                   "segment='" + segment.name + "' count=" +
                                       std::to_string(segment.number_of_sections));
            }
            segment.page_zero = segment.name == "__PAGEZERO";
            segment.has_sections = segment.number_of_sections != 0;
            // Every load-command file offset is relative to the Mach-O image
            // start; validate it as an absolute range without overflowing.
            if (segment.file_offset > size - base) {
                return parse_error("Mach-O segment file offset out of range",
                                   "segment='" + segment.name + "' offset=" +
                                       std::to_string(segment.file_offset));
            }
            if (segment.file_size != 0 &&
                !in_range(base + segment.file_offset, segment.file_size, size)) {
                return parse_error("Mach-O segment exceeds file bounds",
                                   "segment='" + segment.name + "' " +
                                       range_context(base + segment.file_offset,
                                                     segment.file_size, size));
            }
            if (segment.file_size != 0 && base + segment.file_offset > limit) {
                return parse_error("Mach-O segment exceeds slice bounds",
                                   "segment='" + segment.name + "'");
            }

            for (std::uint32_t section_index = 0; section_index < segment.number_of_sections;
                 ++section_index) {
                const std::uint64_t section_base =
                    command + fixed + static_cast<std::uint64_t>(section_index) * section_size;
                Section section;
                section.name = std::string(fixed_name(data + section_base, 16));
                std::uint32_t section_flags = 0;
                if (is64) {
                    section.virtual_address = load64(data, section_base + 32, order);
                    section.virtual_size = load64(data, section_base + 40, order);
                    section.file_offset = load32(data, section_base + 48, order);
                    section_flags = load32(data, section_base + 64, order);
                } else {
                    section.virtual_address = load32(data, section_base + 32, order);
                    section.virtual_size = load32(data, section_base + 36, order);
                    section.file_offset = load32(data, section_base + 40, order);
                    section_flags = load32(data, section_base + 56, order);
                }
                const bool zero_fill = mach_section_is_zero_fill(section_flags);
                section.flags =
                    mach_section_flags(section_flags, segment.init_protection, zero_fill);
                // Section file offsets are relative to the Mach-O image start.
                section.file_offset = base + section.file_offset;
                if (zero_fill) {
                    section.file_size = 0;
                } else {
                    section.file_size = section.virtual_size;
                    if (section.file_size != 0 &&
                        !in_range(section.file_offset, section.file_size, size)) {
                        return parse_error("Mach-O section exceeds file bounds",
                                           "section='" + section.name + "' " +
                                               range_context(section.file_offset,
                                                             section.file_size, size));
                    }
                }
                real_section_executable.push_back(
                    has_flag(section.flags, SectionFlag::executable));
                real_sections.push_back(std::move(section));
            }
            if (segment.name == "__TEXT" && !have_text_segment) {
                have_text_segment = true;
                text_vm_address = segment.vm_address;
                text_file_offset = segment.file_offset;
            }
            segments.push_back(std::move(segment));
        } else if (cmd == kLcSymtab) {
            if (cmd_size < 24) {
                return parse_error("truncated Mach-O LC_SYMTAB command");
            }
            symbol_table = PendingSymbolTable{static_cast<std::uint32_t>(command)};
        } else if (cmd == kLcMain) {
            if (cmd_size < 24) {
                return parse_error("truncated Mach-O LC_MAIN command");
            }
            entry_off = load64(data, command + 8, order);
        }
        command += cmd_size;
    }

    // Build the section list: real sections first (so symbol n_sect indices line
    // up), then segment regions which contain no sections of their own (for
    // example __LINKEDIT).
    parts.sections = std::move(real_sections);
    for (const auto& segment : segments) {
        if (segment.has_sections || segment.page_zero) continue;
        if (segment.file_size == 0 && segment.vm_size == 0) continue;
        Section section;
        section.name = segment.name;
        section.virtual_address = segment.vm_address;
        section.virtual_size = segment.vm_size;
        section.file_offset = base + segment.file_offset;
        section.file_size = segment.file_size;
        section.flags = mach_section_flags(0, segment.init_protection, false);
        parts.sections.push_back(std::move(section));
    }

    // Image base: the text segment when present, otherwise the lowest mapped
    // segment address (page zero excluded).
    if (have_text_segment) {
        parts.image_base = text_vm_address;
    } else {
        bool found = false;
        for (const auto& segment : segments) {
            if (segment.page_zero) continue;
            if (!found || segment.vm_address < parts.image_base) {
                parts.image_base = segment.vm_address;
                found = true;
            }
        }
    }

    if (entry_off) {
        if (have_text_segment &&
            *entry_off >= text_file_offset) {
            parts.entry_point = text_vm_address + (*entry_off - text_file_offset);
        } else if (have_text_segment) {
            parts.entry_point = text_vm_address + *entry_off;
        } else {
            parts.entry_point = parts.image_base + *entry_off;
        }
    }

    // nlist symbols.
    if (symbol_table) {
        const std::uint64_t symtab_command = symbol_table->command_offset;
        const std::uint32_t symbol_offset =
            load32(data, symtab_command + 8, order);
        const std::uint32_t symbol_count = load32(data, symtab_command + 12, order);
        const std::uint32_t string_offset =
            load32(data, symtab_command + 16, order);
        const std::uint32_t string_size = load32(data, symtab_command + 20, order);
        const std::uint64_t nlist_size = slice.bits == 64 ? 16U : 12U;
        const std::uint64_t symbol_absolute = base + symbol_offset;
        const std::uint64_t string_absolute = base + string_offset;
        if (symbol_count > kMaxSymbols) {
            return parse_error("Mach-O symbol count exceeds sanity limit");
        }
        if (symbol_count != 0 &&
            !in_range(symbol_absolute,
                      static_cast<std::uint64_t>(symbol_count) * nlist_size, size)) {
            return parse_error("Mach-O symbol table out of range",
                               range_context(symbol_absolute,
                                             static_cast<std::uint64_t>(symbol_count) *
                                                 nlist_size,
                                             size));
        }
        std::span<const std::uint8_t> string_table{};
        if (string_size != 0) {
            if (!in_range(string_absolute, string_size, size)) {
                return parse_error("Mach-O string table out of range",
                                   range_context(string_absolute, string_size, size));
            }
            auto slice_view = view.slice(string_absolute, string_size);
            if (!slice_view) return slice_view.error();
            string_table = slice_view.value();
        }
        for (std::uint32_t i = 0; i < symbol_count; ++i) {
            const std::uint64_t entry = symbol_absolute + i * nlist_size;
            const std::uint32_t name_offset = load32(data, entry, order);
            const std::uint8_t type = data[entry + 4];
            const std::uint8_t section_index = data[entry + 5];
            if ((type & 0xE0U) != 0) continue;  // Debug/stab entry.
            if ((type & 0x0EU) == 0) continue;  // Undefined.
            const std::uint64_t value = slice.bits == 64
                                            ? load64(data, entry + 8, order)
                                            : load32(data, entry + 8, order);
            std::string name = cstring_at(string_table, name_offset);
            if (name.empty()) continue;
            SymbolKind kind = SymbolKind::unknown;
            if (section_index >= 1 && section_index <= real_section_executable.size()) {
                kind = real_section_executable[section_index - 1] ? SymbolKind::function
                                                                  : SymbolKind::object;
            } else if ((type & 0x0EU) == 0x2U) {
                kind = SymbolKind::object;  // N_ABS
            }
            add_symbol(parts.symbols, std::move(name), value, 0, kind);
        }
    }

    dedupe_symbols(parts.symbols);
    return parts;
}

[[nodiscard]] Result<ImageParts> parse_macho_fat(const BinaryView& view,
                                                 std::uint32_t magic_be) {
    const std::uint64_t size = view.size();
    const std::uint8_t* data = view.data();
    const bool fat64 = magic_be == 0xCAFEBABFU || magic_be == 0xBFBAFECAU;
    const bool big_endian_header = magic_be == 0xCAFEBABEU || magic_be == 0xCAFEBABFU;
    const ByteOrder order = big_endian_header ? ByteOrder::big : ByteOrder::little;
    if (size < 8) return parse_error("truncated Mach-O fat header");
    const std::uint32_t slice_count = load32(data, 4, order);
    if (slice_count == 0 || slice_count > 128U) {
        return parse_error("invalid Mach-O fat slice count",
                           "count=" + std::to_string(slice_count));
    }
    const std::uint64_t arch_size = fat64 ? 32U : 20U;
    if (!in_range(8, static_cast<std::uint64_t>(slice_count) * arch_size, size)) {
        return parse_error("Mach-O fat architecture table out of range");
    }
    std::optional<Error> first_error;
    for (std::uint32_t i = 0; i < slice_count; ++i) {
        const std::uint64_t entry = 8 + static_cast<std::uint64_t>(i) * arch_size;
        std::uint64_t slice_offset = 0;
        std::uint64_t slice_size = 0;
        if (fat64) {
            slice_offset = load64(data, entry + 8, order);
            slice_size = load64(data, entry + 16, order);
        } else {
            slice_offset = load32(data, entry + 8, order);
            slice_size = load32(data, entry + 12, order);
        }
        if (!in_range(slice_offset, slice_size, size)) {
            continue;  // Pick the first slice which is actually usable.
        }
        auto parsed = parse_macho_slice(view, slice_offset, slice_offset + slice_size);
        if (parsed) return parsed;
        if (!first_error) first_error = std::move(parsed).error();
    }
    if (first_error) {
        return unsupported_error("no supported Mach-O slice in fat binary",
                                 first_error->to_string());
    }
    return unsupported_error("no supported Mach-O slice in fat binary");
}

// ---------------------------------------------------------------------------
// Entry point helpers shared by the class implementation.
// ---------------------------------------------------------------------------

[[nodiscard]] Result<ImageParts> parse_image(const BinaryView& view) {
    const std::uint64_t size = view.size();
    const std::uint8_t* data = view.data();
    if (size < 4) {
        return unsupported_error("input is too small to be a recognised executable",
                                 "size=" + std::to_string(size));
    }
    if (data[0] == 0x7FU && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        return parse_elf(view);
    }
    if (data[0] == 'M' && data[1] == 'Z') {
        return parse_pe(view);
    }
    const std::uint32_t magic_be = detail::load_unsigned<std::uint32_t>(data, ByteOrder::big);
    switch (magic_be) {
    case kMachMagic32:
    case kMachMagic64:
    case kMachMagicBig32:
    case kMachMagicBig64:
        return parse_macho_slice(view, 0, size);
    case 0xCAFEBABEU:
    case 0xBEBAFECAU:
    case 0xCAFEBABFU:
    case 0xBFBAFECAU:
        return parse_macho_fat(view, magic_be);
    default:
        break;
    }
    return unsupported_error("unrecognised executable format");
}

}  // namespace

// ---------------------------------------------------------------------------
// ExecutableImage
// ---------------------------------------------------------------------------

Result<ExecutableImage> ExecutableImage::parse(const BinaryView& view) {
    if (!view.valid()) {
        return make_error(ErrorCode::invalid_argument,
                          "cannot parse an invalid binary view");
    }
    auto parts = parse_image(view);
    if (!parts) return parts.error();
    return ExecutableImage::from_parts(view, std::move(parts).value());
}

ExecutableImage ExecutableImage::from_parts(BinaryView view, ImageParts parts) {
    ExecutableImage image;
    image.view_ = std::move(view);
    image.format_ = parts.format;
    image.bits_ = parts.bits != 0 ? parts.bits
                                  : (parts.format == ImageFormat::unknown ? 0U : 64U);
    image.endian_ = parts.endian;
    image.image_base_ = parts.image_base;
    image.entry_point_ = parts.entry_point;
    image.sections_ = std::move(parts.sections);
    image.symbols_ = std::move(parts.symbols);
    return image;
}

const Section* ExecutableImage::find_section(std::string_view name) const noexcept {
    for (const auto& section : sections_) {
        if (section.name == name) return &section;
    }
    return nullptr;
}

const Section* ExecutableImage::section_for_address(std::uint64_t address,
                                                    std::uint64_t length) const noexcept {
    for (const auto& section : sections_) {
        if (section.contains(address, length)) return &section;
    }
    return nullptr;
}

bool ExecutableImage::contains_address(std::uint64_t address) const noexcept {
    return section_for_address(address) != nullptr;
}

bool ExecutableImage::is_executable_address(std::uint64_t address) const noexcept {
    const Section* section = section_for_address(address);
    return section != nullptr && section->executable();
}

Result<std::uint64_t> ExecutableImage::va_to_offset(std::uint64_t address,
                                                    std::uint64_t length) const {
    bool virtually_mapped = false;
    for (const auto& section : sections_) {
        if (address < section.virtual_address) continue;
        const std::uint64_t delta = address - section.virtual_address;
        const bool contains = length == 0 ? delta <= section.virtual_size
                                          : (delta <= section.virtual_size &&
                                             length <= section.virtual_size - delta);
        if (!contains) continue;
        virtually_mapped = true;
        if (has_flag(section.flags, SectionFlag::zero_fill)) continue;
        if (section.file_size == 0) continue;
        if (delta <= section.file_size && length <= section.file_size - delta) {
            return section.file_offset + delta;
        }
    }
    if (virtually_mapped) {
        return make_error(ErrorCode::out_of_range,
                          "virtual address has no file-backed bytes (BSS / zero-fill region)",
                          "address=" + std::to_string(address) +
                              " length=" + std::to_string(length));
    }
    return make_error(ErrorCode::out_of_range, "virtual address is not mapped by any section",
                      "address=" + std::to_string(address) +
                          " length=" + std::to_string(length));
}

Result<std::span<const std::uint8_t>> ExecutableImage::span_at_va(
    std::uint64_t address, std::uint64_t length) const {
    auto offset = va_to_offset(address, length);
    if (!offset) return offset.error();
    return view_.slice(offset.value(), length);
}

Result<std::span<const std::uint8_t>> ExecutableImage::section_bytes(
    const Section& section) const {
    if (has_flag(section.flags, SectionFlag::zero_fill) || section.file_size == 0) {
        return make_error(ErrorCode::out_of_range,
                          "section has no file-backed bytes (BSS / zero-fill)",
                          "section='" + section.name + "'");
    }
    return view_.slice(section.file_offset, section.file_size);
}

std::vector<const Section*> ExecutableImage::sections_with(SectionFlag required) const {
    std::vector<const Section*> result;
    if (required == SectionFlag::none) {
        result.reserve(sections_.size());
        for (const auto& section : sections_) result.push_back(&section);
        return result;
    }
    for (const auto& section : sections_) {
        if (has_flag(section.flags, required)) result.push_back(&section);
    }
    return result;
}

}  // namespace typemorph::core

// TypeMorph - unit tests for ELF / PE / Mach-O parsing, section queries and
// virtual-address translation.
//
// The parser tests deliberately use hand-built in-memory images so that every
// supported container variant (ELF32/ELF64, PE32/PE32+, Mach-O 32/64, fat
// binaries) and every malformed-input rejection path is exercised without
// needing cross-compilers on the build machine.  The committed rust_sample.elf
// fixture then covers the end-to-end path used by the Rust recovery engines.

#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef TYPEMORPH_TEST_FIXTURES
#define TYPEMORPH_TEST_FIXTURES "tests/fixtures"
#endif

using typemorph::core::BinaryView;
using typemorph::core::ByteOrder;
using typemorph::core::ErrorCode;
using typemorph::core::ExecutableImage;
using typemorph::core::ImageFormat;
using typemorph::core::ImageParts;
using typemorph::core::Section;
using typemorph::core::SectionFlag;
using typemorph::core::Symbol;
using typemorph::core::SymbolKind;

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr ByteOrder kLittle = ByteOrder::little;
constexpr ByteOrder kBig = ByteOrder::big;

void put(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width,
         ByteOrder order = kLittle) {
    for (std::size_t i = 0; i < width; ++i) {
        const std::size_t shift = order == kLittle ? i * 8U : (width - 1U - i) * 8U;
        bytes[offset + i] = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

void put_bytes(Bytes& bytes, std::size_t offset, std::string_view text) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(text[i]);
    }
}

[[nodiscard]] std::optional<ExecutableImage> try_parse(const Bytes& bytes) {
    const BinaryView view = BinaryView::from_owned(bytes);
    auto image = ExecutableImage::parse(view);
    if (!image) return std::nullopt;
    return std::move(image).value();
}

[[nodiscard]] ErrorCode parse_error_code(const Bytes& bytes) {
    const BinaryView view = BinaryView::from_owned(bytes);
    auto image = ExecutableImage::parse(view);
    if (image) return ErrorCode::none;
    return image.error().code;
}

[[nodiscard]] const Section* find_section(const ExecutableImage& image,
                                          std::string_view name) {
    for (const auto& section : image.sections()) {
        if (section.name == name) return &section;
    }
    return nullptr;
}

[[nodiscard]] const Symbol* find_symbol(const ExecutableImage& image,
                                        std::string_view name) {
    for (const auto& symbol : image.symbols()) {
        if (symbol.name == name) return &symbol;
    }
    return nullptr;
}

[[nodiscard]] std::uint64_t read_u64(std::span<const std::uint8_t> bytes,
                                     std::size_t offset, ByteOrder order = kLittle) {
    std::uint64_t value = 0;
    if (order == kLittle) {
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8U);
        }
    } else {
        for (std::size_t i = 0; i < 8; ++i) {
            value = (value << 8U) | static_cast<std::uint64_t>(bytes[offset + i]);
        }
    }
    return value;
}

[[nodiscard]] bool bytes_equal(std::span<const std::uint8_t> bytes,
                               std::string_view expected) {
    if (bytes.size() != expected.size()) return false;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] != static_cast<std::uint8_t>(expected[i])) return false;
    }
    return true;
}

[[nodiscard]] ErrorCode translation_error(const ExecutableImage& image,
                                          std::uint64_t address,
                                          std::uint64_t length = 1) {
    auto result = image.va_to_offset(address, length);
    return result.has_value() ? ErrorCode::none : result.error().code;
}

// ---------------------------------------------------------------------------
// Hand-built ELF images
// ---------------------------------------------------------------------------

/// Minimal ELF32 with .text, an optional NOBITS .bss and a section-name table.
/// `big_endian` selects a big-endian image so the parser's byte order handling
/// is covered.  Section header table lives at file offset 0x200.
[[nodiscard]] Bytes make_elf32(bool big_endian, bool with_bss) {
    const ByteOrder order = big_endian ? kBig : kLittle;
    constexpr std::uint32_t kSectionTableOffset = 0x200;
    constexpr std::uint16_t kSectionHeaderSize = 40;
    const std::uint16_t section_count = with_bss ? 4 : 3;
    Bytes bytes(kSectionTableOffset + static_cast<std::size_t>(section_count) * 40, 0);

    // e_ident
    bytes[0] = 0x7F;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 1;                              // ELFCLASS32
    bytes[5] = big_endian ? 2 : 1;             // ELFDATA2MSB / ELFDATA2LSB
    bytes[6] = 1;                              // EV_CURRENT
    put(bytes, 16, 2, 2, order);               // e_type = ET_EXEC
    put(bytes, 18, 3, 2, order);               // e_machine = EM_386
    put(bytes, 20, 1, 4, order);               // e_version
    put(bytes, 24, 0x8048000, 4, order);       // e_entry
    put(bytes, 28, 0, 4, order);               // e_phoff
    put(bytes, 32, kSectionTableOffset, 4, order);
    put(bytes, 36, 0, 4, order);               // e_flags
    put(bytes, 40, 52, 2, order);              // e_ehsize
    put(bytes, 42, 0, 2, order);               // e_phentsize
    put(bytes, 44, 0, 2, order);               // e_phnum
    put(bytes, 46, kSectionHeaderSize, 2, order);
    put(bytes, 48, section_count, 2, order);
    put(bytes, 50, with_bss ? 3 : 2, 2, order);  // e_shstrndx

    // .text content: a plausible i386 prologue.
    put_bytes(bytes, 0x100, "\x55\x89\xE5\x83\xEC\x08\xC3\x90");
    // Section name table at 0x110: "\0.text\0.bss\0.shstrtab".
    const std::string names = std::string("\0.text\0.bss\0.shstrtab", 21);
    put_bytes(bytes, 0x110, names);

    const auto write_section = [&](std::uint16_t index, std::uint32_t name,
                                   std::uint32_t type, std::uint32_t flags,
                                   std::uint32_t address, std::uint32_t offset,
                                   std::uint32_t size) {
        const std::size_t base = kSectionTableOffset + static_cast<std::size_t>(index) * 40U;
        put(bytes, base + 0, name, 4, order);
        put(bytes, base + 4, type, 4, order);
        put(bytes, base + 8, flags, 4, order);
        put(bytes, base + 12, address, 4, order);
        put(bytes, base + 16, offset, 4, order);
        put(bytes, base + 20, size, 4, order);
        put(bytes, base + 32, 16, 4, order);  // sh_addralign
    };

    // Section 0 stays all zeroes.
    write_section(1, 1, 1, 0x6, 0x8048000, 0x100, 8);  // .text PROGBITS ALLOC|EXEC
    if (with_bss) {
        write_section(2, 7, 8, 0x3, 0x8049000, 0x130, 0x40);  // .bss NOBITS ALLOC|WRITE
        write_section(3, 12, 3, 0, 0, 0x110, static_cast<std::uint32_t>(names.size()));
    } else {
        write_section(2, 12, 3, 0, 0, 0x110, static_cast<std::uint32_t>(names.size()));
    }
    return bytes;
}

/// Minimal ELF64 with .text + NOBITS .bss, used for zero-fill rejection.
[[nodiscard]] Bytes make_elf64_with_bss() {
    constexpr std::uint64_t kSectionTableOffset = 0x200;
    constexpr std::uint16_t kSectionHeaderSize = 64;
    constexpr std::uint16_t kSectionCount = 4;
    Bytes bytes(kSectionTableOffset + static_cast<std::size_t>(kSectionCount) * 64, 0);

    bytes[0] = 0x7F;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2;  // ELFCLASS64
    bytes[5] = 1;  // little endian
    bytes[6] = 1;
    put(bytes, 16, 2, 2);                  // ET_EXEC
    put(bytes, 18, 62, 2);                 // EM_X86_64
    put(bytes, 20, 1, 4);                  // e_version
    put(bytes, 24, 0x400000, 8);           // e_entry
    put(bytes, 32, 0, 8);                  // e_phoff
    put(bytes, 40, kSectionTableOffset, 8);
    put(bytes, 52, 64, 2);                 // e_ehsize
    put(bytes, 54, 56, 2);                 // e_phentsize
    put(bytes, 58, kSectionHeaderSize, 2);
    put(bytes, 60, kSectionCount, 2);
    put(bytes, 62, 3, 2);                  // e_shstrndx

    put_bytes(bytes, 0x100, "\x55\x48\x89\xE5\xC3\x90");
    const std::string names = std::string("\0.text\0.bss\0.shstrtab", 21);
    put_bytes(bytes, 0x120, names);

    const auto write_section = [&](std::uint16_t index, std::uint32_t name,
                                   std::uint32_t type, std::uint64_t flags,
                                   std::uint64_t address, std::uint64_t offset,
                                   std::uint64_t size) {
        const std::size_t base = kSectionTableOffset + static_cast<std::size_t>(index) * 64U;
        put(bytes, base + 0, name, 4);
        put(bytes, base + 4, type, 4);
        put(bytes, base + 8, flags, 8);
        put(bytes, base + 16, address, 8);
        put(bytes, base + 24, offset, 8);
        put(bytes, base + 32, size, 8);
        put(bytes, base + 48, 16, 8);  // sh_addralign
    };
    write_section(1, 1, 1, 0x6, 0x400000, 0x100, 6);      // .text
    write_section(2, 7, 8, 0x3, 0x401000, 0x140, 0x40);   // .bss
    write_section(3, 12, 3, 0, 0, 0x120, static_cast<std::uint64_t>(names.size()));
    return bytes;
}

// ---------------------------------------------------------------------------
// Hand-built PE images
// ---------------------------------------------------------------------------

struct PeOptions {
    bool plus = false;
    bool with_exports = true;
    bool with_coff_symbols = true;
};

/// Minimal PE image with .text, .rdata (exports), .data and a NOBITS .bss.
[[nodiscard]] Bytes make_pe(const PeOptions& options) {
    const std::uint16_t optional_size = options.plus ? 240 : 224;
    constexpr std::size_t kRawBase = 0x400;
    constexpr std::size_t kTextRaw = kRawBase;
    constexpr std::size_t kRdataRaw = kRawBase + 0x100;
    constexpr std::size_t kDataRaw = kRawBase + 0x300;
    constexpr std::size_t kSymbolTable = kDataRaw + 0x40;
    const std::size_t file_size =
        options.with_coff_symbols ? kSymbolTable + 18 + 4 : kSymbolTable;
    Bytes bytes(file_size, 0);

    // DOS header.
    bytes[0] = 'M';
    bytes[1] = 'Z';
    put(bytes, 0x3C, 0x40, 4);  // e_lfanew

    // PE signature + COFF file header.
    put_bytes(bytes, 0x40, "PE\0\0");
    put(bytes, 0x44, options.plus ? 0x8664 : 0x14C, 2);  // Machine
    put(bytes, 0x46, 4, 2);                              // NumberOfSections
    put(bytes, 0x48, 0, 4);                              // TimeDateStamp
    put(bytes, 0x4C, options.with_coff_symbols ? kSymbolTable : 0, 4);
    put(bytes, 0x50, options.with_coff_symbols ? 1 : 0, 4);
    put(bytes, 0x54, optional_size, 2);
    put(bytes, 0x56, 0x22, 2);  // Characteristics: executable | 32-bit

    // Optional header.
    const std::size_t optional = 0x58;
    const std::uint64_t image_base = options.plus ? 0x140000000ULL : 0x400000ULL;
    put(bytes, optional + 0, options.plus ? 0x20B : 0x10B, 2);
    put(bytes, optional + 2, 14, 1);
    put(bytes, optional + 16, 0x1000, 4);  // AddressOfEntryPoint
    put(bytes, optional + 20, 0x1000, 4);  // BaseOfCode
    if (options.plus) {
        put(bytes, optional + 24, image_base, 8);
    } else {
        put(bytes, optional + 28, image_base, 4);
    }
    put(bytes, optional + 32, 0x1000, 4);  // SectionAlignment
    put(bytes, optional + 36, 0x200, 4);   // FileAlignment
    put(bytes, optional + 56, 0x6000, 4);  // SizeOfImage
    put(bytes, optional + 60, kRawBase, 4);  // SizeOfHeaders
    const std::size_t directory_offset = optional + (options.plus ? 112 : 96);
    const std::size_t directory_count_offset = optional + (options.plus ? 108 : 92);
    put(bytes, directory_count_offset, 16, 4);
    if (options.with_exports) {
        put(bytes, directory_offset + 0, 0x3000, 4);  // Export directory RVA
        put(bytes, directory_offset + 4, 0x60, 4);    // Export directory size
    }

    // Section table.
    struct SectionSpec {
        std::string_view name;
        std::uint32_t virtual_size;
        std::uint32_t virtual_address;
        std::uint32_t raw_size;
        std::uint32_t raw_offset;
        std::uint32_t characteristics;
    };
    const SectionSpec sections[] = {
        {".text", 0x20, 0x1000, 0x20, static_cast<std::uint32_t>(kTextRaw), 0x60000020U},
        {".rdata", 0x200, 0x3000, 0x200, static_cast<std::uint32_t>(kRdataRaw), 0x40000040U},
        {".data", 0x40, 0x4000, 0x40, static_cast<std::uint32_t>(kDataRaw), 0xC0000040U},
        {".bss", 0x100, 0x5000, 0, 0, 0xC0000080U},
    };
    const std::size_t section_table = optional + optional_size;
    for (std::size_t i = 0; i < 4; ++i) {
        const std::size_t base = section_table + i * 40U;
        put_bytes(bytes, base, sections[i].name);
        put(bytes, base + 8, sections[i].virtual_size, 4);
        put(bytes, base + 12, sections[i].virtual_address, 4);
        put(bytes, base + 16, sections[i].raw_size, 4);
        put(bytes, base + 20, sections[i].raw_offset, 4);
        put(bytes, base + 36, sections[i].characteristics, 4);
    }

    // .text raw content.
    put_bytes(bytes, kTextRaw, "\x55\x48\x89\xE5\xB8\x2A\x00\x00\x00\xC3\x90\x90");

    // .rdata: export directory + arrays + names.
    const std::size_t export_dir = kRdataRaw;
    put(bytes, export_dir + 12, 0x3050, 4);  // Name RVA (DLL name)
    put(bytes, export_dir + 16, 1, 4);       // Ordinal base
    put(bytes, export_dir + 20, 1, 4);       // NumberOfFunctions
    put(bytes, export_dir + 24, 1, 4);       // NumberOfNames
    put(bytes, export_dir + 28, 0x3028, 4);  // AddressOfFunctions
    put(bytes, export_dir + 32, 0x302C, 4);  // AddressOfNames
    put(bytes, export_dir + 36, 0x3030, 4);  // AddressOfNameOrdinals
    put(bytes, kRdataRaw + 0x28, 0x1000, 4);  // functions[0] = entry RVA
    put(bytes, kRdataRaw + 0x2C, 0x3040, 4);  // names[0] = "exported_fn"
    put(bytes, kRdataRaw + 0x30, 0, 2);       // ordinals[0]
    put_bytes(bytes, kRdataRaw + 0x40, "exported_fn");
    put_bytes(bytes, kRdataRaw + 0x50, "sample.dll");

    // .data raw content (not otherwise used).
    put(bytes, kDataRaw, 0x11223344, 4);

    // Optional COFF symbol table with a single inline-named function symbol.
    if (options.with_coff_symbols) {
        put_bytes(bytes, kSymbolTable, "coff_fn");
        put(bytes, kSymbolTable + 8, 0x10, 4);   // Value (offset in .text)
        put(bytes, kSymbolTable + 12, 1, 2);     // SectionNumber
        put(bytes, kSymbolTable + 14, 0x20, 2);  // Type (function)
        put(bytes, kSymbolTable + 16, 2, 1);     // StorageClass = external
        put(bytes, kSymbolTable + 17, 0, 1);     // NumberOfAuxSymbols
        put(bytes, kSymbolTable + 18, 4, 4);     // String table size
    }
    return bytes;
}

// ---------------------------------------------------------------------------
// Hand-built Mach-O images
// ---------------------------------------------------------------------------

// Layout shared by make_macho64().
constexpr std::uint64_t kMachTextVm = 0x100000000ULL;  // __TEXT base
constexpr std::uint64_t kMachTextFileOffset = 0x400;
constexpr std::uint64_t kMachTextVa = kMachTextVm + kMachTextFileOffset;
constexpr std::uint64_t kMachSymtabOffset = 0x1240;
constexpr std::uint64_t kMachStrtabOffset = 0x1260;

void write_segment64(Bytes& bytes, std::size_t offset, std::string_view segment_name,
                     std::uint64_t vmaddr, std::uint64_t vmsize, std::uint64_t fileoff,
                     std::uint64_t filesize, std::uint32_t initprot,
                     std::uint32_t section_count) {
    put(bytes, offset + 0, 0x19, 4);  // LC_SEGMENT_64
    put(bytes, offset + 4, 72U + static_cast<std::uint64_t>(section_count) * 80U, 4);
    put_bytes(bytes, offset + 8, segment_name);
    put(bytes, offset + 24, vmaddr, 8);
    put(bytes, offset + 32, vmsize, 8);
    put(bytes, offset + 40, fileoff, 8);
    put(bytes, offset + 48, filesize, 8);
    put(bytes, offset + 56, 7, 4);  // maxprot
    put(bytes, offset + 60, initprot, 4);
    put(bytes, offset + 64, section_count, 4);
    put(bytes, offset + 68, 0, 4);  // flags
}

void write_section64(Bytes& bytes, std::size_t offset, std::string_view section_name,
                     std::string_view segment_name, std::uint64_t address,
                     std::uint64_t size, std::uint32_t file_offset,
                     std::uint32_t flags) {
    put_bytes(bytes, offset + 0, section_name);
    put_bytes(bytes, offset + 16, segment_name);
    put(bytes, offset + 32, address, 8);
    put(bytes, offset + 40, size, 8);
    put(bytes, offset + 48, file_offset, 4);
    put(bytes, offset + 52, 4, 4);  // align = 2^4
    put(bytes, offset + 64, flags, 4);
}

/// 64-bit little-endian Mach-O with __TEXT (__text), __DATA (__data), LC_MAIN
/// and LC_SYMTAB carrying one function symbol.
[[nodiscard]] Bytes make_macho64() {
    constexpr std::size_t kHeaderSize = 32;
    constexpr std::size_t kTextCommand = kHeaderSize;                 // 152 bytes
    constexpr std::size_t kDataCommand = kTextCommand + 152;          // 152 bytes
    constexpr std::size_t kMainCommand = kDataCommand + 152;          // 24 bytes
    constexpr std::size_t kSymtabCommand = kMainCommand + 24;         // 24 bytes
    constexpr std::size_t kCommandsEnd = kSymtabCommand + 24;
    constexpr std::size_t kFileSize = 0x1280;
    Bytes bytes(kFileSize, 0);

    put(bytes, 0, 0xFEEDFACF, 4);  // MH_MAGIC_64 (written little-endian)
    put(bytes, 4, 0x01000007, 4);  // CPU_TYPE_X86_64
    put(bytes, 8, 3, 4);           // CPU_SUBTYPE_X86_64_ALL
    put(bytes, 12, 2, 4);          // MH_EXECUTE
    put(bytes, 16, 4, 4);          // ncmds
    put(bytes, 20, kCommandsEnd - kHeaderSize, 4);  // sizeofcmds
    put(bytes, 24, 0, 4);          // flags
    put(bytes, 28, 0, 4);          // reserved

    write_segment64(bytes, kTextCommand, "__TEXT", kMachTextVm, 0x1000, 0, 0x1000, 5, 1);
    write_section64(bytes, kTextCommand + 72, "__text", "__TEXT", kMachTextVa, 0x100,
                    static_cast<std::uint32_t>(kMachTextFileOffset), 0x80000400U);

    write_segment64(bytes, kDataCommand, "__DATA", kMachTextVm + 0x1000, 0x1000, 0x1000,
                    0x240, 3, 1);
    write_section64(bytes, kDataCommand + 72, "__data", "__DATA", kMachTextVm + 0x1200,
                    0x40, 0x1200, 0);

    put(bytes, kMainCommand + 0, 0x80000028, 4);  // LC_MAIN
    put(bytes, kMainCommand + 4, 24, 4);
    put(bytes, kMainCommand + 8, kMachTextFileOffset, 8);  // entryoff

    put(bytes, kSymtabCommand + 0, 0x2, 4);  // LC_SYMTAB
    put(bytes, kSymtabCommand + 4, 24, 4);
    put(bytes, kSymtabCommand + 8, kMachSymtabOffset, 4);
    put(bytes, kSymtabCommand + 12, 2, 4);  // nsyms
    put(bytes, kSymtabCommand + 16, kMachStrtabOffset, 4);
    put(bytes, kSymtabCommand + 20, 13, 4);  // strsize

    // __text payload: endbr64 + frame prologue.
    put_bytes(bytes, kMachTextFileOffset, "\xF3\x0F\x1E\xFA\x55\x48\x89\xE5\xC3");
    const std::string names = std::string("\0__text_main\0", 13);
    put_bytes(bytes, kMachStrtabOffset, names);

    // nlist_64 entries: null + __text_main.
    const std::size_t symbol = kMachSymtabOffset + 16;
    put(bytes, symbol + 0, 1, 4);           // n_strx
    put(bytes, symbol + 4, 0x0F, 1);        // n_type = N_SECT | N_EXT
    put(bytes, symbol + 5, 1, 1);           // n_sect (__text)
    put(bytes, symbol + 6, 0, 2);           // n_desc
    put(bytes, symbol + 8, kMachTextVa, 8);  // n_value
    return bytes;
}

/// 32-bit big-endian Mach-O, exercising the endian and bitness branches.
[[nodiscard]] Bytes make_macho32_big_endian() {
    constexpr std::size_t kHeaderSize = 28;
    constexpr std::size_t kSegmentCommand = kHeaderSize;              // 124 bytes
    constexpr std::size_t kMainCommand = kSegmentCommand + 124;       // 24 bytes
    constexpr std::size_t kCommandsEnd = kMainCommand + 24;
    constexpr std::size_t kFileSize = 0x900;
    Bytes bytes(kFileSize, 0);

    put(bytes, 0, 0xFEEDFACE, 4, kBig);  // MH_MAGIC (big-endian file)
    put(bytes, 4, 7, 4, kBig);           // CPU_TYPE_I386
    put(bytes, 8, 3, 4, kBig);
    put(bytes, 12, 2, 4, kBig);          // MH_EXECUTE
    put(bytes, 16, 2, 4, kBig);          // ncmds
    put(bytes, 20, kCommandsEnd - kHeaderSize, 4, kBig);

    const std::size_t segment = kSegmentCommand;
    put(bytes, segment + 0, 0x1, 4, kBig);  // LC_SEGMENT
    put(bytes, segment + 4, 124, 4, kBig);
    put_bytes(bytes, segment + 8, "__TEXT");
    put(bytes, segment + 24, 0x1000, 4, kBig);   // vmaddr
    put(bytes, segment + 28, 0x1000, 4, kBig);   // vmsize
    put(bytes, segment + 32, 0, 4, kBig);        // fileoff
    put(bytes, segment + 36, kFileSize, 4, kBig);  // filesize
    put(bytes, segment + 40, 7, 4, kBig);        // maxprot
    put(bytes, segment + 44, 5, 4, kBig);        // initprot R|X
    put(bytes, segment + 48, 1, 4, kBig);        // nsects
    const std::size_t section = segment + 56;
    put_bytes(bytes, section + 0, "__text");
    put_bytes(bytes, section + 16, "__TEXT");
    put(bytes, section + 32, 0x1800, 4, kBig);   // addr
    put(bytes, section + 36, 0x100, 4, kBig);    // size
    put(bytes, section + 40, 0x800, 4, kBig);    // offset
    put(bytes, section + 56, 0x80000400U, 4, kBig);  // flags

    put(bytes, kMainCommand + 0, 0x80000028, 4, kBig);
    put(bytes, kMainCommand + 4, 24, 4, kBig);
    put(bytes, kMainCommand + 8, 0x800, 8, kBig);  // entryoff
    return bytes;
}

/// Wraps a Mach-O slice in a big-endian fat/universal binary.
[[nodiscard]] Bytes make_fat_macho(const Bytes& slice, bool invalid_first_slice) {
    const std::uint32_t slice_count = invalid_first_slice ? 2 : 1;
    const std::uint64_t first_offset = 0x1000;
    const std::uint64_t second_offset = 0x2000;
    const std::uint64_t file_size = invalid_first_slice
                                        ? second_offset + slice.size()
                                        : first_offset + slice.size();
    Bytes bytes(static_cast<std::size_t>(file_size), 0);
    put(bytes, 0, 0xCAFEBABE, 4, kBig);  // FAT_MAGIC
    put(bytes, 4, slice_count, 4, kBig);
    const auto write_arch = [&](std::size_t index, std::uint32_t offset,
                                std::uint32_t size) {
        const std::size_t base = 8 + index * 20U;
        put(bytes, base + 0, 0x01000007, 4, kBig);
        put(bytes, base + 4, 3, 4, kBig);
        put(bytes, base + 8, offset, 4, kBig);
        put(bytes, base + 12, size, 4, kBig);
        put(bytes, base + 16, 12, 4, kBig);  // align = 2^12
    };
    if (invalid_first_slice) {
        write_arch(0, static_cast<std::uint32_t>(first_offset), 4);
        write_arch(1, static_cast<std::uint32_t>(second_offset),
                   static_cast<std::uint32_t>(slice.size()));
        put_bytes(bytes, first_offset, "JUNK");
        for (std::size_t i = 0; i < slice.size(); ++i) {
            bytes[second_offset + i] = slice[i];
        }
    } else {
        write_arch(0, static_cast<std::uint32_t>(first_offset),
                   static_cast<std::uint32_t>(slice.size()));
        for (std::size_t i = 0; i < slice.size(); ++i) {
            bytes[first_offset + i] = slice[i];
        }
    }
    return bytes;
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixture-backed integration tests
// ---------------------------------------------------------------------------

TEST_CASE("executable/parse rust ELF fixture") {
    const auto path = std::filesystem::path(TYPEMORPH_TEST_FIXTURES) / "rust_sample.elf";
    auto view = BinaryView::open(path);
    REQUIRE(view.has_value());
    auto image = ExecutableImage::parse(view.value());
    REQUIRE(image.has_value());

    const ExecutableImage& elf = image.value();
    CHECK(elf.valid());
    CHECK(elf.format() == ImageFormat::elf);
    CHECK_EQ(elf.bits(), 64);
    CHECK(elf.endian() == ByteOrder::little);
    CHECK_EQ(elf.entry_point(), 0x401000ULL);
    CHECK_EQ(elf.image_base(), 0ULL);
    CHECK_EQ(elf.format_name(), std::string("ELF"));
    CHECK_EQ(elf.view().size(), view.value().size());

    const Section* text = find_section(elf, ".text");
    REQUIRE(text != nullptr);
    CHECK_EQ(text->virtual_address, 0x401000ULL);
    CHECK_EQ(text->virtual_size, 0x60ULL);
    CHECK_EQ(text->file_offset, 0x1000ULL);
    CHECK(text->executable());
    CHECK(!text->writable());
    CHECK(text->read_only());
    CHECK(typemorph::core::has_flag(text->flags, SectionFlag::code));

    const Section* rodata = find_section(elf, ".rodata");
    REQUIRE(rodata != nullptr);
    CHECK(rodata->read_only());
    CHECK(!rodata->executable());
    CHECK(typemorph::core::has_flag(rodata->flags, SectionFlag::data));

    const Section* data = find_section(elf, ".data");
    REQUIRE(data != nullptr);
    CHECK(data->writable());
    CHECK(!data->executable());
    CHECK(!data->read_only());

    CHECK(find_section(elf, ".does-not-exist") == nullptr);
    CHECK(elf.section_for_address(0x403040) != nullptr);
    CHECK_EQ(elf.section_for_address(0x403040)->name, std::string(".data"));
    CHECK(elf.contains_address(0x401010));
    CHECK(!elf.contains_address(0x900000));
    CHECK(elf.is_executable_address(0x401020));
    CHECK(!elf.is_executable_address(0x402000));

    const auto executable_sections = elf.sections_with(SectionFlag::executable);
    REQUIRE_EQ(executable_sections.size(), static_cast<std::size_t>(1));
    CHECK_EQ(executable_sections.front()->name, std::string(".text"));
    CHECK_EQ(elf.sections_with(SectionFlag::none).size(), elf.sections().size());

    auto text_bytes = elf.section_bytes(*text);
    REQUIRE(text_bytes.has_value());
    CHECK_EQ(text_bytes.value().size(), static_cast<std::size_t>(0x60));
    CHECK_EQ(text_bytes.value()[0], static_cast<std::uint8_t>(0xF3));  // endbr64
    CHECK_EQ(text_bytes.value()[1], static_cast<std::uint8_t>(0x0F));

    CHECK_EQ(elf.va_to_offset(0x401000).value_or(0), 0x1000ULL);
    CHECK_EQ(elf.va_to_offset(0x401000, 0).value_or(0), 0x1000ULL);
    CHECK_EQ(elf.va_to_offset(0x403040, 8).value_or(0), 0x3040ULL);
    CHECK(!elf.va_to_offset(0x401060, 4).has_value());
    CHECK(!elf.va_to_offset(0x900000).has_value());

    auto span = elf.span_at_va(0x402000, 26);
    REQUIRE(span.has_value());
    CHECK(bytes_equal(span.value(), "hello from rust_sample.elf"));

    // .data carries (ptr, len) fat pointers plus the trait-object vtable.
    auto data_bytes = elf.section_bytes(*data);
    REQUIRE(data_bytes.has_value());
    const auto data_span = data_bytes.value();
    CHECK_EQ(read_u64(data_span, 0x00), 0x402000ULL);
    CHECK_EQ(read_u64(data_span, 0x08), 26ULL);
    CHECK_EQ(read_u64(data_span, 0x10), 0x402020ULL);
    CHECK_EQ(read_u64(data_span, 0x18), 31ULL);
    CHECK_EQ(read_u64(data_span, 0x20), 0x402040ULL);
    CHECK_EQ(read_u64(data_span, 0x28), 15ULL);
    CHECK_EQ(read_u64(data_span, 0x40), 0x401000ULL);  // drop_in_place
    CHECK_EQ(read_u64(data_span, 0x48), 0x18ULL);      // size
    CHECK_EQ(read_u64(data_span, 0x50), 0x08ULL);      // align
    CHECK_EQ(read_u64(data_span, 0x58), 0x401020ULL);  // method_0
    CHECK_EQ(read_u64(data_span, 0x60), 0x401040ULL);  // method_1

    // Every fat pointer translates to its UTF-8 payload.
    auto str0 = elf.span_at_va(0x402000, 26);
    REQUIRE(str0.has_value());
    CHECK(bytes_equal(str0.value(), "hello from rust_sample.elf"));
    auto str2 = elf.span_at_va(0x402040, 15);
    REQUIRE(str2.has_value());
    CHECK(bytes_equal(str2.value(), "gr\xC3\xBC\xC3\x9F" "e, \xE4\xB8\x96\xE7\x95\x8C"));
    CHECK(elf.is_executable_address(0x401000));

    // Symbols from .symtab.
    CHECK_EQ(elf.symbols().size(), static_cast<std::size_t>(8));
    const Symbol* drop = find_symbol(elf, "rust_sample_drop_in_place");
    REQUIRE(drop != nullptr);
    CHECK_EQ(drop->address, 0x401000ULL);
    CHECK_EQ(drop->size, 32ULL);
    CHECK(drop->kind == SymbolKind::function);
    CHECK(drop->rust);
    const Symbol* method1 = find_symbol(elf, "rust_sample_method_1");
    REQUIRE(method1 != nullptr);
    CHECK_EQ(method1->address, 0x401040ULL);
    CHECK(method1->kind == SymbolKind::function);
    const Symbol* vtable = find_symbol(elf, "rust_sample_vtable");
    REQUIRE(vtable != nullptr);
    CHECK_EQ(vtable->address, 0x403040ULL);
    CHECK(vtable->kind == SymbolKind::object);
}

// ---------------------------------------------------------------------------
// ELF variants
// ---------------------------------------------------------------------------

TEST_CASE("executable/parse ELF32 little-endian with BSS") {
    auto image = try_parse(make_elf32(false, true));
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::elf);
    CHECK_EQ(image->bits(), 32);
    CHECK(image->endian() == ByteOrder::little);
    CHECK_EQ(image->entry_point(), 0x8048000ULL);

    const Section* text = find_section(*image, ".text");
    REQUIRE(text != nullptr);
    CHECK(text->executable());
    CHECK_EQ(image->va_to_offset(0x8048000, 8).value_or(0), 0x100ULL);
    auto text_bytes = image->section_bytes(*text);
    REQUIRE(text_bytes.has_value());
    CHECK_EQ(text_bytes.value().size(), static_cast<std::size_t>(8));

    const Section* bss = find_section(*image, ".bss");
    REQUIRE(bss != nullptr);
    CHECK(typemorph::core::has_flag(bss->flags, SectionFlag::zero_fill));
    CHECK_EQ(bss->virtual_address, 0x8049000ULL);
    CHECK_EQ(bss->virtual_size, 0x40ULL);
    CHECK_EQ(bss->file_size, 0ULL);

    // Zero-fill sections have no file bytes and must be rejected.
    CHECK(translation_error(*image, 0x8049000) == ErrorCode::out_of_range);
    CHECK(translation_error(*image, 0x8049000, 4) == ErrorCode::out_of_range);
    const auto bss_bytes = image->section_bytes(*bss);
    REQUIRE(!bss_bytes.has_value());
    CHECK(bss_bytes.error().code == ErrorCode::out_of_range);
    const auto zero_fill = image->sections_with(SectionFlag::zero_fill);
    REQUIRE_EQ(zero_fill.size(), static_cast<std::size_t>(1));
    CHECK_EQ(zero_fill.front()->name, std::string(".bss"));
}

TEST_CASE("executable/parse ELF32 big-endian") {
    auto image = try_parse(make_elf32(true, false));
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::elf);
    CHECK_EQ(image->bits(), 32);
    CHECK(image->endian() == ByteOrder::big);
    CHECK_EQ(image->entry_point(), 0x8048000ULL);

    const Section* text = find_section(*image, ".text");
    REQUIRE(text != nullptr);
    CHECK_EQ(text->virtual_address, 0x8048000ULL);
    CHECK(text->executable());
    CHECK_EQ(image->va_to_offset(0x8048000, 4).value_or(0), 0x100ULL);
    auto span = image->span_at_va(0x8048002, 1);
    REQUIRE(span.has_value());
    CHECK_EQ(span.value()[0], static_cast<std::uint8_t>(0xE5));  // 89 E5 (mov ebp,esp)
}

TEST_CASE("executable/parse ELF64 with BSS rejects zero fill") {
    auto image = try_parse(make_elf64_with_bss());
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::elf);
    CHECK_EQ(image->bits(), 64);
    CHECK(image->endian() == ByteOrder::little);
    CHECK_EQ(image->entry_point(), 0x400000ULL);

    const Section* text = find_section(*image, ".text");
    REQUIRE(text != nullptr);
    CHECK(text->executable());
    CHECK_EQ(image->va_to_offset(0x400000).value_or(0), 0x100ULL);

    const Section* bss = find_section(*image, ".bss");
    REQUIRE(bss != nullptr);
    CHECK(typemorph::core::has_flag(bss->flags, SectionFlag::zero_fill));
    CHECK(translation_error(*image, 0x401000) == ErrorCode::out_of_range);
    const auto bss_bytes = image->section_bytes(*bss);
    REQUIRE(!bss_bytes.has_value());
    CHECK(bss_bytes.error().code == ErrorCode::out_of_range);
    CHECK(!image->is_executable_address(0x401000));
}

// ---------------------------------------------------------------------------
// PE variants
// ---------------------------------------------------------------------------

TEST_CASE("executable/parse PE32 with exports and COFF symbols") {
    auto image = try_parse(make_pe(PeOptions{false, true, true}));
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::pe);
    CHECK_EQ(image->bits(), 32);
    CHECK(image->endian() == ByteOrder::little);
    CHECK_EQ(image->image_base(), 0x400000ULL);
    CHECK_EQ(image->entry_point(), 0x401000ULL);
    CHECK_EQ(image->format_name(), std::string("PE"));

    const Section* text = find_section(*image, ".text");
    REQUIRE(text != nullptr);
    CHECK_EQ(text->virtual_address, 0x401000ULL);
    CHECK_EQ(text->file_offset, 0x400ULL);
    CHECK_EQ(text->file_size, 0x20ULL);
    CHECK(text->executable());
    CHECK(text->read_only());
    CHECK_EQ(image->va_to_offset(0x401000).value_or(0), 0x400ULL);

    const Section* rdata = find_section(*image, ".rdata");
    REQUIRE(rdata != nullptr);
    CHECK(rdata->read_only());
    CHECK(!rdata->executable());
    CHECK_EQ(image->va_to_offset(0x403028).value_or(0), 0x528ULL);

    const Section* data = find_section(*image, ".data");
    REQUIRE(data != nullptr);
    CHECK(data->writable());
    CHECK(!data->executable());

    // NOBITS-style section: no raw bytes, translation must fail.
    const Section* bss = find_section(*image, ".bss");
    REQUIRE(bss != nullptr);
    CHECK(typemorph::core::has_flag(bss->flags, SectionFlag::zero_fill));
    CHECK(translation_error(*image, 0x405000) == ErrorCode::out_of_range);

    auto text_bytes = image->section_bytes(*text);
    REQUIRE(text_bytes.has_value());
    CHECK_EQ(text_bytes.value()[0], static_cast<std::uint8_t>(0x55));  // push ebp

    // Export table + COFF symbol table both contribute named functions.
    const Symbol* exported = find_symbol(*image, "exported_fn");
    REQUIRE(exported != nullptr);
    CHECK_EQ(exported->address, 0x401000ULL);
    CHECK(exported->kind == SymbolKind::function);
    const Symbol* coff = find_symbol(*image, "coff_fn");
    REQUIRE(coff != nullptr);
    CHECK_EQ(coff->address, 0x401010ULL);
    CHECK(coff->kind == SymbolKind::function);
}

TEST_CASE("executable/parse PE32+ with exports and COFF symbols") {
    auto image = try_parse(make_pe(PeOptions{true, true, true}));
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::pe);
    CHECK_EQ(image->bits(), 64);
    CHECK_EQ(image->image_base(), 0x140000000ULL);
    CHECK_EQ(image->entry_point(), 0x140001000ULL);

    const Section* text = find_section(*image, ".text");
    REQUIRE(text != nullptr);
    CHECK_EQ(text->virtual_address, 0x140001000ULL);
    CHECK_EQ(image->va_to_offset(0x140001000).value_or(0), 0x400ULL);

    const Symbol* exported = find_symbol(*image, "exported_fn");
    REQUIRE(exported != nullptr);
    CHECK_EQ(exported->address, 0x140001000ULL);
    const Symbol* coff = find_symbol(*image, "coff_fn");
    REQUIRE(coff != nullptr);
    CHECK_EQ(coff->address, 0x140001010ULL);

    const Section* bss = find_section(*image, ".bss");
    REQUIRE(bss != nullptr);
    CHECK_EQ(bss->virtual_address, 0x140005000ULL);
    CHECK(translation_error(*image, 0x140005000) == ErrorCode::out_of_range);
}

TEST_CASE("executable/parse PE without optional symbol tables") {
    auto image = try_parse(make_pe(PeOptions{false, false, false}));
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::pe);
    CHECK(image->symbols().empty());
}

// ---------------------------------------------------------------------------
// Mach-O variants
// ---------------------------------------------------------------------------

TEST_CASE("executable/parse Mach-O 64 with LC_MAIN and symbols") {
    auto image = try_parse(make_macho64());
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::macho);
    CHECK_EQ(image->bits(), 64);
    CHECK(image->endian() == ByteOrder::little);
    CHECK_EQ(image->image_base(), kMachTextVm);
    CHECK_EQ(image->entry_point(), kMachTextVa);
    CHECK_EQ(image->format_name(), std::string("Mach-O"));

    const Section* text = find_section(*image, "__text");
    REQUIRE(text != nullptr);
    CHECK_EQ(text->virtual_address, kMachTextVa);
    CHECK_EQ(text->file_offset, kMachTextFileOffset);
    CHECK(text->executable());
    CHECK_EQ(image->va_to_offset(kMachTextVa, 4).value_or(0), kMachTextFileOffset);

    const Section* data = find_section(*image, "__data");
    REQUIRE(data != nullptr);
    CHECK(data->writable());
    CHECK(!data->executable());
    CHECK_EQ(image->va_to_offset(kMachTextVm + 0x1200, 8).value_or(0), 0x1200ULL);

    const Section* linkedit = find_section(*image, "__DATA");
    CHECK(linkedit == nullptr);  // Segments with sections are not duplicated.

    auto text_bytes = image->section_bytes(*text);
    REQUIRE(text_bytes.has_value());
    CHECK_EQ(text_bytes.value()[0], static_cast<std::uint8_t>(0xF3));  // endbr64
    CHECK(image->is_executable_address(kMachTextVa));
    CHECK(!image->is_executable_address(kMachTextVm + 0x1200));

    const Symbol* main_symbol = find_symbol(*image, "__text_main");
    REQUIRE(main_symbol != nullptr);
    CHECK_EQ(main_symbol->address, kMachTextVa);
    CHECK(main_symbol->kind == SymbolKind::function);
}

TEST_CASE("executable/parse Mach-O 32 big-endian") {
    auto image = try_parse(make_macho32_big_endian());
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::macho);
    CHECK_EQ(image->bits(), 32);
    CHECK(image->endian() == ByteOrder::big);
    CHECK_EQ(image->image_base(), 0x1000ULL);
    CHECK_EQ(image->entry_point(), 0x1800ULL);

    const Section* text = find_section(*image, "__text");
    REQUIRE(text != nullptr);
    CHECK_EQ(text->virtual_address, 0x1800ULL);
    CHECK_EQ(text->file_offset, 0x800ULL);
    CHECK(text->executable());
    CHECK_EQ(image->va_to_offset(0x1800, 2).value_or(0), 0x800ULL);
}

TEST_CASE("executable/parse fat Mach-O picks first supported slice") {
    const Bytes slice = make_macho64();
    auto image = try_parse(make_fat_macho(slice, false));
    REQUIRE(image.has_value());
    CHECK(image->format() == ImageFormat::macho);
    CHECK_EQ(image->bits(), 64);
    CHECK_EQ(image->entry_point(), kMachTextVa);
    // File offsets are absolute within the containing fat file.
    CHECK_EQ(image->va_to_offset(kMachTextVa, 4).value_or(0), 0x1000ULL + kMachTextFileOffset);

    // A bogus first slice must be skipped in favour of the valid second one.
    auto skipped = try_parse(make_fat_macho(slice, true));
    REQUIRE(skipped.has_value());
    CHECK(skipped->format() == ImageFormat::macho);
    CHECK_EQ(skipped->entry_point(), kMachTextVa);
    CHECK_EQ(skipped->va_to_offset(kMachTextVa, 4).value_or(0),
             0x2000ULL + kMachTextFileOffset);
}

// ---------------------------------------------------------------------------
// Malformed inputs
// ---------------------------------------------------------------------------

TEST_CASE("executable/rejects invalid views and garbage") {
    const BinaryView invalid;
    auto result = ExecutableImage::parse(invalid);
    CHECK(!result.has_value());
    CHECK(result.error().code == ErrorCode::invalid_argument);

    CHECK(parse_error_code(Bytes{}) == ErrorCode::unsupported);
    CHECK(parse_error_code(Bytes{0x00, 0x01, 0x02}) == ErrorCode::unsupported);
    const Bytes garbage = {'n', 'o', 't', 'a', 'n', 'e', 'x', 'e', 'c', 'u', 't', 'a', 'b', 'l', 'e'};
    CHECK(parse_error_code(garbage) == ErrorCode::unsupported);
}

TEST_CASE("executable/rejects malformed ELF") {
    const Bytes valid = make_elf32(false, false);

    Bytes truncated = valid;
    truncated.resize(20);
    CHECK(parse_error_code(truncated) == ErrorCode::parse_error);

    Bytes bad_class = valid;
    bad_class[4] = 0;
    CHECK(parse_error_code(bad_class) == ErrorCode::unsupported);

    Bytes bad_encoding = valid;
    bad_encoding[5] = 0;
    CHECK(parse_error_code(bad_encoding) == ErrorCode::parse_error);

    Bytes bad_section_table = valid;
    put(bad_section_table, 32, 0xFFFFFF00U, 4);  // e_shoff beyond EOF
    CHECK(parse_error_code(bad_section_table) == ErrorCode::parse_error);

    Bytes bad_entry_size = valid;
    put(bad_entry_size, 46, 8, 2);  // e_shentsize too small
    CHECK(parse_error_code(bad_entry_size) == ErrorCode::parse_error);

    Bytes bad_section_offset = valid;
    put(bad_section_offset, 0x200 + 40 + 16, 0xFFFFU, 4);  // .text sh_offset past EOF
    CHECK(parse_error_code(bad_section_offset) == ErrorCode::parse_error);

    Bytes bad_shstrndx = valid;
    put(bad_shstrndx, 50, 42, 2);  // e_shstrndx out of range
    CHECK(parse_error_code(bad_shstrndx) == ErrorCode::parse_error);
}

TEST_CASE("executable/rejects malformed PE") {
    const Bytes valid = make_pe(PeOptions{});
    REQUIRE(try_parse(valid).has_value());

    Bytes bad_lfanew = valid;
    put(bad_lfanew, 0x3C, 0xFFFFFFF0U, 4);
    CHECK(parse_error_code(bad_lfanew) == ErrorCode::parse_error);

    Bytes missing_signature = valid;
    missing_signature[0x40] = 'X';
    CHECK(parse_error_code(missing_signature) == ErrorCode::parse_error);

    Bytes bad_optional_magic = valid;
    put(bad_optional_magic, 0x58, 0x999, 2);
    CHECK(parse_error_code(bad_optional_magic) == ErrorCode::unsupported);

    Bytes truncated = valid;
    truncated.resize(0x100);
    CHECK(parse_error_code(truncated) == ErrorCode::parse_error);

    // MZ signature without a PE header at the recorded offset.
    Bytes mz_only(0x80, 0);
    mz_only[0] = 'M';
    mz_only[1] = 'Z';
    put(mz_only, 0x3C, 0x40, 4);
    put_bytes(mz_only, 0x40, "NOPE");
    CHECK(parse_error_code(mz_only) == ErrorCode::parse_error);
}

TEST_CASE("executable/rejects malformed Mach-O") {
    const Bytes valid = make_macho64();
    REQUIRE(try_parse(valid).has_value());

    Bytes bad_commands = valid;
    put(bad_commands, 20, 0xFFFFFFU, 4);  // sizeofcmds beyond EOF
    CHECK(parse_error_code(bad_commands) == ErrorCode::parse_error);

    Bytes truncated = valid;
    truncated.resize(16);
    CHECK(parse_error_code(truncated) == ErrorCode::parse_error);

    Bytes bad_magic = valid;
    put(bad_magic, 0, 0x12345678U, 4);
    CHECK(parse_error_code(bad_magic) == ErrorCode::unsupported);

    // Fat binary whose only slice cannot be parsed.
    Bytes fat = make_fat_macho(valid, false);
    put(fat, 16, 0x0FFFFFFFU, 4, kBig);  // slice offset beyond EOF
    CHECK(parse_error_code(fat) == ErrorCode::unsupported);
}

// ---------------------------------------------------------------------------
// from_parts / query helpers
// ---------------------------------------------------------------------------

TEST_CASE("executable/from_parts builds a queryable image") {
    const Bytes payload = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
                           0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x12, 0x34};
    const BinaryView view = BinaryView::from_owned(payload);

    ImageParts parts;
    parts.format = ImageFormat::elf;
    parts.bits = 32;
    parts.endian = ByteOrder::little;
    parts.image_base = 0x1000;
    parts.entry_point = 0x1004;
    Section code;
    code.name = ".code";
    code.virtual_address = 0x1000;
    code.virtual_size = 0x10;
    code.file_offset = 0;
    code.file_size = 0x10;
    code.flags = SectionFlag::readable | SectionFlag::executable | SectionFlag::code |
                 SectionFlag::read_only;
    parts.sections.push_back(code);
    Symbol symbol;
    symbol.name = "entry";
    symbol.address = 0x1004;
    symbol.size = 4;
    symbol.kind = SymbolKind::function;
    parts.symbols.push_back(symbol);

    const ExecutableImage image = ExecutableImage::from_parts(view, parts);
    CHECK(image.valid());
    CHECK(image.format() == ImageFormat::elf);
    CHECK_EQ(image.bits(), 32);
    CHECK_EQ(image.image_base(), 0x1000ULL);
    CHECK_EQ(image.entry_point(), 0x1004ULL);
    CHECK_EQ(image.sections().size(), static_cast<std::size_t>(1));
    CHECK(find_section(image, ".code") != nullptr);
    CHECK_EQ(image.va_to_offset(0x1004).value_or(0), 4ULL);
    CHECK(image.is_executable_address(0x1005));
    auto span = image.span_at_va(0x1004, 2);
    REQUIRE(span.has_value());
    CHECK_EQ(span.value()[0], static_cast<std::uint8_t>(0x11));
    CHECK_EQ(span.value()[1], static_cast<std::uint8_t>(0x22));
    CHECK_EQ(image.symbols().size(), static_cast<std::size_t>(1));
    CHECK_EQ(image.symbols().front().name, std::string("entry"));

    auto section_span = image.section_bytes(image.sections().front());
    REQUIRE(section_span.has_value());
    CHECK_EQ(section_span.value().size(), static_cast<std::size_t>(16));
}

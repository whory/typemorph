// TypeMorph - Memory Dump Fixer & Dynamic PE Reconstructor Implementation
#include "typemorph/dump/dump_fixer.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace typemorph::dump {

namespace {

inline std::uint16_t read_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

inline std::uint32_t read_u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

inline void write_u32(std::uint8_t* p, std::uint32_t val) {
    p[0] = static_cast<std::uint8_t>(val & 0xFF);
    p[1] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
    p[2] = static_cast<std::uint8_t>((val >> 16) & 0xFF);
    p[3] = static_cast<std::uint8_t>((val >> 24) & 0xFF);
}

} // namespace

bool DumpFixer::is_memory_dump(const BinaryView& view) {
    if (view.size() < 1024) return false;
    const auto* data = view.data();

    // Check MZ signature
    if (data[0] != 'M' || data[1] != 'Z') return false;

    std::uint32_t e_lfanew = read_u32(data + 0x3C);
    if (e_lfanew + 0x100 > view.size()) return false;

    // Check PE signature
    if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E' ||
        data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0) {
        return false;
    }

    // Check section headers: in a memory dump, PointerToRawData often equals VirtualAddress,
    // or SizeOfRawData equals VirtualSize, indicating unaligned memory mapping.
    std::uint16_t num_sections = read_u16(data + e_lfanew + 6);
    std::uint16_t opt_hdr_size = read_u16(data + e_lfanew + 20);
    std::size_t sec_table_offset = e_lfanew + 24 + opt_hdr_size;

    if (sec_table_offset + num_sections * 40 > view.size()) return false;

    for (std::size_t i = 0; i < num_sections; ++i) {
        const auto* sec = data + sec_table_offset + (i * 40);
        std::uint32_t virt_addr = read_u32(sec + 12);
        std::uint32_t raw_ptr = read_u32(sec + 20);
        // Memory dumps dumped linearly from RAM typically have raw_ptr == virt_addr
        if (virt_addr > 0 && raw_ptr == virt_addr) {
            return true;
        }
    }

    // Alternatively, check for vmpdump / Scylla / Process Hacker tags
    const std::vector<std::string> dump_sigs = {
        "vmpdump", "Scylla", "Process Hacker", "Dumped by"
    };
    for (const auto& sig : dump_sigs) {
        if (std::search(data, data + view.size(), sig.begin(), sig.end()) != data + view.size()) {
            return true;
        }
    }

    return false;
}

DumpFixReport DumpFixer::analyze(const BinaryView& view) {
    DumpFixReport report;
    report.is_memory_dump = is_memory_dump(view);

    const auto* data = view.data();
    std::size_t size = view.size();
    if (size < 0x200 || data[0] != 'M' || data[1] != 'Z') return report;

    std::uint32_t e_lfanew = read_u32(data + 0x3C);
    if (e_lfanew + 0x100 > size) return report;

    std::uint16_t num_sections = read_u16(data + e_lfanew + 6);
    std::uint16_t opt_hdr_size = read_u16(data + e_lfanew + 20);
    std::uint16_t magic = read_u16(data + e_lfanew + 24);

    if (magic == 0x10B) { // PE32
        report.original_entry_point_rva = read_u32(data + e_lfanew + 40);
        report.image_base = read_u32(data + e_lfanew + 52);
        report.section_alignment = read_u32(data + e_lfanew + 56);
        report.file_alignment = read_u32(data + e_lfanew + 60);
    } else if (magic == 0x20B) { // PE32+ (x64)
        report.original_entry_point_rva = read_u32(data + e_lfanew + 40);
        std::uint64_t base_low = read_u32(data + e_lfanew + 48);
        std::uint64_t base_high = read_u32(data + e_lfanew + 52);
        report.image_base = base_low | (base_high << 32);
        report.section_alignment = read_u32(data + e_lfanew + 56);
        report.file_alignment = read_u32(data + e_lfanew + 60);
    }

    // Determine dump tool source
    const auto has_str = [&](std::string_view needle) {
        return std::search(data, data + size, needle.begin(), needle.end()) != data + size;
    };

    if (has_str("vmpdump")) {
        report.detected_source = "vmpdump (VMProtect Memory Dumper)";
    } else if (has_str("Scylla")) {
        report.detected_source = "Scylla PE Dumper";
    } else if (has_str("WriteProcess-Dumper")) {
        report.detected_source = "WriteProcess-Dumper (Memory Stream)";
    } else {
        report.detected_source = "Generic Virtual Memory Dump";
    }

    std::size_t sec_offset = e_lfanew + 24 + opt_hdr_size;
    report.total_sections = num_sections;

    for (std::size_t i = 0; i < num_sections && sec_offset + (i + 1) * 40 <= size; ++i) {
        const auto* sec = data + sec_offset + (i * 40);
        DumpSectionInfo s;
        char name_buf[9] = {0};
        std::memcpy(name_buf, sec, 8);
        s.name = name_buf;
        s.virtual_size = read_u32(sec + 8);
        s.virtual_address = read_u32(sec + 12);
        s.raw_data_size = read_u32(sec + 16);
        s.raw_data_offset = read_u32(sec + 20);
        s.characteristics = read_u32(sec + 36);

        s.is_executable = (s.characteristics & 0x20000000) != 0;
        s.is_writable   = (s.characteristics & 0x80000000) != 0;

        report.sections.push_back(s);
    }

    report.headers_rebuilt = true;
    report.log.push_back("Identified " + std::to_string(report.sections.size()) + " sections in memory dump.");
    return report;
}

DumpFixResult DumpFixer::fix(const BinaryView& view, std::uint64_t new_oep_va) {
    DumpFixResult result;
    result.report = analyze(view);
    if (!result.report.is_memory_dump && view.size() < 1024) {
        result.success = false;
        result.error_message = "File is not a valid memory dump or PE binary.";
        return result;
    }

    const auto* data = view.data();
    std::size_t size = view.size();
    result.fixed_pe_image.assign(data, data + size);

    std::uint32_t e_lfanew = read_u32(data + 0x3C);
    std::uint16_t num_sections = read_u16(data + e_lfanew + 6);
    std::uint16_t opt_hdr_size = read_u16(data + e_lfanew + 20);
    std::size_t sec_offset = e_lfanew + 24 + opt_hdr_size;

    // 1. Re-align sections from memory mapping (VirtualAddress -> RawDataOffset)
    std::uint32_t file_align = result.report.file_alignment ? result.report.file_alignment : 0x200;

    for (std::size_t i = 0; i < num_sections && sec_offset + (i + 1) * 40 <= result.fixed_pe_image.size(); ++i) {
        auto* sec = result.fixed_pe_image.data() + sec_offset + (i * 40);
        std::uint32_t virt_size = read_u32(sec + 8);
        std::uint32_t virt_addr = read_u32(sec + 12);

        // Align raw size to file alignment
        std::uint32_t aligned_raw_size = (virt_size + file_align - 1) & ~(file_align - 1);
        if (aligned_raw_size == 0) aligned_raw_size = file_align;

        // If dump was written linearly with memory offsets:
        if (read_u32(sec + 20) == virt_addr) {
            write_u32(sec + 16, aligned_raw_size); // SizeOfRawData
            write_u32(sec + 20, virt_addr);        // PointerToRawData matches memory alignment
        }
    }

    // 2. Patch new OEP if requested
    if (new_oep_va != 0 && new_oep_va >= result.report.image_base) {
        std::uint32_t new_oep_rva = static_cast<std::uint32_t>(new_oep_va - result.report.image_base);
        write_u32(result.fixed_pe_image.data() + e_lfanew + 40, new_oep_rva);
        result.report.original_entry_point_rva = new_oep_rva;
    }

    result.success = true;
    return result;
}

std::string DumpFixer::format_report(const DumpFixReport& report) {
    std::ostringstream ss;
    ss << "=== TypeMorph Memory Dump Fixer (vmpdump / WriteProcess-Dumper / Scylla) ===\n\n"
       << "Source Dumper     : " << report.detected_source << "\n"
       << "Image Base        : 0x" << std::hex << std::uppercase << report.image_base << "\n"
       << "Entry Point (RVA) : 0x" << report.original_entry_point_rva << "\n"
       << "Section Alignment : 0x" << report.section_alignment << "\n"
       << "File Alignment    : 0x" << report.file_alignment << "\n"
       << "Total Sections    : " << std::dec << report.sections.size() << "\n\n";

    ss << "Sections:\n"
       << "  Name      VirtAddr    VirtSize    RawOffset   RawSize     Attr\n"
       << "  ----------------------------------------------------------------\n";

    for (const auto& s : report.sections) {
        ss << "  " << std::left << std::setw(10) << s.name
           << "0x" << std::hex << std::setw(10) << s.virtual_address
           << "0x" << std::setw(10) << s.virtual_size
           << "0x" << std::setw(10) << s.raw_data_offset
           << "0x" << std::setw(10) << s.raw_data_size
           << (s.is_executable ? "EXEC " : "")
           << (s.is_writable ? "WRITE" : "") << "\n";
    }

    return ss.str();
}

} // namespace typemorph::dump

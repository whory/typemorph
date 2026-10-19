// TypeMorph - Memory Dump Fixer & Dynamic PE Reconstructor Tests (vmpdump / Scylla / WriteProcess-Dumper)
#include "typemorph/dump/dump_fixer.hpp"
#include "typemorph/core/binary_view.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <string>
#include <vector>

TEST_CASE("dump_fixer: reject non-dump plain buffer") {
    std::vector<std::uint8_t> plain(512, 0x90);
    auto view = typemorph::core::BinaryView::from_owned(plain);
    CHECK(!typemorph::dump::DumpFixer::is_memory_dump(view));

    auto rep = typemorph::dump::DumpFixer::analyze(view);
    CHECK(!rep.is_memory_dump);
    CHECK_EQ(rep.sections.size(), 0U);
}

TEST_CASE("dump_fixer: detect and realign memory dump into valid PE") {
    std::vector<std::uint8_t> dump_bin(8192, 0);

    // 1. MZ header
    dump_bin[0] = 'M'; dump_bin[1] = 'Z';
    std::uint32_t e_lfanew = 0x80;
    std::memcpy(dump_bin.data() + 0x3C, &e_lfanew, 4);

    // 2. PE signature
    dump_bin[e_lfanew] = 'P'; dump_bin[e_lfanew + 1] = 'E';

    // FileHeader: 2 sections, opt header size = 224 (0xE0)
    std::uint16_t num_sec = 2;
    std::uint16_t opt_size = 224;
    std::memcpy(dump_bin.data() + e_lfanew + 6, &num_sec, 2);
    std::memcpy(dump_bin.data() + e_lfanew + 20, &opt_size, 2);

    // OptionalHeader: PE32 (0x10B), AddressOfEntryPoint = 0x1234, ImageBase = 0x00400000
    std::uint16_t magic = 0x10B;
    std::uint32_t ep = 0x00001234;
    std::uint32_t image_base = 0x00400000;
    std::uint32_t sec_align = 0x1000;
    std::uint32_t file_align = 0x200;
    std::memcpy(dump_bin.data() + e_lfanew + 24, &magic, 2);
    std::memcpy(dump_bin.data() + e_lfanew + 40, &ep, 4);
    std::memcpy(dump_bin.data() + e_lfanew + 52, &image_base, 4);
    std::memcpy(dump_bin.data() + e_lfanew + 56, &sec_align, 4);
    std::memcpy(dump_bin.data() + e_lfanew + 60, &file_align, 4);

    // Tag: vmpdump marker
    const std::string tag = "Dumped with vmpdump";
    std::copy(tag.begin(), tag.end(), dump_bin.begin() + 0x60);

    // Section 1 (.text): in RAM dump, raw_ptr == virt_addr == 0x1000
    std::size_t sec1_off = e_lfanew + 24 + opt_size;
    std::memcpy(dump_bin.data() + sec1_off, ".text\0\0\0", 8);
    std::uint32_t sec1_vsize = 0x800;
    std::uint32_t sec1_vaddr = 0x1000;
    std::uint32_t sec1_rsize = 0x800;
    std::uint32_t sec1_rptr  = 0x1000; // PointerToRawData equals VirtualAddress (memory dump characteristic)
    std::uint32_t sec1_chars = 0x60000020; // EXEC | READ
    std::memcpy(dump_bin.data() + sec1_off + 8, &sec1_vsize, 4);
    std::memcpy(dump_bin.data() + sec1_off + 12, &sec1_vaddr, 4);
    std::memcpy(dump_bin.data() + sec1_off + 16, &sec1_rsize, 4);
    std::memcpy(dump_bin.data() + sec1_off + 20, &sec1_rptr, 4);
    std::memcpy(dump_bin.data() + sec1_off + 36, &sec1_chars, 4);

    // Section 2 (.rdata)
    std::size_t sec2_off = sec1_off + 40;
    std::memcpy(dump_bin.data() + sec2_off, ".rdata\0\0", 8);
    std::uint32_t sec2_vsize = 0x400;
    std::uint32_t sec2_vaddr = 0x2000;
    std::uint32_t sec2_rsize = 0x400;
    std::uint32_t sec2_rptr  = 0x2000;
    std::uint32_t sec2_chars = 0x40000040; // READ | INITIALIZED_DATA
    std::memcpy(dump_bin.data() + sec2_off + 8, &sec2_vsize, 4);
    std::memcpy(dump_bin.data() + sec2_off + 12, &sec2_vaddr, 4);
    std::memcpy(dump_bin.data() + sec2_off + 16, &sec2_rsize, 4);
    std::memcpy(dump_bin.data() + sec2_off + 20, &sec2_rptr, 4);
    std::memcpy(dump_bin.data() + sec2_off + 36, &sec2_chars, 4);

    auto view = typemorph::core::BinaryView::from_owned(dump_bin);
    CHECK(typemorph::dump::DumpFixer::is_memory_dump(view));

    auto rep = typemorph::dump::DumpFixer::analyze(view);
    CHECK(rep.is_memory_dump);
    CHECK(rep.detected_source.find("vmpdump") != std::string::npos);
    CHECK_EQ(rep.sections.size(), 2U);
    CHECK_EQ(rep.original_entry_point_rva, 0x1234U);
    CHECK(rep.sections[0].is_executable);

    // Fix dump with a new OEP = 0x00401050
    auto fix_res = typemorph::dump::DumpFixer::fix(view, 0x00401050ULL);
    CHECK(fix_res.success);
    CHECK_EQ(fix_res.report.original_entry_point_rva, 0x1050U);

    // Check report output
    std::string text = typemorph::dump::DumpFixer::format_report(rep);
    CHECK(text.find("vmpdump") != std::string::npos);
    CHECK(text.find(".text") != std::string::npos);
    CHECK(text.find("EXEC") != std::string::npos);
}

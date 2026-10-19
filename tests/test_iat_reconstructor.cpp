// TypeMorph - PE IAT Reconstruction & Import Table Fixer unit tests.
#include "test_framework.hpp"

#include "typemorph/pe/iat_reconstructor.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

using namespace typemorph::pe;
using namespace typemorph::core;

namespace {

// Helper to construct a synthetic valid PE32+ (x64) image buffer
std::vector<std::uint8_t> create_synthetic_pe64(std::uint32_t raw_data_size = 0x1000) {
    std::vector<std::uint8_t> buffer(0x400 + raw_data_size, 0x00);

    // MZ Header
    buffer[0] = 'M';
    buffer[1] = 'Z';
    // PE pointer at 0x3C = 0x80
    *reinterpret_cast<std::uint32_t*>(&buffer[0x3C]) = 0x80;

    const std::size_t pe = 0x80;
    // PE\0\0
    buffer[pe + 0] = 'P';
    buffer[pe + 1] = 'E';

    // FileHeader: Machine = 0x8664 (x64), NumSections = 1, OptHdrSize = 0xF0
    *reinterpret_cast<std::uint16_t*>(&buffer[pe + 4]) = 0x8664;
    *reinterpret_cast<std::uint16_t*>(&buffer[pe + 6]) = 1;
    *reinterpret_cast<std::uint16_t*>(&buffer[pe + 20]) = 0xF0;

    // OptionalHeader (PE32+): Magic = 0x20B
    const std::size_t opt = pe + 24;
    *reinterpret_cast<std::uint16_t*>(&buffer[opt + 0]) = 0x20B;
    // AddressOfEntryPoint = 0x1000
    *reinterpret_cast<std::uint32_t*>(&buffer[opt + 16]) = 0x1000;
    // ImageBase = 0x140000000
    *reinterpret_cast<std::uint64_t*>(&buffer[opt + 24]) = 0x140000000ULL;
    // SectionAlignment = 0x1000, FileAlignment = 0x200
    *reinterpret_cast<std::uint32_t*>(&buffer[opt + 32]) = 0x1000;
    *reinterpret_cast<std::uint32_t*>(&buffer[opt + 36]) = 0x200;
    // SizeOfImage = 0x3000, SizeOfHeaders = 0x400
    *reinterpret_cast<std::uint32_t*>(&buffer[opt + 56]) = 0x3000;
    *reinterpret_cast<std::uint32_t*>(&buffer[opt + 60]) = 0x400;
    // NumberOfRvaAndSizes = 16
    *reinterpret_cast<std::uint32_t*>(&buffer[opt + 108]) = 16;

    // Section 1 Header at opt + 0xF0: ".text"
    const std::size_t sec1 = opt + 0xF0;
    std::memcpy(&buffer[sec1], ".text\0\0\0", 8);
    *reinterpret_cast<std::uint32_t*>(&buffer[sec1 + 8]) = raw_data_size; // VirtualSize
    *reinterpret_cast<std::uint32_t*>(&buffer[sec1 + 12]) = 0x1000;        // VirtualAddress
    *reinterpret_cast<std::uint32_t*>(&buffer[sec1 + 16]) = raw_data_size; // SizeOfRawData
    *reinterpret_cast<std::uint32_t*>(&buffer[sec1 + 20]) = 0x400;         // PointerToRawData
    *reinterpret_cast<std::uint32_t*>(&buffer[sec1 + 36]) = 0x60000020U;   // CODE | EXECUTE | READ

    return buffer;
}

}  // namespace

TEST_CASE("iat_reconstructor: api resolution queries") {
    // Check known Windows APIs
    CHECK(IatReconstructor::is_known_winapi("kernel32.dll", "GetProcAddress"));
    CHECK(IatReconstructor::is_known_winapi("KERNEL32.DLL", "LoadLibraryA"));
    CHECK(IatReconstructor::is_known_winapi("ntdll.dll", "NtQueryInformationProcess"));
    CHECK(IatReconstructor::is_known_winapi("user32.dll", "MessageBoxA"));
    CHECK(IatReconstructor::is_known_winapi("ws2_32.dll", "WSAStartup"));
    CHECK(!IatReconstructor::is_known_winapi("kernel32.dll", "NonExistentApiFooBar"));

    // Check address resolution (x64)
    constexpr std::uint64_t kBaseK32 = 0x7FFF00000000ULL + 0x20000000ULL;
    auto res_k32 = IatReconstructor::resolve_api_by_address(kBaseK32 + 0x1F220, 64);
    CHECK(res_k32.has_value());
    if (res_k32) {
        CHECK_EQ(res_k32->first, std::string("KERNEL32.dll"));
        CHECK_EQ(res_k32->second, std::string("GetProcAddress"));
    }

    // Check address resolution (x86)
    constexpr std::uint64_t kBaseU32_x86 = 0x76000000ULL;
    auto res_u32 = IatReconstructor::resolve_api_by_address(kBaseU32_x86 + 0x21000, 32);
    CHECK(res_u32.has_value());
    if (res_u32) {
        CHECK_EQ(res_u32->first, std::string("USER32.dll"));
        CHECK_EQ(res_u32->second, std::string("MessageBoxA"));
    }
}

TEST_CASE("iat_reconstructor: analyze dumped binary with consecutive api pointers") {
    auto pe = create_synthetic_pe64(0x1000);
    const std::size_t text_raw = 0x400; // RVA 0x1000

    // Plant simulated IAT table inside .text at RVA 0x1200 (raw offset 0x400 + 0x200 = 0x600)
    const std::size_t iat_raw = text_raw + 0x200;
    constexpr std::uint64_t kBaseK32 = 0x7FFF00000000ULL + 0x20000000ULL;

    // Pointer 0: GetProcAddress
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 0]) = kBaseK32 + 0x1F220;
    // Pointer 1: LoadLibraryA
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 8]) = kBaseK32 + 0x1F500;
    // Pointer 2: ExitProcess
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 16]) = kBaseK32 + 0x20000;
    // Pointer 3: VirtualAlloc
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 24]) = kBaseK32 + 0x20100;
    // Null terminator
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 32]) = 0;

    BinaryView view = BinaryView::from_owned(std::move(pe));
    IatReconstructor reconstructor;
    auto report = reconstructor.analyze(view);

    CHECK(report.success);
    CHECK_EQ(report.bits, 64);
    CHECK_EQ(report.image_base, 0x140000000ULL);
    CHECK_EQ(report.entry_point, 0x140001000ULL);
    CHECK(!report.discovered_ranges.empty());
    CHECK(report.resolved_functions >= 4);

    bool found_getproc = false;
    bool found_loadlib = false;
    for (const auto& mod : report.modules) {
        for (const auto& fn : mod.functions) {
            if (fn.name == "GetProcAddress") found_getproc = true;
            if (fn.name == "LoadLibraryA") found_loadlib = true;
        }
    }
    CHECK(found_getproc);
    CHECK(found_loadlib);

    std::string summary = IatReconstructor::to_text_summary(report);
    CHECK(summary.find("GetProcAddress") != std::string::npos);
    CHECK(summary.find("KERNEL32.dll") != std::string::npos);
}

TEST_CASE("iat_reconstructor: trace thunk redirections (jmp & push-ret)") {
    auto pe = create_synthetic_pe64(0x1000);
    const std::size_t text_raw = 0x400; // RVA 0x1000
    constexpr std::uint64_t kBaseK32 = 0x7FFF00000000ULL + 0x20000000ULL;

    // Create a redirection stub at RVA 0x1100 (raw offset 0x400 + 0x100 = 0x500):
    // MOV RAX, TargetApi; PUSH RAX; RET
    const std::size_t stub_raw = text_raw + 0x100;
    pe[stub_raw + 0] = 0x48;
    pe[stub_raw + 1] = 0xB8;
    *reinterpret_cast<std::uint64_t*>(&pe[stub_raw + 2]) = kBaseK32 + 0x1F220; // GetProcAddress
    pe[stub_raw + 10] = 0x50; // PUSH RAX
    pe[stub_raw + 11] = 0xC3; // RET

    // Create IAT pointer table at RVA 0x1300 (raw offset 0x700) pointing to stub
    const std::size_t iat_raw = text_raw + 0x300;
    // Pointer 0: points to stub at 0x140001100
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 0]) = 0x140001100ULL;
    // Pointer 1: direct LoadLibraryA
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 8]) = kBaseK32 + 0x1F500;
    // Pointer 2: direct ExitProcess
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 16]) = kBaseK32 + 0x20000;
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 24]) = 0;

    BinaryView view = BinaryView::from_owned(std::move(pe));
    IatReconstructor reconstructor;
    auto report = reconstructor.analyze(view);

    CHECK(report.success);
    CHECK(report.redirected_thunks > 0);

    bool found_stub_resolved = false;
    for (const auto& mod : report.modules) {
        for (const auto& fn : mod.functions) {
            if (fn.name == "GetProcAddress" && fn.resolution_type == ThunkResolutionType::push_ret_thunk) {
                found_stub_resolved = true;
            }
        }
    }
    CHECK(found_stub_resolved);
}

TEST_CASE("iat_reconstructor: rebuild pe with new section and import descriptors") {
    auto pe = create_synthetic_pe64(0x1000);
    const std::size_t text_raw = 0x400;
    const std::size_t iat_raw = text_raw + 0x200;
    constexpr std::uint64_t kBaseK32 = 0x7FFF00000000ULL + 0x20000000ULL;

    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 0]) = kBaseK32 + 0x1F220; // GetProcAddress
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 8]) = kBaseK32 + 0x1F500; // LoadLibraryA
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 16]) = kBaseK32 + 0x20000; // ExitProcess
    *reinterpret_cast<std::uint64_t*>(&pe[iat_raw + 24]) = 0;

    BinaryView view = BinaryView::from_owned(std::move(pe));
    IatReconstructor reconstructor;
    IatReconstructionReport report;
    auto rebuilt = reconstructor.rebuild_pe(view, &report);

    CHECK(rebuilt.has_value());
    CHECK(report.binary_patched);
    CHECK_EQ(report.new_section_name, std::string(".typem"));
    CHECK(report.new_import_rva > 0);
    CHECK(report.patched_binary_size > view.size());

    // Verify the rebuilt binary can be parsed as a valid PE image
    BinaryView rebuilt_view = BinaryView::from_owned(std::move(rebuilt.value()));
    auto img_res = ExecutableImage::parse(rebuilt_view);
    CHECK(img_res.has_value());
    if (img_res) {
        CHECK_EQ(img_res->sections().size(), 2); // .text + .typem
        CHECK_EQ(img_res->sections()[1].name, std::string(".typem"));
    }
}

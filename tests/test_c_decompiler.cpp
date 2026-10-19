// TypeMorph - C / C++ High-Level Code & Struct Reconstructor tests.
#include "test_framework.hpp"

#include "typemorph/decompile/c_decompiler.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace typemorph::decompile;
using namespace typemorph::core;

TEST_CASE("decompile: struct field layout inference from memory displacements") {
    // Machine code simulating member accesses on rcx / this pointer:
    // mov rax, [rcx + 0x00]       ; 48 8B 41 00 (uint64_t at +0x0)
    // mov edx, [rcx + 0x08]       ; 8B 51 08    (uint32_t at +0x8)
    // movss xmm0, [rcx + 0x10]    ; F3 0F 10 41 10 (float at +0x10)
    // movsd xmm1, [rcx + 0x18]    ; F2 0F 10 49 18 (double at +0x18)
    // mov [rcx + 0x20], rax       ; 48 89 41 20 (uint64_t at +0x20)
    const std::vector<std::uint8_t> code = {
        0x48, 0x8B, 0x41, 0x00,
        0x8B, 0x51, 0x08,
        0xF3, 0x0F, 0x10, 0x41, 0x10,
        0xF2, 0x0F, 0x10, 0x49, 0x18,
        0x48, 0x89, 0x41, 0x20,
        0xC3
    };

    auto fields = CDecompiler::infer_struct_layout(code);
    REQUIRE_EQ(fields.size(), std::size_t{5});

    CHECK_EQ(fields[0].offset, std::uint32_t{0x00});
    CHECK_EQ(fields[0].size, std::uint32_t{8});
    CHECK_EQ(fields[0].type_name, std::string("uint64_t"));

    CHECK_EQ(fields[1].offset, std::uint32_t{0x08});
    CHECK_EQ(fields[1].size, std::uint32_t{4});
    CHECK_EQ(fields[1].type_name, std::string("uint32_t"));

    CHECK_EQ(fields[2].offset, std::uint32_t{0x10});
    CHECK_EQ(fields[2].size, std::uint32_t{4});
    CHECK_EQ(fields[2].type_name, std::string("float"));
    CHECK(fields[2].is_float);

    CHECK_EQ(fields[3].offset, std::uint32_t{0x18});
    CHECK_EQ(fields[3].size, std::uint32_t{8});
    CHECK_EQ(fields[3].type_name, std::string("double"));
    CHECK(fields[3].is_float);

    CHECK_EQ(fields[4].offset, std::uint32_t{0x20});
    CHECK_EQ(fields[4].size, std::uint32_t{8});
    CHECK_EQ(fields[4].type_name, std::string("uint64_t"));
}

TEST_CASE("decompile: C struct header emission with alignment padding") {
    std::vector<StructField> fields;
    fields.push_back({0x00, 4, "uint32_t", "id", false, false});
    // Offset gap: 0x04 -> 0x08 (4 bytes of padding)
    fields.push_back({0x08, 8, "uint64_t", "timestamp", true, false});
    // Offset gap: 0x10 -> 0x18 (8 bytes of padding)
    fields.push_back({0x18, 4, "float", "ratio", false, true});

    std::string c_decl = CDecompiler::emit_struct_c("TaskRecord", fields);
    CHECK(c_decl.find("typedef struct TaskRecord {") != std::string::npos);
    CHECK(c_decl.find("uint32_t id; // +0x0") != std::string::npos);
    CHECK(c_decl.find("uint8_t _pad_0[4];") != std::string::npos);
    CHECK(c_decl.find("uint64_t timestamp; // +0x8") != std::string::npos);
    CHECK(c_decl.find("uint8_t _pad_1[8];") != std::string::npos);
    CHECK(c_decl.find("float ratio; // +0x18") != std::string::npos);
    CHECK(c_decl.find("} TaskRecord_t;") != std::string::npos);
}

TEST_CASE("decompile: structured C pseudocode decompilation from x64 machine code") {
    // Function:
    // push rbp
    // mov rbp, rsp
    // sub rsp, 32
    // test rcx, rcx          ; 48 85 C9
    // je loc_zero            ; 74 08
    // mov eax, [rcx + 0x04]  ; 8B 41 04
    // add eax, edx           ; 03 C2
    // jmp done               ; EB 02
    // loc_zero:
    // xor eax, eax           ; 31 C0
    // done:
    // mov rsp, rbp
    // pop rbp
    // ret                    ; C3
    const std::vector<std::uint8_t> code = {
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x83, 0xEC, 0x20,
        0x48, 0x85, 0xC9,
        0x74, 0x08,
        0x8B, 0x41, 0x04,
        0x03, 0xC2,
        0xEB, 0x02,
        0x31, 0xC0,
        0x48, 0x89, 0xEC,
        0x5D,
        0xC3
    };

    CDecompiler decompiler;
    auto decompiled = decompiler.decompile_bytes(code, 0x00401000, 64, ImageFormat::pe, "compute_record");

    CHECK_EQ(decompiled.entry_va, std::uint64_t{0x00401000});
    CHECK_EQ(decompiled.name, std::string("compute_record"));
    REQUIRE(!decompiled.structs.empty());
    CHECK_EQ(decompiled.structs[0].fields.size(), std::size_t{1});
    CHECK_EQ(decompiled.structs[0].fields[0].offset, std::uint32_t{4});

    // Verify structured control-flow elements in pseudocode
    CHECK(decompiled.pseudocode.find("compute_record") != std::string::npos);
    CHECK(decompiled.pseudocode.find("is_null = (rcx == NULL)") != std::string::npos);
    CHECK(decompiled.pseudocode.find("if (is_zero)") != std::string::npos);
    CHECK(decompiled.pseudocode.find("ctx->field_4") != std::string::npos);
    CHECK(decompiled.pseudocode.find("eax += edx;") != std::string::npos);
    CHECK(decompiled.pseudocode.find("eax = 0;") != std::string::npos);
    CHECK(decompiled.pseudocode.find("return") != std::string::npos);
}

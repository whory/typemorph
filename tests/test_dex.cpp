// TypeMorph - Android Dalvik Executable (DEX) & Java Decompiler unit tests
#include "typemorph/dex/dex_analyzer.hpp"
#include "test_framework.hpp"

#include <vector>
#include <string>
#include <cstring>

namespace {

using typemorph::core::BinaryView;
using typemorph::dex::DexAnalyzer;
using typemorph::dex::DexReport;

// Construct a minimal valid synthetic Dalvik DEX file
std::vector<std::uint8_t> create_synthetic_dex() {
    std::vector<std::uint8_t> buf(1024, 0);

    // 0x00: Magic 'dex\n035\0'
    buf[0] = 'd'; buf[1] = 'e'; buf[2] = 'x'; buf[3] = '\n';
    buf[4] = '0'; buf[5] = '3'; buf[6] = '5'; buf[7] = '\0';

    // 0x20: File size = 1024
    buf[0x20] = 0x00; buf[0x21] = 0x04; buf[0x22] = 0x00; buf[0x23] = 0x00;
    // 0x24: Header size = 0x70
    buf[0x24] = 0x70; buf[0x25] = 0x00; buf[0x26] = 0x00; buf[0x27] = 0x00;
    // 0x28: Endian tag
    buf[0x28] = 0x78; buf[0x29] = 0x56; buf[0x2A] = 0x34; buf[0x2B] = 0x12;

    // String IDs: 4 strings at 0x70
    // String 0: "Lcom/example/KeyValidator;"
    // String 1: "V" (void)
    // String 2: "validateKey"
    // String 3: "SUCCESS"
    std::uint32_t string_ids_off = 0x70;
    buf[0x38] = 4; buf[0x3C] = 0x70;

    // String Data starts at 0x200
    std::uint32_t s0_off = 0x200;
    std::uint32_t s1_off = 0x230;
    std::uint32_t s2_off = 0x240;
    std::uint32_t s3_off = 0x260;

    // String ID pointers (uint32 file offsets)
    auto put_u32 = [&](std::size_t off, std::uint32_t val) {
        buf[off] = static_cast<std::uint8_t>(val & 0xFF);
        buf[off + 1] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
        buf[off + 2] = static_cast<std::uint8_t>((val >> 16) & 0xFF);
        buf[off + 3] = static_cast<std::uint8_t>((val >> 24) & 0xFF);
    };

    put_u32(string_ids_off + 0 * 4, s0_off);
    put_u32(string_ids_off + 1 * 4, s1_off);
    put_u32(string_ids_off + 2 * 4, s2_off);
    put_u32(string_ids_off + 3 * 4, s3_off);

    auto put_mutf8 = [&](std::size_t off, const std::string& str) {
        buf[off++] = static_cast<std::uint8_t>(str.size()); // ULEB128 len
        for (char c : str) buf[off++] = static_cast<std::uint8_t>(c);
        buf[off] = 0; // null terminator
    };

    put_mutf8(s0_off, "Lcom/example/KeyValidator;");
    put_mutf8(s1_off, "V");
    put_mutf8(s2_off, "validateKey");
    put_mutf8(s3_off, "SUCCESS");

    // Type IDs: 2 types at 0x90
    // Type 0 -> String 0 (Lcom/example/KeyValidator;)
    // Type 1 -> String 1 (V)
    std::uint32_t type_ids_off = 0x90;
    buf[0x40] = 2; buf[0x44] = 0x90;
    put_u32(type_ids_off + 0 * 4, 0);
    put_u32(type_ids_off + 1 * 4, 1);

    // Proto IDs: 1 proto at 0xA0
    // shorty_idx = 1 ("V"), return_type_idx = 1 ("V"), params_off = 0
    std::uint32_t proto_ids_off = 0xA0;
    buf[0x48] = 1; buf[0x4C] = 0xA0;
    put_u32(proto_ids_off, 1);     // shorty
    put_u32(proto_ids_off + 4, 1); // return type
    put_u32(proto_ids_off + 8, 0); // params off (none)

    // Method IDs: 1 method at 0xB0
    // class_idx = 0 (KeyValidator), proto_idx = 0, name_idx = 2 ("validateKey")
    std::uint32_t method_ids_off = 0xB0;
    buf[0x58] = 1; buf[0x5C] = 0xB0;
    buf[method_ids_off + 0] = 0; buf[method_ids_off + 1] = 0; // class 0
    buf[method_ids_off + 2] = 0; buf[method_ids_off + 3] = 0; // proto 0
    put_u32(method_ids_off + 4, 2);                           // name: validateKey

    // Class Defs: 1 class at 0xC0
    // class_idx = 0, access_flags = 0x0001 (public), superclass_idx = 0xFFFFFFFF, class_data_off = 0x300
    std::uint32_t class_defs_off = 0xC0;
    buf[0x60] = 1; buf[0x64] = 0xC0;
    put_u32(class_defs_off + 0, 0);          // class_idx
    put_u32(class_defs_off + 4, 0x0001);     // public
    put_u32(class_defs_off + 8, 0xFFFFFFFF); // superclass
    put_u32(class_defs_off + 12, 0);         // interfaces
    put_u32(class_defs_off + 16, 0xFFFFFFFF);// source file
    put_u32(class_defs_off + 20, 0);         // annotations
    put_u32(class_defs_off + 24, 0x300);     // class_data_off

    // Class Data at 0x300
    // static_fields_size = 0, instance_fields_size = 0, direct_methods_size = 1, virtual_methods_size = 0
    std::size_t cd_off = 0x300;
    buf[cd_off++] = 0; // static fields
    buf[cd_off++] = 0; // instance fields
    buf[cd_off++] = 1; // direct methods
    buf[cd_off++] = 0; // virtual methods

    // direct method 0:
    // method_idx_diff = 0 (method 0), access_flags = 0x0009 (public static), code_off = 0x350
    buf[cd_off++] = 0;
    buf[cd_off++] = 0x09;
    // ULEB128 for 0x350: 0xD0, 0x06
    buf[cd_off++] = 0xD0;
    buf[cd_off++] = 0x06;

    // Code Item at 0x350
    // registers_size = 2, ins_size = 0, outs_size = 0, tries_size = 0, debug_info_off = 0, insns_size = 3
    std::size_t code_off = 0x350;
    buf[code_off + 0] = 2; buf[code_off + 1] = 0; // registers
    put_u32(code_off + 12, 3); // insns_size in 16-bit code units (3 units = 6 bytes)

    // Bytecode instructions:
    // 1) const-string v0, string@3 ("SUCCESS") -> opcode 0x1A, vA = 0, string index = 3
    // 2 code units: [0x1A, 0x00], [0x03, 0x00]
    buf[code_off + 16] = 0x1A;
    buf[code_off + 17] = 0x00;
    buf[code_off + 18] = 0x03;
    buf[code_off + 19] = 0x00;

    // 2) return-void -> opcode 0x0E
    // 1 code unit: [0x0E, 0x00]
    buf[code_off + 20] = 0x0E;
    buf[code_off + 21] = 0x00;

    return buf;
}

} // namespace

TEST_CASE("dex: reject non-dex binary") {
    std::vector<std::uint8_t> dummy(512, 0x00);
    auto view = BinaryView::from_owned(dummy);
    CHECK(!DexAnalyzer::is_dex(view));

    auto rep = DexAnalyzer::analyze(view);
    CHECK(!rep.is_dex);
    CHECK_EQ(rep.classes.size(), 0U);
}

TEST_CASE("dex: parse valid synthetic dex file and decompile dalvik bytecode") {
    auto dex_bytes = create_synthetic_dex();
    auto view = BinaryView::from_owned(dex_bytes);

    CHECK(DexAnalyzer::is_dex(view));

    auto rep = DexAnalyzer::analyze(view);
    CHECK(rep.is_dex);
    CHECK_EQ(rep.version, "035");
    CHECK_EQ(rep.classes.size(), 1U);

    const auto& cls = rep.classes[0];
    CHECK_EQ(cls.name, "com.example.KeyValidator");
    CHECK_EQ(cls.methods.size(), 1U);

    const auto& meth = cls.methods[0];
    CHECK_EQ(meth.name, "validateKey");
    CHECK_EQ(meth.return_type, "void");
    CHECK(!meth.instructions.empty());

    // Check disassembled instructions
    bool found_const_string = false;
    bool found_return_void = false;
    for (const auto& ins : meth.instructions) {
        if (ins.find("const-string") != std::string::npos && ins.find("SUCCESS") != std::string::npos) {
            found_const_string = true;
        }
        if (ins.find("return-void") != std::string::npos) {
            found_return_void = true;
        }
    }
    CHECK(found_const_string);
    CHECK(found_return_void);

    // Check high-level Java source reconstruction
    std::string java = DexAnalyzer::to_java_source(rep);
    CHECK(java.find("package com.example;") != std::string::npos);
    CHECK(java.find("class KeyValidator") != std::string::npos);
    CHECK(java.find("void validateKey()") != std::string::npos);
    CHECK(java.find("String v0 = \"SUCCESS\";") != std::string::npos);
    CHECK(java.find("return;") != std::string::npos);

    // Check text report
    std::string report_txt = DexAnalyzer::format_report(rep);
    CHECK(report_txt.find("com.example.KeyValidator") != std::string::npos);
    CHECK(report_txt.find("validateKey") != std::string::npos);
}

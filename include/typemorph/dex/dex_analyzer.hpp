// TypeMorph - Android Dalvik Executable (DEX) & Java Decompiler Engine (JADX style)
//
// Extracts and reconstructs:
// - DEX Header (magic dex\n035-039, SHA-1 checksum, pool sizes)
// - String pool, Type descriptors (e.g. Ljava/lang/String; -> java.lang.String)
// - Field and Method prototypes with parameter/return types
// - Class definitions, access flags (public, static, final, interface)
// - Dalvik bytecode disassembler (registers, opcodes, branching, invocation)
// - High-level Java class & method source code reconstruction
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::dex {

using core::BinaryView;

struct DexMethod {
    std::string class_name;
    std::string name;
    std::string return_type;
    std::vector<std::string> param_types;
    std::uint32_t access_flags = 0;
    std::uint16_t registers_size = 0;
    std::vector<std::string> instructions; // Disassembled Dalvik instructions
    std::string decompiled_java;           // High-level Java representation
};

struct DexField {
    std::string name;
    std::string type;
    std::uint32_t access_flags = 0;
};

struct DexClass {
    std::string name;            // e.g. "com.example.app.MainActivity"
    std::string super_class;     // e.g. "android.app.Activity"
    std::vector<std::string> interfaces;
    std::uint32_t access_flags = 0;
    std::string source_file;
    std::vector<DexField> fields;
    std::vector<DexMethod> methods;
};

struct DexReport {
    bool is_dex = false;
    std::string version; // "035", "037", "038", "039"
    std::uint32_t file_size = 0;
    std::uint32_t checksum = 0;
    std::size_t string_count = 0;
    std::size_t type_count = 0;
    std::size_t method_count = 0;
    std::vector<DexClass> classes;
    std::vector<std::string> strings;
};

class DexAnalyzer {
public:
    static bool is_dex(const BinaryView& view);
    static DexReport analyze(const BinaryView& view);
    static std::string format_report(const DexReport& report);
    static std::string to_java_source(const DexReport& report);
};

} // namespace typemorph::dex

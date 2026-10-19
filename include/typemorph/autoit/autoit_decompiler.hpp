// TypeMorph - AutoIt v3 Script Extractor & Decompiler (Exe2Aut engine)
//
// Extracts and reconstructs:
// - AutoIt v3 executable signatures (AU3!EA06, AU3!EA05, AU3!EA04)
// - Embedded file payloads (scripts, DLLs, icons, resources)
// - AutoIt bytecode tokens and operators (Func, EndFunc, If, While, For)
// - String tables, variable mappings ($var), and function calls
// - High-level AutoIt (.au3) source code reconstruction
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::autoit {

using core::BinaryView;

struct AutoItEmbeddedFile {
    std::string filename;
    std::size_t offset = 0;
    std::size_t compressed_size = 0;
    std::size_t uncompressed_size = 0;
    bool is_script = false;
    std::string decompiled_source;
};

struct AutoItReport {
    bool is_autoit = false;
    std::string version; // "AU3!EA06", "AU3!EA05", "AU3!EA04"
    std::uint64_t script_offset = 0;
    std::vector<AutoItEmbeddedFile> files;
    std::string primary_script;
    std::vector<std::string> strings;
};

class AutoItDecompiler {
public:
    static bool is_autoit(const BinaryView& view);
    static AutoItReport analyze(const BinaryView& view);
    static std::string format_report(const AutoItReport& report);
    static std::string decompile_tokens(std::span<const std::uint8_t> data);
};

} // namespace typemorph::autoit

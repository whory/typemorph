// TypeMorph - MSVC Rich Header & Compiler Fingerprinting Engine.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::pe {

struct RichRecord {
    std::uint16_t tool_id = 0;
    std::uint16_t build_number = 0;
    std::uint32_t count = 0;
    std::string tool_name;
    std::string vs_version;
};

struct RichHeaderReport {
    bool present = false;
    std::uint32_t xor_key = 0;
    std::uint64_t offset = 0;
    std::size_t size = 0;
    std::uint32_t checksum = 0;
    std::string hash;              // RichPE hex hash
    std::vector<RichRecord> records;
    std::vector<std::string> compiler_versions;
};

class RichHeaderParser {
public:
    RichHeaderParser() = default;

    [[nodiscard]] RichHeaderReport parse(const core::BinaryView& view) const;

    // Resolves Tool ID to human-readable string (e.g. 0x0017 -> "Utc1900_C", 0x00A0 -> "Cvtres")
    static std::string tool_id_to_name(std::uint16_t tool_id);

    // Resolves build number to Visual Studio release (e.g. 30133 -> "Visual Studio 2019")
    static std::string build_to_vs_version(std::uint16_t build_number);
};

}  // namespace typemorph::pe

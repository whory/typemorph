// TypeMorph - Golang pclntab & Symbol Metadata Reconstructor.
//
// Extracts function names, entry points, packages, and source line metadata
// from stripped Go binaries across Go 1.2 - Go 1.23+ runtime formats.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::golang {

enum class GoPclnVersion : std::uint8_t {
    unknown,
    go12,     // 0xFFFFFFFB (Go 1.2 - 1.15)
    go116,    // 0xFFFFFFFA (Go 1.16 - 1.17)
    go118,    // 0xFFFFFFF0 / 0xFFFFFFF1 (Go 1.18 - 1.23+)
};

[[nodiscard]] constexpr std::string_view to_string(GoPclnVersion ver) noexcept {
    switch (ver) {
    case GoPclnVersion::go12: return "Go 1.2 - 1.15";
    case GoPclnVersion::go116: return "Go 1.16 - 1.17";
    case GoPclnVersion::go118: return "Go 1.18 - 1.23+";
    case GoPclnVersion::unknown: return "Unknown";
    }
    return "Unknown";
}

struct GoFunction {
    std::string name;
    std::string package_name;
    std::uint64_t entry_va = 0;
    std::uint32_t frame_size = 0;
    std::uint32_t args_size = 0;
};

struct GoAnalysisReport {
    bool detected = false;
    GoPclnVersion version = GoPclnVersion::unknown;
    std::uint16_t ptr_size = 8;
    std::uint8_t quantum = 1;
    std::uint64_t pclntab_va = 0;
    std::size_t function_count = 0;
    std::vector<GoFunction> functions;
    std::vector<std::string> packages;
    std::size_t user_functions = 0;
    std::size_t runtime_functions = 0;
};

class GoAnalyzer {
public:
    GoAnalyzer() = default;

    [[nodiscard]] GoAnalysisReport analyze(const core::ExecutableImage& image) const;
    [[nodiscard]] GoAnalysisReport analyze_view(const core::BinaryView& view) const;

    // Parses package prefix from full Go function name (e.g. "net/http.(*Server).Serve" -> "net/http")
    static std::string extract_package(std::string_view full_name);

private:
    [[nodiscard]] GoAnalysisReport parse_pclntab(const core::ExecutableImage& image,
                                                 const std::uint8_t* base,
                                                 std::size_t offset,
                                                 std::size_t max_len,
                                                 std::uint64_t pclntab_va) const;
};

}  // namespace typemorph::golang

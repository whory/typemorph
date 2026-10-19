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

struct GoField {
    std::string name;
    std::string type_name = "any";
    std::string tag;
    std::uint64_t offset = 0;
};

struct GoStructType {
    std::string name;
    std::string package_name;
    std::uint64_t type_va = 0;
    std::uint64_t size = 0;
    std::vector<GoField> fields;
};

struct GoMethod {
    std::string name;
    std::string type_signature = "func()";
    std::uint64_t fn_va = 0;
};

struct GoInterfaceType {
    std::string name;
    std::string package_name;
    std::uint64_t type_va = 0;
    std::vector<GoMethod> methods;
};

struct GoITab {
    std::uint64_t itab_va = 0;
    std::string interface_name;
    std::string concrete_type_name;
    std::vector<GoMethod> methods;
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
    std::vector<GoStructType> structs;
    std::vector<GoInterfaceType> interfaces;
    std::vector<GoITab> itabs;
    std::string golang_source;
};

class GoAnalyzer {
public:
    GoAnalyzer() = default;

    [[nodiscard]] GoAnalysisReport analyze(const core::ExecutableImage& image) const;
    [[nodiscard]] GoAnalysisReport analyze_view(const core::BinaryView& view) const;

    // Parses package prefix from full Go function name (e.g. "net/http.(*Server).Serve" -> "net/http")
    static std::string extract_package(std::string_view full_name);

    // Emits clean, compilable Go source code from reconstructed report
    [[nodiscard]] static std::string to_golang_source(const GoAnalysisReport& report);

    // Recovers types, structs, interfaces, and itabs from memory / moduledata
    void recover_types(const core::ExecutableImage& image, GoAnalysisReport& report) const;

private:
    [[nodiscard]] GoAnalysisReport parse_pclntab(const core::ExecutableImage& image,
                                                 const std::uint8_t* base,
                                                 std::size_t offset,
                                                 std::size_t max_len,
                                                 std::uint64_t pclntab_va) const;
};

}  // namespace typemorph::golang

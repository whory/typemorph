// TypeMorph - .NET / C# Metadata & Code Reconstructor.
//
// Extracts CLI metadata, TypeDef, MethodDef, Field, and TypeRef tables from
// PE .NET / CLR assemblies (ECMA-335) and reconstructs compilable C# source code.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::dotnet {

struct DotNetField {
    std::string name;
    std::string type_name = "object";
    uint16_t flags = 0;
    bool is_public = false;
    bool is_private = false;
    bool is_static = false;
    bool is_readonly = false;
};

struct DotNetParameter {
    std::string name;
    std::string type_name = "object";
    uint16_t sequence = 0;
};

struct DotNetMethod {
    std::string name;
    std::string return_type = "void";
    std::vector<DotNetParameter> parameters;
    std::uint32_t rva = 0;
    std::uint16_t flags = 0;
    bool is_public = false;
    bool is_private = false;
    bool is_static = false;
    bool is_virtual = false;
    bool is_constructor = false;
};

struct DotNetType {
    std::string name;
    std::string namespace_name;
    std::string full_name;
    std::string base_type;
    std::uint32_t flags = 0;
    bool is_public = false;
    bool is_interface = false;
    bool is_abstract = false;
    bool is_sealed = false;
    bool is_enum = false;
    bool is_value_type = false;
    std::vector<DotNetField> fields;
    std::vector<DotNetMethod> methods;
};

struct DotNetReport {
    bool is_dotnet = false;
    std::string runtime_version;
    std::uint32_t cli_header_rva = 0;
    std::uint32_t metadata_rva = 0;
    std::uint32_t entry_point_token = 0;
    std::size_t type_count = 0;
    std::size_t method_count = 0;
    std::size_t field_count = 0;
    std::vector<DotNetType> types;
    std::string csharp_source;
};

class DotNetAnalyzer {
public:
    DotNetAnalyzer() = default;

    [[nodiscard]] DotNetReport analyze(const core::ExecutableImage& image) const;
    [[nodiscard]] DotNetReport analyze_view(const core::BinaryView& view) const;

    // Generates formatted, compilable C# source code from reconstructed metadata
    [[nodiscard]] static std::string to_csharp(const DotNetReport& report);

private:
    [[nodiscard]] DotNetReport parse_metadata(
        const std::uint8_t* data,
        std::size_t size,
        std::uint64_t meta_offset,
        std::uint64_t meta_size,
        const std::string& runtime_ver,
        std::uint32_t cli_rva,
        std::uint32_t meta_rva,
        std::uint32_t ep_token) const;
};

}  // namespace typemorph::dotnet

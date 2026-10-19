// TypeMorph - C / C++ High-Level Code & Struct Reconstructor.
//
// Decompiles machine code into structured C pseudocode (if/else, loops, calls),
// recovers struct memory layouts from displacement operands ([reg + offset]),
// and reconstructs polymorphic C++ classes with virtual method dispatch.
#pragma once

#include "typemorph/abi/calling_convention.hpp"
#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/rtti/rtti_analyzer.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::decompile {

struct StructField {
    std::uint32_t offset = 0;
    std::uint32_t size = 4;
    std::string type_name = "uint32_t";
    std::string name;
    bool is_pointer = false;
    bool is_float = false;
};

struct ReconstructedStruct {
    std::string name;
    std::uint64_t function_va = 0;
    std::string base_register;
    std::uint32_t total_size = 0;
    std::vector<StructField> fields;
    std::string c_declaration;
};

struct DecompiledFunction {
    std::uint64_t entry_va = 0;
    std::string name;
    std::string prototype;
    std::string pseudocode;
    std::vector<ReconstructedStruct> structs;
};

struct DecompileReport {
    std::size_t total_functions = 0;
    std::vector<DecompiledFunction> functions;
    std::vector<ReconstructedStruct> global_structs;
    std::string combined_source;
};

class CDecompiler {
public:
    CDecompiler() = default;

    // Decompiles a single function from an executable image
    [[nodiscard]] DecompiledFunction decompile_function(
        const core::ExecutableImage& image,
        std::uint64_t entry_va,
        std::string_view name = "") const;

    // Decompiles raw function byte span directly
    [[nodiscard]] DecompiledFunction decompile_bytes(
        std::span<const std::uint8_t> code,
        std::uint64_t entry_va,
        std::uint16_t bits,
        core::ImageFormat format,
        std::string_view name = "") const;

    // Analyzes and decompiles all functions in binary (or target VA if specified)
    [[nodiscard]] DecompileReport decompile(
        const core::ExecutableImage& image,
        std::optional<std::uint64_t> target_va = std::nullopt) const;

    // Reconstructs struct fields from base register memory accesses [base + disp]
    [[nodiscard]] static std::vector<StructField> infer_struct_layout(
        std::span<const std::uint8_t> code,
        std::string_view base_reg = "");

    // Generates complete C struct definition string
    [[nodiscard]] static std::string emit_struct_c(
        std::string_view struct_name,
        const std::vector<StructField>& fields);
};

}  // namespace typemorph::decompile

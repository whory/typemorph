// TypeMorph - PE IAT Reconstruction & Import Table Fixer Engine.
// Implements advanced IAT discovery, API resolution, redirection tracing,
// and PE import table reconstruction inspired by Scylla and VMPImportFixer.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::pe {

enum class ThunkResolutionType : std::uint8_t {
    direct_va,          // Pointer holds an actual export virtual address
    direct_rva,         // Pointer holds RVA to export
    jmp_thunk,          // Pointer to JMP [rel32/abs64/reg] or JMP imm stub
    push_ret_thunk,     // Pointer to PUSH imm; RET stub (VMP / Themida style)
    custom_stub         // Generic obfuscated dispatcher
};

[[nodiscard]] constexpr std::string_view to_string(ThunkResolutionType type) noexcept {
    switch (type) {
    case ThunkResolutionType::direct_va: return "direct_va";
    case ThunkResolutionType::direct_rva: return "direct_rva";
    case ThunkResolutionType::jmp_thunk: return "jmp_thunk";
    case ThunkResolutionType::push_ret_thunk: return "push_ret_thunk";
    case ThunkResolutionType::custom_stub: return "custom_stub";
    }
    return "unknown";
}

struct ImportedFunction {
    std::string name;
    std::uint16_t ordinal = 0;
    std::uint64_t iat_va = 0;              // Address where pointer is stored in IAT
    std::uint32_t iat_rva = 0;             // RVA of this IAT entry
    std::uint64_t target_va = 0;           // Address pointed to
    std::uint64_t resolved_target_va = 0;  // Resolved target VA if traced through stub
    ThunkResolutionType resolution_type = ThunkResolutionType::direct_va;
    bool valid = false;
    std::string comment;                   // Tracing / heuristic notes
};

struct ImportedModule {
    std::string module_name;               // e.g. "KERNEL32.dll"
    std::uint32_t first_thunk_rva = 0;     // RVA of IAT table for this module
    std::uint32_t original_first_thunk_rva = 0; // RVA of INT table (if reconstructed)
    std::vector<ImportedFunction> functions;

    [[nodiscard]] std::size_t valid_count() const noexcept {
        std::size_t count = 0;
        for (const auto& fn : functions) {
            if (fn.valid) ++count;
        }
        return count;
    }
};

struct IatSearchRange {
    std::uint64_t start_va = 0;
    std::uint64_t end_va = 0;
    std::size_t size = 0;
    std::string section_name;
    std::size_t candidate_pointer_count = 0;
    std::size_t resolved_api_count = 0;
};

struct IatReconstructionReport {
    bool success = false;
    std::uint16_t bits = 64;
    std::uint64_t image_base = 0;
    std::uint64_t entry_point = 0;
    
    // Existing PE import directory info
    std::uint32_t original_import_rva = 0;
    std::uint32_t original_import_size = 0;
    bool original_import_valid = false;

    // Discovered IAT ranges
    std::vector<IatSearchRange> discovered_ranges;

    // Reconstructed modules & functions
    std::vector<ImportedModule> modules;
    std::size_t total_functions = 0;
    std::size_t resolved_functions = 0;
    std::size_t redirected_thunks = 0;

    // Output binary patching info (if rebuilt)
    bool binary_patched = false;
    std::uint32_t new_import_rva = 0;
    std::uint32_t new_import_size = 0;
    std::string new_section_name;
    std::size_t patched_binary_size = 0;
};

struct IatReconstructionOptions {
    std::optional<std::uint64_t> search_start_va;
    std::optional<std::uint64_t> search_end_va;
    bool trace_redirections = true;        // Follow JMP / PUSH-RET stubs to real API
    std::size_t max_trace_depth = 5;       // Max hops when following stubs
    bool build_new_section = true;         // Append new section (.typem) for reconstructed import tables
    std::string new_section_name = ".typem";
    std::uint64_t default_image_base = 0;  // Fallback if not specified in PE
};

class IatReconstructor {
public:
    explicit IatReconstructor(IatReconstructionOptions options = {})
        : options_(std::move(options)) {}

    // Analyzes the given PE binary view and locates/reconstructs the IAT
    [[nodiscard]] IatReconstructionReport analyze(const core::BinaryView& view) const;

    // Reconstructs the IAT and patches the PE binary with a new import directory,
    // returning the complete rebuilt binary buffer
    [[nodiscard]] core::Result<std::vector<std::uint8_t>> rebuild_pe(
        const core::BinaryView& view,
        IatReconstructionReport* out_report = nullptr) const;

    // Converts reconstruction report to human-readable string summary
    [[nodiscard]] static std::string to_text_summary(const IatReconstructionReport& rep);

    // Queries standard Windows API database for a known virtual address or export name
    static std::optional<std::pair<std::string, std::string>> resolve_api_by_address(
        std::uint64_t address, std::uint16_t bits);

    // Queries standard Windows API database to check if a DLL and function name match
    static bool is_known_winapi(std::string_view module_name, std::string_view func_name);

private:
    IatReconstructionOptions options_;
};

}  // namespace typemorph::pe

// TypeMorph - Calling Convention & Function Signature Classifier.
//
// Recovers function calling conventions (__cdecl, __stdcall, __fastcall, __thiscall,
// __win64, __sysv, Go ABIInternal/ABI0), argument counts, register allocations,
// stack frame sizes, and reconstructed C/C++ prototypes from stripped binaries.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::abi {

enum class CallingConvention : std::uint8_t {
    unknown,
    x86_cdecl,
    x86_stdcall,
    x86_fastcall,
    x86_thiscall,
    x64_windows,
    x64_sysv,
    go_abiinternal,
    go_abi0,
    arm64_aapcs
};

[[nodiscard]] constexpr std::string_view to_string(CallingConvention cc) noexcept {
    switch (cc) {
    case CallingConvention::x86_cdecl: return "__cdecl";
    case CallingConvention::x86_stdcall: return "__stdcall";
    case CallingConvention::x86_fastcall: return "__fastcall";
    case CallingConvention::x86_thiscall: return "__thiscall";
    case CallingConvention::x64_windows: return "__win64";
    case CallingConvention::x64_sysv: return "__sysv";
    case CallingConvention::go_abiinternal: return "go_abiinternal";
    case CallingConvention::go_abi0: return "go_abi0";
    case CallingConvention::arm64_aapcs: return "__aapcs64";
    case CallingConvention::unknown: return "unknown";
    }
    return "unknown";
}

inline std::ostream& operator<<(std::ostream& os, CallingConvention cc) {
    return os << to_string(cc);
}

enum class ReturnKind : std::uint8_t {
    unknown,
    void_type,
    integer,        // rax / eax
    pointer,        // rax pointing to object/struct
    boolean_type,   // al / setcc
    floating_point  // xmm0
};

[[nodiscard]] constexpr std::string_view to_string(ReturnKind rk) noexcept {
    switch (rk) {
    case ReturnKind::void_type: return "void";
    case ReturnKind::integer: return "integer";
    case ReturnKind::pointer: return "pointer";
    case ReturnKind::boolean_type: return "bool";
    case ReturnKind::floating_point: return "float";
    case ReturnKind::unknown: return "unknown";
    }
    return "unknown";
}

inline std::ostream& operator<<(std::ostream& os, ReturnKind rk) {
    return os << to_string(rk);
}

struct FunctionArgument {
    std::size_t index = 0;
    std::string name;          // e.g. "this_ptr", "arg0", "rcx"
    std::string location;      // e.g. "rcx", "rdi", "ecx", "stack[+0x8]"
    std::string type_hint;     // e.g. "void*", "uint32_t", "int64_t", "double"
};

struct FunctionSignature {
    std::uint64_t entry_va = 0;
    std::string name;          // e.g. "sub_00401000" or symbol name
    CallingConvention convention = CallingConvention::unknown;
    ReturnKind return_kind = ReturnKind::unknown;
    std::string return_type_hint = "void";
    std::vector<FunctionArgument> arguments;
    std::uint32_t stack_frame_size = 0;
    std::uint32_t stack_purge_bytes = 0; // callee purged bytes (ret N)
    double confidence = 0.0;
    std::string prototype;     // e.g. "int32_t __stdcall sub_00401020(uint32_t arg0, uint32_t arg1)"
    std::string rationale;
};

struct AbiReport {
    std::size_t total_functions = 0;
    std::vector<FunctionSignature> signatures;
    std::map<std::string, std::size_t> convention_distribution;
};

class AbiClassifier {
public:
    AbiClassifier() = default;

    // Analyzes a single function given its entry VA in an executable image
    [[nodiscard]] FunctionSignature analyze_function(
        const core::ExecutableImage& image,
        std::uint64_t entry_va,
        std::string_view name = "") const;

    // Analyzes function code bytes directly (independent of image container)
    [[nodiscard]] FunctionSignature analyze_function_bytes(
        std::span<const std::uint8_t> code,
        std::uint64_t entry_va,
        std::uint16_t bits,
        core::ImageFormat format,
        std::string_view name = "") const;

    // Scans all functions in an executable image (or single target if provided)
    [[nodiscard]] AbiReport analyze(
        const core::ExecutableImage& image,
        std::optional<std::uint64_t> target_va = std::nullopt) const;
};

}  // namespace typemorph::abi

// TypeMorph - Security, Hardening (checksec), Packer & Anomaly Analyzer.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::security {

struct SecurityMitigations {
    bool aslr = false;
    bool high_entropy_va = false;
    bool dep_nx = false;
    bool cfg = false;                 // Control Flow Guard
    bool cet_shadow_stack = false;    // Control-flow Enforcement Technology (CET)
    bool safe_seh = false;            // Safe Structured Exception Handling
    bool isolated = false;            // AppContainer / Isolation
    bool signed_binary = false;       // Authenticode / Digital Signature present
    bool pie = false;                 // Position Independent Executable (ELF)
    bool relro = false;               // Read-Only Relocations (ELF)
    bool stack_canary = false;        // Stack smash protector (__stack_chk_fail)
};

struct SectionAnomaly {
    std::string name;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    bool is_wx = false;               // Writable & Executable (W^X violation)
    bool is_empty_raw = false;        // Virtual size > 0 but raw size == 0
    double expansion_ratio = 1.0;     // virtual_size / file_size
    std::string note;
};

struct PackerSignature {
    std::string name;                 // e.g. "UPX", "VMProtect", "Themida", "PyInstaller"
    double confidence = 0.95;
    std::string rationale;
};

struct OverlayInfo {
    bool present = false;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    double entropy = 0.0;
};

struct SecurityReport {
    core::ImageFormat format = core::ImageFormat::unknown;
    std::uint16_t bits = 64;
    SecurityMitigations mitigations;
    std::vector<SectionAnomaly> section_anomalies;
    std::vector<PackerSignature> packers;
    OverlayInfo overlay;
    std::vector<std::string> anti_analysis_indicators;
    bool has_tls_callbacks = false;
    std::uint64_t entry_point = 0;
    bool entry_point_outside_code = false;
};

class SecurityAnalyzer {
public:
    SecurityAnalyzer() = default;

    [[nodiscard]] SecurityReport analyze(const core::ExecutableImage& image) const;
    [[nodiscard]] SecurityReport analyze_view(const core::BinaryView& view) const;
};

}  // namespace typemorph::security

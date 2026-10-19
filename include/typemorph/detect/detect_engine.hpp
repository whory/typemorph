// TypeMorph - Advanced Deep File / Compiler / Packer / Protection Detection Engine (DIE Engine style)
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::detect {

enum class DetectionCategory {
    compiler,
    linker,
    packer,
    protector,
    runtime,
    installer,
    tool,
    overlay_payload,
    unknown
};

[[nodiscard]] const char* to_string(DetectionCategory cat) noexcept;

struct DetectionRecord {
    DetectionCategory category = DetectionCategory::unknown;
    std::string name;          // e.g. "UPX", "VMProtect", "Themida", "Microsoft Visual C/C++", "Go", "Rust"
    std::string version;       // e.g. "3.96", "3.0-3.5", "19.28", "1.75+"
    double confidence = 0.95;  // 0.0 .. 1.0
    std::string rationale;     // e.g. "EP pattern match [55 89 E5 ...]", "Section signature '.vmp0'", "Magic header 'UPX!'"
    std::uint64_t matched_offset = 0;
};

struct DetectionReport {
    core::ImageFormat format = core::ImageFormat::unknown;
    std::uint16_t bits = 0;
    std::string arch;
    std::uint64_t entry_point = 0;
    std::uint64_t entry_point_file_offset = 0;
    std::vector<std::uint8_t> ep_bytes_sample; // First 16-32 bytes at EP

    std::vector<DetectionRecord> matches;

    // Primary detected roles
    std::string primary_compiler;
    std::string primary_packer;
    std::string primary_protector;
    std::string primary_runtime;

    [[nodiscard]] bool is_packed() const noexcept {
        return !primary_packer.empty() || !primary_protector.empty();
    }
};

class DetectorEngine {
public:
    DetectorEngine() = default;

    [[nodiscard]] DetectionReport detect(const core::ExecutableImage& image) const;
    [[nodiscard]] DetectionReport detect_view(const core::BinaryView& view) const;

    // Format human-readable summary
    [[nodiscard]] static std::string to_text_summary(const DetectionReport& report);
};

}  // namespace typemorph::detect

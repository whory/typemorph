// TypeMorph - multi-sample differential format inference.
//
// Given two or more instances of an unknown format, invariants identify magic
// values, size-delta correlation identifies array lengths, monotonic sequences
// identify timestamps/IDs, and the remaining high-entropy gaps become opaque
// payload fields.  The result is a TypeNode tree directly consumable by the
// emitters and the TUI.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace typemorph::infer {

struct Sample {
    core::BinaryView view;
    std::string name;
    std::optional<std::int64_t> timestamp;
};

struct DiffOptions {
    std::uint64_t min_array_elements = 3;
    double confidence_threshold = 0.85;
    std::uint64_t max_fields = 256;
    std::uint64_t field_scan_limit = 4096;
    core::ByteOrder endian = core::ByteOrder::little;
    bool detect_arrays = true;
    bool detect_timestamps = true;
    bool detect_invariants = true;
    bool nested_records = true;
    std::uint64_t max_nested_element_size = 256;
};

enum class EvidenceKind : std::uint8_t {
    invariant_bytes,
    constant_value,
    size_correlation,
    monotonic_sequence,
    alignment,
    entropy,
    pointer,
    text,
    structural_boundary,
};

[[nodiscard]] constexpr std::string_view to_string(EvidenceKind kind) noexcept {
    switch (kind) {
    case EvidenceKind::invariant_bytes: return "invariant-bytes";
    case EvidenceKind::constant_value: return "constant-value";
    case EvidenceKind::size_correlation: return "size-correlation";
    case EvidenceKind::monotonic_sequence: return "monotonic-sequence";
    case EvidenceKind::alignment: return "alignment";
    case EvidenceKind::entropy: return "entropy";
    case EvidenceKind::pointer: return "pointer";
    case EvidenceKind::text: return "text";
    case EvidenceKind::structural_boundary: return "structural-boundary";
    }
    return "unknown";
}

struct Evidence {
    EvidenceKind kind = EvidenceKind::structural_boundary;
    std::uint64_t offset = 0;
    double confidence = 0.0;
    std::string description;
};

struct InferredField {
    std::uint64_t offset = 0;
    std::uint8_t width = 1;
    core::PrimitiveKind kind = core::PrimitiveKind::u8;
    std::string name;
    std::string type_name;
    double confidence = 0.0;
    bool invariant = false;
    std::optional<std::uint64_t> array_element_size;
    std::optional<std::uint64_t> count_field_offset;
    std::optional<std::uint64_t> element_count;
    std::string rationale;
};

struct InferenceResult {
    core::TypePtr root;
    core::ByteOrder endian = core::ByteOrder::little;
    std::vector<InferredField> fields;
    std::vector<Evidence> evidence;
    double confidence = 0.0;
    std::size_t sample_count = 0;
    std::uint64_t min_size = 0;
    std::uint64_t max_size = 0;
    std::string format_name = "recovered";
};

class DiffEngine {
public:
    explicit DiffEngine(DiffOptions options = {});

    // Accepts one or more samples.  With one sample only structural/entropy
    // heuristics are available; confidence is capped accordingly.
    [[nodiscard]] core::Result<InferenceResult> infer(std::span<const Sample> samples) const;

    // Convenience overload for callers that only have views.
    [[nodiscard]] core::Result<InferenceResult> infer(
        std::span<const core::BinaryView> views) const;

    [[nodiscard]] const DiffOptions& options() const noexcept { return options_; }

private:
    DiffOptions options_;
};

}  // namespace typemorph::infer

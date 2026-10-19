// TypeMorph - Bitfield and Flag Detector.
//
// Identifies packed boolean flags, mask registers, and sub-byte bitfields
// across multi-sample runs or repeated record arrays.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace typemorph::infer {

struct BitfieldAnalysisResult {
    bool is_bitfield = false;
    double confidence = 0.0;
    core::PrimitiveKind underlying = core::PrimitiveKind::u32;
    std::vector<core::BitfieldMember> members;
    std::string rationale;

    [[nodiscard]] core::TypePtr to_type_node(std::string name = {},
                                             std::uint64_t offset = 0,
                                             core::ByteOrder endian = core::ByteOrder::little) const {
        return core::TypeNode::bitfield(underlying, members, endian, std::move(name), offset, confidence);
    }
};

struct BitfieldOptions {
    double min_confidence = 0.65;
    std::size_t min_samples = 3;
    bool detect_multi_bit_fields = true;
};

class BitfieldDetector {
public:
    explicit BitfieldDetector(BitfieldOptions options = {}) : options_(options) {}

    // Analyzes a set of integer values (e.g. collected across samples or repeated struct instances)
    [[nodiscard]] BitfieldAnalysisResult analyze(std::span<const std::uint64_t> observed_values,
                                                 core::PrimitiveKind primitive_kind) const;

    // Helper to extract a column of integers from multiple binary views at a specific offset
    [[nodiscard]] BitfieldAnalysisResult analyze_offset(std::span<const core::BinaryView> samples,
                                                        std::uint64_t offset,
                                                        core::PrimitiveKind primitive_kind,
                                                        core::ByteOrder endian) const;

private:
    BitfieldOptions options_;
};

}  // namespace typemorph::infer

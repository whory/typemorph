// TypeMorph - Bitfield and Flag Detector implementation.
#include "typemorph/infer/bitfield_detector.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <set>
#include <sstream>

namespace typemorph::infer {
namespace {

std::string hex_u64(std::uint64_t val) {
    std::ostringstream ss;
    ss << std::hex << val;
    return ss.str();
}

}  // namespace

BitfieldAnalysisResult BitfieldDetector::analyze(std::span<const std::uint64_t> observed_values,
                                                 core::PrimitiveKind primitive_kind) const {
    BitfieldAnalysisResult result;
    result.underlying = primitive_kind;
    const std::uint8_t total_bits = static_cast<std::uint8_t>(core::primitive_size(primitive_kind) * 8);

    if (observed_values.size() < options_.min_samples || total_bits == 0 || total_bits > 64) {
        return result;
    }

    const std::size_t n = observed_values.size();

    // Check if values are mostly a monotonic sequential counter (e.g., 1, 2, 3, 4)
    std::size_t unit_diffs = 0;
    for (std::size_t i = 1; i < n; ++i) {
        if (observed_values[i] > observed_values[i - 1] &&
            (observed_values[i] - observed_values[i - 1] == 1)) {
            ++unit_diffs;
        }
    }
    if (unit_diffs >= n - 1 && n >= 3) {
        // Obvious sequential arithmetic counter
        result.confidence = 0.0;
        return result;
    }

    // Per-bit statistics
    std::vector<std::size_t> bit_ones(total_bits, 0);
    std::size_t power_of_two_count = 0;
    std::set<std::uint64_t> distinct_values;
    std::uint64_t bitwise_or_all = 0;

    for (std::uint64_t val : observed_values) {
        distinct_values.insert(val);
        bitwise_or_all |= val;
        if (val > 0 && (val & (val - 1)) == 0) {
            ++power_of_two_count;
        }
        for (std::uint8_t b = 0; b < total_bits; ++b) {
            if ((val >> b) & 1ULL) {
                ++bit_ones[b];
            }
        }
    }

    if (distinct_values.size() < 2) {
        return result; // Constant value
    }

    // Count active bits (toggling between 0 and 1)
    std::vector<std::uint8_t> active_bits;
    for (std::uint8_t b = 0; b < total_bits; ++b) {
        if (bit_ones[b] > 0 && bit_ones[b] < n) {
            active_bits.push_back(b);
        }
    }

    if (active_bits.empty()) {
        return result;
    }

    // Check for "bit gaps": active higher bits with completely inactive lower bits
    std::size_t bit_gaps = 0;
    bool seen_active = false;
    for (std::uint8_t b = 0; b < total_bits; ++b) {
        if (bit_ones[b] > 0) {
            seen_active = true;
        } else if (seen_active && bit_ones[b] == 0) {
            // Check if any higher bit is active
            for (std::uint8_t higher = b + 1; higher < total_bits; ++higher) {
                if (bit_ones[higher] > 0) {
                    ++bit_gaps;
                    break;
                }
            }
        }
    }

    // Calculate confidence heuristics
    double p2_ratio = static_cast<double>(power_of_two_count) / static_cast<double>(n);
    double gap_factor = bit_gaps > 0 ? 0.35 : 0.0;
    double active_ratio = static_cast<double>(active_bits.size()) / static_cast<double>(total_bits);

    double confidence = 0.50 + (p2_ratio * 0.30) + gap_factor;
    if (active_ratio > 0.0 && active_ratio <= 0.5) {
        confidence += 0.15; // Flags typically have sparse active bits
    }
    confidence = std::clamp(confidence, 0.0, 0.98);

    if (confidence < options_.min_confidence) {
        return result;
    }

    result.is_bitfield = true;
    result.confidence = confidence;

    // Construct bitfield members covering all total_bits
    std::uint8_t bit_cursor = 0;
    std::size_t flag_idx = 0;
    std::size_t res_idx = 0;

    while (bit_cursor < total_bits) {
        if (bit_ones[bit_cursor] > 0) {
            // Check for multi-bit subfield if adjacent bits are also active
            std::uint8_t width = 1;
            if (options_.detect_multi_bit_fields) {
                while (bit_cursor + width < total_bits && bit_ones[bit_cursor + width] > 0 && width < 4) {
                    ++width;
                }
            }

            core::BitfieldMember member;
            member.bit_offset = bit_cursor;
            member.bit_width = width;
            if (width == 1) {
                std::uint64_t mask = 1ULL << bit_cursor;
                member.name = "flag_0x" + hex_u64(mask);
                member.comment = "bit " + std::to_string(bit_cursor);
            } else {
                member.name = "subfield_" + std::to_string(flag_idx++);
                member.comment = "bits " + std::to_string(bit_cursor) + ".." + std::to_string(bit_cursor + width - 1);
            }
            result.members.push_back(std::move(member));
            bit_cursor += width;
        } else {
            // Run of inactive bits -> reserved padding
            std::uint8_t res_width = 0;
            const std::uint8_t res_start = bit_cursor;
            while (bit_cursor < total_bits && bit_ones[bit_cursor] == 0) {
                ++res_width;
                ++bit_cursor;
            }
            core::BitfieldMember member;
            member.bit_offset = res_start;
            member.bit_width = res_width;
            member.name = "reserved_" + std::to_string(res_idx++);
            member.comment = "unused / reserved bits";
            result.members.push_back(std::move(member));
        }
    }

    result.rationale = "detected " + std::to_string(active_bits.size()) + " active flag bits with " +
                       std::to_string(static_cast<int>(p2_ratio * 100)) + "% power-of-two values";
    return result;
}

BitfieldAnalysisResult BitfieldDetector::analyze_offset(std::span<const core::BinaryView> samples,
                                                        std::uint64_t offset,
                                                        core::PrimitiveKind primitive_kind,
                                                        core::ByteOrder endian) const {
    const std::uint8_t size = core::primitive_size(primitive_kind);
    std::vector<std::uint64_t> values;
    values.reserve(samples.size());

    for (const auto& sample : samples) {
        if (!sample.valid() || offset + size > sample.size()) continue;
        auto val_res = sample.read_uint(offset, size, endian);
        if (val_res.has_value()) {
            values.push_back(val_res.value());
        }
    }

    return analyze(values, primitive_kind);
}

}  // namespace typemorph::infer

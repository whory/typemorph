// TypeMorph - dynamic and static array boundary detection.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace typemorph::infer {

struct ArrayDetectorOptions {
    std::uint64_t min_array_elements = 3;
    std::uint64_t max_scan_bytes = 4096;
    std::uint64_t max_element_size = 1024;
    double confidence_threshold = 0.60;
};

struct ArrayBoundary {
    // Absolute offset of the length field.
    std::uint64_t length_offset = 0;
    std::uint8_t length_width = 4;
    // Absolute offset of the first element.
    std::uint64_t data_offset = 0;
    std::uint64_t element_size = 1;
    std::uint64_t observed_count = 0;
    double confidence = 0.0;
    std::string rationale;
};

// Correlates changing integer fields with file-size deltas across samples.
class ArrayDetector {
public:
    explicit ArrayDetector(ArrayDetectorOptions options = {});

    [[nodiscard]] std::vector<ArrayBoundary> detect(std::span<const core::BinaryView> samples) const;

    // Given a sorted set of per-sample (count, file_size) observations, derive
    // the element stride with least-squares plus exact-divisibility checks.
    [[nodiscard]] static std::optional<std::uint64_t> infer_stride(
        std::span<const std::pair<std::uint64_t, std::uint64_t>> count_and_size);

    [[nodiscard]] const ArrayDetectorOptions& options() const noexcept { return options_; }

private:
    ArrayDetectorOptions options_;
};

}  // namespace typemorph::infer

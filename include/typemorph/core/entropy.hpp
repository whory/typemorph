// TypeMorph - Shannon entropy analysis.
//
// The sliding-window implementation maintains the histogram incrementally
// (O(1) per byte after the first window) and uses four independent histogram
// accumulators to remove the store-to-load dependency chain that limits a
// naive byte-at-a-time loop.  This is the hot path used by the TUI heat map and
// by the alignment oracle.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "typemorph/core/result.hpp"

namespace typemorph::core {

struct EntropyProfile {
    std::size_t window_size = 0;
    std::size_t stride = 0;
    std::vector<std::uint64_t> offsets;
    std::vector<double> entropy;

    [[nodiscard]] double min() const noexcept;
    [[nodiscard]] double max() const noexcept;
    [[nodiscard]] double mean() const noexcept;
    [[nodiscard]] bool empty() const noexcept { return entropy.empty(); }
};

[[nodiscard]] double shannon_entropy(std::span<const std::uint8_t> bytes) noexcept;

// Entropy for each complete window.  stride==0 means stride=window.
[[nodiscard]] Result<EntropyProfile> sliding_entropy(std::span<const std::uint8_t> bytes,
                                                     std::size_t window_size,
                                                     std::size_t stride = 0);

// Convenience: one entropy value per fixed-size block, with the final partial
// block included.  A block_size of 0 is rejected.
[[nodiscard]] Result<std::vector<double>> block_entropy(std::span<const std::uint8_t> bytes,
                                                        std::size_t block_size);

// Maps entropy in [0,8] to a 0..255 intensity suitable for a terminal heat map.
[[nodiscard]] std::uint8_t entropy_intensity(double entropy) noexcept;
[[nodiscard]] const char* entropy_label(double entropy) noexcept;

}  // namespace typemorph::core

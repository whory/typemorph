#include "typemorph/core/entropy.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <numeric>

namespace typemorph::core {
namespace {

constexpr double kLog2E = 1.4426950408889634074;

void accumulate(std::array<std::uint64_t, 256>& counts, std::uint8_t byte) noexcept {
    ++counts[byte];
}

double entropy_from_histogram(const std::array<std::uint64_t, 256>& histogram,
                              std::uint64_t total) noexcept {
    if (total == 0) return 0.0;
    double sum_c_log_c = 0.0;
    for (const std::uint64_t count : histogram) {
        if (count != 0) {
            sum_c_log_c += static_cast<double>(count) *
                           std::log2(static_cast<double>(count));
        }
    }
    const double entropy = std::log2(static_cast<double>(total)) - sum_c_log_c /
                                                                      static_cast<double>(total);
    return std::max(0.0, entropy);
}

}  // namespace

double shannon_entropy(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) return 0.0;

    // Four independent histograms eliminate the read-modify-write dependency
    // chain present in a single-accumulator byte loop.  This is the inner loop
    // for every heat-map and alignment probe.
    std::array<std::uint64_t, 256> h0{};
    std::array<std::uint64_t, 256> h1{};
    std::array<std::uint64_t, 256> h2{};
    std::array<std::uint64_t, 256> h3{};

    std::size_t i = 0;
    const std::size_t size = bytes.size();
    const std::uint8_t* data = bytes.data();
    for (; i + 3 < size; i += 4) {
        ++h0[data[i]];
        ++h1[data[i + 1]];
        ++h2[data[i + 2]];
        ++h3[data[i + 3]];
    }
    for (; i < size; ++i) {
        ++h0[data[i]];
    }

    std::uint64_t total = 0;
    std::array<std::uint64_t, 256> histogram{};
    for (std::size_t symbol = 0; symbol < 256; ++symbol) {
        const std::uint64_t count = h0[symbol] + h1[symbol] + h2[symbol] + h3[symbol];
        histogram[symbol] = count;
        total += count;
    }
    return entropy_from_histogram(histogram, total);
}

Result<EntropyProfile> sliding_entropy(std::span<const std::uint8_t> bytes,
                                       std::size_t window_size, std::size_t stride) {
    if (window_size == 0) {
        return make_error(ErrorCode::invalid_argument, "entropy window must be non-zero");
    }
    if (stride == 0) stride = window_size;
    if (bytes.size() < window_size) {
        return EntropyProfile{window_size, stride, {}, {}};
    }

    std::array<std::uint64_t, 256> histogram{};
    std::uint64_t in_window = 0;
    for (std::size_t i = 0; i < window_size; ++i) {
        accumulate(histogram, bytes[i]);
        ++in_window;
    }

    auto recompute_sum = [&histogram]() {
        double sum = 0.0;
        for (const std::uint64_t count : histogram) {
            if (count != 0) {
                sum += static_cast<double>(count) * std::log2(static_cast<double>(count));
            }
        }
        return sum;
    };

    double sum_c_log_c = recompute_sum();
    EntropyProfile profile;
    profile.window_size = window_size;
    profile.stride = stride;

    std::size_t offset = 0;
    const std::size_t total = bytes.size();
    while (offset + window_size <= total) {
        const double h = std::log2(static_cast<double>(window_size)) -
                         sum_c_log_c / static_cast<double>(window_size);
        profile.offsets.push_back(offset);
        profile.entropy.push_back(std::max(0.0, h));

        if (offset + window_size == total) break;
        const std::size_t next = offset + stride;
        if (next + window_size > total) break;

        // Slide: remove old bytes, insert new bytes.  For stride==1 this is two
        // bytes of work regardless of window size.  A stride larger than the
        // window is a disjoint jump, so the old window is removed completely.
        const std::size_t overlap = std::min(stride, window_size);
        for (std::size_t i = offset; i < offset + overlap; ++i) {
            const std::uint64_t count = histogram[bytes[i]];
            if (count > 0) {
                sum_c_log_c -= static_cast<double>(count) * std::log2(static_cast<double>(count));
                --histogram[bytes[i]];
                if (count > 1) {
                    sum_c_log_c += static_cast<double>(count - 1) *
                                   std::log2(static_cast<double>(count - 1));
                }
            }
        }
        for (std::size_t i = offset + window_size; i < next + overlap; ++i) {
            const std::uint64_t count = histogram[bytes[i]];
            sum_c_log_c += static_cast<double>(count + 1) *
                           std::log2(static_cast<double>(count + 1));
            sum_c_log_c -= static_cast<double>(count) * std::log2(static_cast<double>(count));
            ++histogram[bytes[i]];
        }
        if (stride > window_size) {
            // The ranges above do not cover the whole jump; rebuild exactly.
            histogram.fill(0);
            for (std::size_t i = 0; i < window_size; ++i) ++histogram[bytes[next + i]];
            sum_c_log_c = recompute_sum();
        }
        offset = next;
    }
    return profile;
}

Result<std::vector<double>> block_entropy(std::span<const std::uint8_t> bytes,
                                          std::size_t block_size) {
    if (block_size == 0) {
        return make_error(ErrorCode::invalid_argument, "entropy block size must be non-zero");
    }
    std::vector<double> result;
    result.reserve((bytes.size() + block_size - 1) / block_size);
    for (std::size_t offset = 0; offset < bytes.size(); offset += block_size) {
        const std::size_t length = std::min(block_size, bytes.size() - offset);
        result.push_back(shannon_entropy(bytes.subspan(offset, length)));
    }
    return result;
}

double EntropyProfile::min() const noexcept {
    if (entropy.empty()) return 0.0;
    return *std::min_element(entropy.begin(), entropy.end());
}

double EntropyProfile::max() const noexcept {
    if (entropy.empty()) return 0.0;
    return *std::max_element(entropy.begin(), entropy.end());
}

double EntropyProfile::mean() const noexcept {
    if (entropy.empty()) return 0.0;
    const double sum = std::accumulate(entropy.begin(), entropy.end(), 0.0);
    return sum / static_cast<double>(entropy.size());
}

std::uint8_t entropy_intensity(double entropy) noexcept {
    const double clamped = std::clamp(entropy, 0.0, 8.0);
    const double scaled = clamped / 8.0 * 255.0;
    return static_cast<std::uint8_t>(std::clamp(std::lround(scaled), 0L, 255L));
}

const char* entropy_label(double entropy) noexcept {
    if (entropy < 1.0) return "zero";
    if (entropy < 2.5) return "low";
    if (entropy < 4.5) return "mixed";
    if (entropy < 6.5) return "high";
    return "dense";
}

}  // namespace typemorph::core

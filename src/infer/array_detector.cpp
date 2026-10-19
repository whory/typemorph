#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "typemorph/infer/array_detector.hpp"

namespace typemorph::infer {
namespace {

constexpr std::uint8_t kLengthWidths[] = {4, 2, 1, 8};

[[nodiscard]] std::string hex_offset(std::uint64_t offset) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out = "0x";
    char buffer[16];
    std::size_t used = 0;
    std::uint64_t value = offset;
    do {
        buffer[used++] = digits[value & 0xFU];
        value >>= 4U;
    } while (value != 0 && used < sizeof(buffer));
    while (used > 0) out.push_back(buffer[--used]);
    return out;
}

[[nodiscard]] std::string width_suffix(std::uint8_t width) {
    return "u" + std::to_string(static_cast<unsigned>(width) * 8U);
}

// Signed difference for two unsigned observations, in a representation that
// cannot overflow.  Model: size = base + stride * count with stride > 0.
struct Delta {
    bool positive = true;
    std::uint64_t magnitude = 0;
    bool zero() const noexcept { return magnitude == 0; }
};

[[nodiscard]] Delta unsigned_delta(std::uint64_t a, std::uint64_t b) noexcept {
    if (a >= b) return Delta{true, a - b};
    return Delta{false, b - a};
}

// y must be base + stride * x for some common base.  This validates the model
// for a pair of observations without multiplying (so no overflow is possible).
[[nodiscard]] bool pair_matches(std::uint64_t xi, std::uint64_t yi, std::uint64_t xj,
                                std::uint64_t yj, std::uint64_t stride) noexcept {
    const Delta dx = unsigned_delta(xi, xj);
    const Delta dy = unsigned_delta(yi, yj);
    if (dx.zero()) return dy.zero();
    if (dy.positive != dx.positive) return false;
    return dy.magnitude % dx.magnitude == 0 && dy.magnitude / dx.magnitude == stride;
}

}  // namespace

ArrayDetector::ArrayDetector(ArrayDetectorOptions options) : options_(options) {
    if (options_.min_array_elements == 0) options_.min_array_elements = 1;
    if (options_.max_element_size == 0) options_.max_element_size = 1;
    if (options_.max_scan_bytes == 0) options_.max_scan_bytes = 1;
}

std::optional<std::uint64_t> ArrayDetector::infer_stride(
    std::span<const std::pair<std::uint64_t, std::uint64_t>> count_and_size) {
    if (count_and_size.size() < 2) return std::nullopt;

    // The mathematically exact route: the pair with the largest count delta
    // determines the only candidate slope, and every other pair must agree.
    std::uint64_t widest_dx = 0;
    for (std::size_t i = 0; i < count_and_size.size(); ++i) {
        for (std::size_t j = i + 1; j < count_and_size.size(); ++j) {
            const Delta dx =
                unsigned_delta(count_and_size[i].first, count_and_size[j].first);
            widest_dx = std::max(widest_dx, dx.magnitude);
        }
    }
    if (widest_dx == 0) return std::nullopt;  // constant count: no size signal

    std::uint64_t candidate = 0;
    for (std::size_t i = 0; i < count_and_size.size(); ++i) {
        for (std::size_t j = i + 1; j < count_and_size.size(); ++j) {
            const Delta dx =
                unsigned_delta(count_and_size[i].first, count_and_size[j].first);
            if (dx.magnitude != widest_dx) continue;
            const Delta dy = unsigned_delta(count_and_size[i].second, count_and_size[j].second);
            if (dy.positive == dx.positive && dy.magnitude % dx.magnitude == 0) {
                const std::uint64_t slope = dy.magnitude / dx.magnitude;
                if (slope == 0) continue;
                if (candidate == 0) {
                    candidate = slope;
                } else if (candidate != slope) {
                    candidate = 0;  // conflicting evidence: fall through to LS
                    break;
                }
            }
        }
        if (candidate == 0) break;
    }
    if (candidate != 0) {
        bool exact = true;
        for (std::size_t i = 0; i < count_and_size.size() && exact; ++i) {
            for (std::size_t j = i + 1; j < count_and_size.size(); ++j) {
                if (!pair_matches(count_and_size[i].first, count_and_size[i].second,
                                  count_and_size[j].first, count_and_size[j].second, candidate)) {
                    exact = false;
                    break;
                }
            }
        }
        if (exact) return candidate;
    }

    // Least-squares fallback for observations that are exact modulo < 1 byte of
    // measurement noise.  Anything noisier is rejected rather than guessed.
    long double sum_x = 0.0L;
    long double sum_y = 0.0L;
    for (const auto& [count, size] : count_and_size) {
        sum_x += static_cast<long double>(count);
        sum_y += static_cast<long double>(size);
    }
    const long double n = static_cast<long double>(count_and_size.size());
    const long double mean_x = sum_x / n;
    const long double mean_y = sum_y / n;
    long double covariance = 0.0L;
    long double variance = 0.0L;
    for (const auto& [count, size] : count_and_size) {
        const long double dx = static_cast<long double>(count) - mean_x;
        covariance += dx * (static_cast<long double>(size) - mean_y);
        variance += dx * dx;
    }
    if (variance <= 0.0L) return std::nullopt;
    const long double slope = covariance / variance;
    if (!(slope > 0.0L)) return std::nullopt;
    const long double rounded = std::floor(slope + 0.5L);
    if (rounded < 1.0L) return std::nullopt;
    if (std::fabs(slope - rounded) > 0.02L * std::max(1.0L, rounded)) return std::nullopt;
    const long double intercept = mean_y - rounded * mean_x;
    for (const auto& [count, size] : count_and_size) {
        const long double predicted =
            intercept + rounded * static_cast<long double>(count);
        if (std::fabs(static_cast<long double>(size) - predicted) > 0.5L) {
            return std::nullopt;
        }
    }
    return static_cast<std::uint64_t>(rounded);
}

std::vector<ArrayBoundary> ArrayDetector::detect(std::span<const core::BinaryView> samples) const {
    std::vector<ArrayBoundary> result;
    if (samples.size() < 2) return result;

    std::uint64_t min_size = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_size = 0;
    for (const auto& sample : samples) {
        if (!sample.valid() || sample.empty()) return result;
        min_size = std::min<std::uint64_t>(min_size, sample.size());
        max_size = std::max<std::uint64_t>(max_size, sample.size());
    }
    if (min_size == 0) return result;

    const std::uint64_t scan = std::min<std::uint64_t>(options_.max_scan_bytes, min_size);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> observations;
    observations.reserve(samples.size());

    std::vector<ArrayBoundary> candidates;
    for (std::uint64_t offset = 0; offset < scan; ++offset) {
        for (const std::uint8_t width : kLengthWidths) {
            if (offset + width > scan) continue;
            observations.clear();
            bool usable = true;
            for (const auto& sample : samples) {
                const auto value = sample.read_uint(offset, width, core::ByteOrder::little);
                if (!value) {
                    usable = false;
                    break;
                }
                const std::uint64_t count = value.value();
                // A count cannot exceed the file size (element stride >= 1),
                // which also caps the multiplication below.
                if (count > max_size) {
                    usable = false;
                    break;
                }
                observations.emplace_back(count, sample.size());
            }
            if (!usable) continue;

            std::uint64_t distinct_counts = 1;
            for (std::size_t i = 1; i < observations.size(); ++i) {
                if (observations[i].first != observations[0].first) {
                    ++distinct_counts;
                }
            }
            if (distinct_counts < 2) continue;

            const auto stride = infer_stride(observations);
            if (!stride.has_value()) continue;
            const std::uint64_t element_size = stride.value();
            if (element_size == 0 || element_size > options_.max_element_size) continue;

            // Base offset must be identical for every sample and must keep the
            // length field outside the element data.
            std::optional<std::uint64_t> base;
            std::uint64_t observed_count = 0;
            std::uint64_t largest_size = 0;
            bool consistent = true;
            for (const auto& [count, size] : observations) {
                if (count > (std::numeric_limits<std::uint64_t>::max() / element_size)) {
                    consistent = false;
                    break;
                }
                const std::uint64_t data_bytes = count * element_size;
                if (data_bytes > size) {
                    consistent = false;
                    break;
                }
                const std::uint64_t candidate_base = size - data_bytes;
                if (!base.has_value()) {
                    base = candidate_base;
                } else if (base.value() != candidate_base) {
                    consistent = false;
                    break;
                }
                if (size >= largest_size) {
                    largest_size = size;
                    observed_count = count;
                }
            }
            if (!consistent || !base.has_value()) continue;

            const std::uint64_t data_offset = base.value();
            if (data_offset < offset + width) continue;
            if (data_offset > min_size) continue;
            if (observed_count < options_.min_array_elements) continue;

            ArrayBoundary boundary;
            boundary.length_offset = offset;
            boundary.length_width = width;
            boundary.data_offset = data_offset;
            boundary.element_size = element_size;
            boundary.observed_count = observed_count;
            double confidence = 0.55;
            confidence += 0.08 * static_cast<double>(std::min<std::size_t>(samples.size() - 2, 3));
            if (element_size % 4 == 0) confidence += 0.05;
            if (data_offset % 8 == 0) confidence += 0.05;
            confidence += width >= 4 ? 0.03 : (width == 2 ? 0.02 : 0.01);
            std::uint64_t min_count = observations.front().first;
            std::uint64_t max_count = observations.front().first;
            for (const auto& [count, size] : observations) {
                (void)size;
                min_count = std::min(min_count, count);
                max_count = std::max(max_count, count);
            }
            if (max_count >= min_count + 2 * options_.min_array_elements) confidence += 0.04;
            boundary.confidence = std::clamp(confidence, 0.0, 0.99);
            boundary.rationale = "count at " + hex_offset(offset) + " (" + width_suffix(width) +
                                 ") correlates exactly with file size: element stride " +
                                 std::to_string(element_size) + ", header size " +
                                 std::to_string(data_offset) + ", observed count " +
                                 std::to_string(observed_count) + " over " +
                                 std::to_string(samples.size()) + " samples";
            candidates.push_back(std::move(boundary));
        }
    }

    if (candidates.empty()) return result;

    // Deduplicate overlapping interpretations of the same length field (for
    // example a u32 count whose upper bytes are zero also parses as a u16).
    std::sort(candidates.begin(), candidates.end(),
              [](const ArrayBoundary& a, const ArrayBoundary& b) {
                  if (a.confidence != b.confidence) return a.confidence > b.confidence;
                  if (a.length_offset != b.length_offset) return a.length_offset < b.length_offset;
                  return a.length_width > b.length_width;
              });

    std::vector<ArrayBoundary> accepted;
    for (auto& candidate : candidates) {
        const std::uint64_t begin = candidate.length_offset;
        const std::uint64_t end = begin + candidate.length_width;
        bool duplicate = false;
        for (const auto& existing : accepted) {
            const std::uint64_t existing_begin = existing.length_offset;
            const std::uint64_t existing_end = existing_begin + existing.length_width;
            if (begin < existing_end && existing_begin < end) {
                duplicate = true;
                break;
            }
            if (candidate.data_offset == existing.data_offset &&
                candidate.element_size == existing.element_size &&
                candidate.observed_count == existing.observed_count) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) accepted.push_back(candidate);
    }

    // Stable, offset-ordered output for deterministic downstream layout.
    std::sort(accepted.begin(), accepted.end(),
              [](const ArrayBoundary& a, const ArrayBoundary& b) {
                  if (a.length_offset != b.length_offset) return a.length_offset < b.length_offset;
                  return a.length_width > b.length_width;
              });
    return accepted;
}

}  // namespace typemorph::infer

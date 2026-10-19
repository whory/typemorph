// TypeMorph - alignment and primitive-width heuristics.
//
// The oracle answers one question: "how plausible is it that a `width`-byte
// primitive starts at file offset `offset`?"  Every answer is derived from
// local, deterministic evidence so that repeated runs (and the TUI refresh
// loop) always produce the same tree:
//
//   * natural alignment fit        - a u32 at offset 4 is more plausible than
//                                    a u32 at offset 5;
//   * content prior                - all-zero runs are almost always padding,
//                                    uniform non-zero runs are constants, and
//                                    mixed content is ordinary data;
//   * padding context              - a field flanked by a padding run is more
//                                    likely a real member of a struct;
//   * interior zero runs           - a candidate that spans an internal zero
//                                    run of >= min_run bytes is probably two
//                                    narrower fields, not one wide one.
//
// detect_fields() turns the scoring function into a greedy, non-overlapping
// segmentation (highest score first, ties broken by offset then by width).
// detect_alignment() then derives the alignment of the containing structure
// from the offsets of the accepted fields.
#include "typemorph/infer/alignment_oracle.hpp"

#include "typemorph/core/entropy.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <limits>
#include <optional>
#include <utility>

namespace typemorph::infer {
namespace {

constexpr std::uint8_t kCandidateWidths[] = {8, 4, 2, 1};

[[nodiscard]] std::uint8_t widest_supported_width(std::uint8_t max_width) noexcept {
    if (max_width >= 8) return 8;
    if (max_width >= 4) return 4;
    if (max_width >= 2) return 2;
    return 1;
}

[[nodiscard]] std::uint64_t width_unit(std::uint8_t width) noexcept {
    if (width == 0) return 1;
    const unsigned bits = static_cast<unsigned>(width);
    return std::uint64_t{1} << (std::bit_width(bits) - 1U);
}

[[nodiscard]] bool is_printable(std::uint8_t value) noexcept { return value >= 0x20 && value <= 0x7E; }

// Detects a semantically plausible IEEE-754 single-precision value.  Integer
// values that happen to decode as denormals, infinities or absurd magnitudes
// are rejected, which keeps the false-positive rate for random 32-bit words
// reasonably low.
[[nodiscard]] bool plausible_f32(std::uint32_t bits) noexcept {
    const float value = std::bit_cast<float>(bits);
    if (!std::isfinite(value)) return false;
    const double magnitude = std::fabs(static_cast<double>(value));
    return magnitude >= 1e-4 && magnitude <= 1e9;
}

[[nodiscard]] bool plausible_f64(std::uint64_t bits) noexcept {
    const double value = std::bit_cast<double>(bits);
    if (!std::isfinite(value)) return false;
    const double magnitude = std::fabs(value);
    return magnitude >= 1e-6 && magnitude <= 1e12;
}

struct ByteStats {
    std::size_t zero_count = 0;
    std::size_t leading_zeros = 0;
    std::size_t trailing_zeros = 0;
    std::size_t max_interior_zero_run = 0;
    bool all_same = true;
    bool all_printable = true;
    double entropy = 0.0;
};

[[nodiscard]] ByteStats analyse(std::span<const std::uint8_t> bytes) noexcept {
    ByteStats stats;
    if (bytes.empty()) return stats;
    stats.entropy = core::shannon_entropy(bytes);
    const std::uint8_t first = bytes.front();
    for (const std::uint8_t byte : bytes) {
        if (byte == 0) ++stats.zero_count;
        if (byte != first) stats.all_same = false;
        if (!is_printable(byte)) stats.all_printable = false;
    }
    while (stats.leading_zeros < bytes.size() && bytes[stats.leading_zeros] == 0) {
        ++stats.leading_zeros;
    }
    while (stats.trailing_zeros < bytes.size() &&
           bytes[bytes.size() - 1 - stats.trailing_zeros] == 0) {
        ++stats.trailing_zeros;
    }
    // Interior zero runs are the ones that do not touch either end.
    std::size_t run = 0;
    for (std::size_t i = 1; i + 1 < bytes.size(); ++i) {
        if (bytes[i] == 0) {
            ++run;
            stats.max_interior_zero_run = std::max(stats.max_interior_zero_run, run);
        } else {
            run = 0;
        }
    }
    return stats;
}

// Length of the zero run immediately ending at `offset` (exclusive).
[[nodiscard]] std::size_t zero_run_before(const core::BinaryView& view, std::uint64_t offset,
                                          std::size_t cap) noexcept {
    std::size_t run = 0;
    while (run < cap && offset > run) {
        if (view.data()[static_cast<std::size_t>(offset) - 1 - run] != 0) break;
        ++run;
    }
    return run;
}

// Length of the zero run immediately starting at `offset`.
[[nodiscard]] std::size_t zero_run_after(const core::BinaryView& view, std::uint64_t offset,
                                         std::size_t cap) noexcept {
    const std::size_t size = view.size();
    std::size_t run = 0;
    while (run < cap && static_cast<std::size_t>(offset) + run < size) {
        if (view.data()[static_cast<std::size_t>(offset) + run] != 0) break;
        ++run;
    }
    return run;
}

// A candidate is rejected when it overlaps an already accepted field.  `taken`
// is kept sorted so the check is O(log n).
[[nodiscard]] bool overlaps(const std::vector<std::pair<std::uint64_t, std::uint64_t>>& taken,
                            std::uint64_t begin, std::uint64_t end) {
    auto it = std::upper_bound(taken.begin(), taken.end(), begin,
                               [](std::uint64_t value, const std::pair<std::uint64_t, std::uint64_t>& r) {
                                   return value < r.first;
                               });
    if (it != taken.begin()) {
        const auto& previous = *(it - 1);
        if (previous.second > begin) return true;
    }
    if (it != taken.end() && it->first < end) return true;
    return false;
}

void insert_taken(std::vector<std::pair<std::uint64_t, std::uint64_t>>& taken, std::uint64_t begin,
                  std::uint64_t end) {
    auto it = std::lower_bound(taken.begin(), taken.end(), begin,
                               [](const std::pair<std::uint64_t, std::uint64_t>& r, std::uint64_t value) {
                                   return r.first < value;
                               });
    taken.insert(it, {begin, end});
}

[[nodiscard]] std::string hex_offset(std::uint64_t offset) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out = "0x";
    std::uint64_t value = offset;
    char buffer[16];
    std::size_t used = 0;
    do {
        buffer[used++] = digits[value & 0xFU];
        value >>= 4U;
    } while (value != 0 && used < sizeof(buffer));
    while (used > 0) out.push_back(buffer[--used]);
    return out;
}

}  // namespace

AlignmentOracle::AlignmentOracle(core::BinaryView view, core::ByteOrder order,
                                 AlignmentOptions options)
    : view_(std::move(view)), order_(order), options_(options) {
    if (options_.min_width == 0) options_.min_width = 1;
    if (options_.max_width < options_.min_width) options_.max_width = options_.min_width;
    if (options_.max_width > 8) options_.max_width = 8;
    if (options_.min_run == 0) options_.min_run = 1;
}

double AlignmentOracle::score(std::uint64_t offset, std::uint8_t width) const {
    if (!view_.valid() || view_.empty()) return 0.0;
    if (width < options_.min_width || width > options_.max_width) return 0.0;
    if (width == 0) return 0.0;
    const std::uint64_t size = view_.size();
    if (offset >= size || static_cast<std::uint64_t>(width) > size - offset) return 0.0;

    const auto bytes =
        view_.slice_unchecked(static_cast<std::size_t>(offset), static_cast<std::size_t>(width));
    const ByteStats stats = analyse(bytes);

    // Natural alignment fit: exact for power-of-two widths, partial when the
    // field is at least comfortably aligned to half of its width.
    const std::uint64_t unit = width_unit(width);
    double alignment = 0.15;
    if (unit > 0 && offset % unit == 0) {
        alignment = 1.0;
    } else if (unit >= 2 && offset % 2 == 0) {
        alignment = 0.55;
    }

    // Content prior.  Pure zero bytes are almost always padding, a uniform
    // non-zero run is a constant / magic value, and anything mixed is data.
    double content = 0.62 + 0.38 * std::clamp(stats.entropy / 6.0, 0.0, 1.0);
    if (stats.zero_count == bytes.size()) {
        content = 0.0;
    } else if (stats.all_same) {
        content = 0.55;
    }

    // Padding context: a real struct member is frequently surrounded by
    // zero padding, but a single trailing zero is just a value byte, so a
    // genuine padding run must be at least min_run bytes long.
    const std::size_t run_cap = std::max<std::size_t>(options_.min_run, 4);
    double padding = 0.62;
    const std::size_t before = zero_run_before(view_, offset, run_cap);
    if (before >= options_.min_run) padding += 0.19;
    const std::size_t after = zero_run_after(view_, offset + width, run_cap);
    if (after >= options_.min_run) padding += 0.19;
    padding = std::min(padding, 1.0);

    double score = 0.45 * alignment + 0.30 * content + 0.25 * padding;

    // A candidate that spans an internal zero run is very likely two narrower
    // fields (or a field followed by padding) rather than one wide primitive.
    if (stats.max_interior_zero_run >= options_.min_run) {
        score *= 0.45;
    } else if (stats.max_interior_zero_run >= 1) {
        score *= 0.82;
    }

    // Prefer the narrowest representation that still explains the bytes: wide
    // hypotheses must earn their extra coverage through content entropy.
    double width_prior = 1.0;
    switch (width) {
    case 1: width_prior = 0.88; break;
    case 2: width_prior = 0.93; break;
    case 4: width_prior = 1.0; break;
    case 8: width_prior = 1.0; break;
    default: width_prior = 0.80; break;
    }
    score *= width_prior;

    // All-zero candidates are padding candidates, never fields.
    if (stats.zero_count == bytes.size()) score *= 0.5;

    return std::clamp(score, 0.0, 1.0);
}

std::uint64_t AlignmentOracle::detect_alignment(std::uint64_t start,
                                                std::uint64_t max_length) const {
    if (!view_.valid() || view_.empty()) return 1;
    const std::uint64_t size = view_.size();
    if (start >= size) return 1;
    const std::uint64_t length =
        std::min<std::uint64_t>(max_length, size - start);  // NOLINT(performance-unnecessary-value-param)
    if (length == 0) return 1;

    const auto fields = detect_fields();
    std::vector<std::uint64_t> anchors;
    anchors.reserve(fields.size() + 1);
    for (const auto& field : fields) {
        if (field.confidence < 0.60) continue;
        if (field.offset < start || field.offset >= start + length) continue;
        anchors.push_back(field.offset - start);
    }
    if (anchors.size() < 2) return 1;

    // Points that are all multiples of 16 are also multiples of 8/4/2/1, so the
    // largest alignment that still explains a super-majority of field offsets
    // wins.  16 is the practical ceiling for naturally aligned struct members.
    for (const std::uint64_t candidate : {std::uint64_t{16}, std::uint64_t{8}, std::uint64_t{4},
                                          std::uint64_t{2}}) {
        std::size_t aligned = 0;
        for (const std::uint64_t anchor : anchors) {
            if (anchor % candidate == 0) ++aligned;
        }
        if (static_cast<double>(aligned) / static_cast<double>(anchors.size()) >= 0.75) {
            return candidate;
        }
    }
    return 1;
}

std::vector<AlignmentField> AlignmentOracle::detect_fields() const {
    std::vector<AlignmentField> fields;
    if (!view_.valid() || view_.empty()) return fields;

    const std::uint64_t scan =
        std::min<std::uint64_t>(options_.max_scan_bytes, view_.size());
    if (scan == 0) return fields;

    struct Candidate {
        double score = 0.0;
        std::uint64_t offset = 0;
        std::uint8_t width = 0;
    };
    std::vector<Candidate> candidates;
    candidates.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(scan * 4, 1U << 18U)));

    const std::uint8_t max_width = widest_supported_width(options_.max_width);
    for (std::uint64_t offset = 0; offset < scan; ++offset) {
        for (const std::uint8_t width : kCandidateWidths) {
            if (width > max_width) continue;
            if (width < options_.min_width) continue;
            if (offset + width > scan) continue;
            const double candidate_score = score(offset, width);
            if (candidate_score < 0.55) continue;
            candidates.push_back(Candidate{candidate_score, offset, width});
        }
    }

    // Deterministic ordering: score descending, then earliest offset, then the
    // widest hypothesis (so an exact 4-byte fit beats a 1-byte subdivision).
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  if (a.score != b.score) return a.score > b.score;
                  if (a.offset != b.offset) return a.offset < b.offset;
                  return a.width > b.width;
              });

    std::vector<std::pair<std::uint64_t, std::uint64_t>> taken;
    taken.reserve(candidates.size());
    for (const Candidate& candidate : candidates) {
        const std::uint64_t begin = candidate.offset;
        const std::uint64_t end = begin + candidate.width;
        if (overlaps(taken, begin, end)) continue;
        insert_taken(taken, begin, end);

        AlignmentField field;
        field.offset = begin;
        field.width = candidate.width;
        field.kind = classify(begin, candidate.width);
        field.confidence = candidate.score;
        field.naturally_aligned =
            (begin % width_unit(candidate.width)) == 0 &&
            width_unit(candidate.width) == static_cast<std::uint64_t>(candidate.width);
        field.rationale = "u" + std::to_string(static_cast<unsigned>(candidate.width) * 8U) +
                          " at " + hex_offset(begin) + " (score " +
                          std::to_string(static_cast<int>(candidate.score * 100.0)) + "%)";
        if (field.naturally_aligned) {
            field.rationale += ", naturally aligned";
        } else {
            field.rationale += ", unaligned";
        }
        fields.push_back(std::move(field));
    }
    return fields;
}

core::PrimitiveKind AlignmentOracle::classify(std::uint64_t offset, std::uint8_t width) const {
    if (!view_.valid() || width == 0) return core::PrimitiveKind::u8;
    const std::uint64_t size = view_.size();
    if (offset >= size || static_cast<std::uint64_t>(width) > size - offset) {
        return core::PrimitiveKind::u8;
    }
    switch (width) {
    case 1: {
        const std::uint8_t byte = view_.data()[static_cast<std::size_t>(offset)];
        return is_printable(byte) ? core::PrimitiveKind::character : core::PrimitiveKind::u8;
    }
    case 2: {
        const auto raw = view_.read_uint(offset, 2, order_);
        if (!raw) return core::PrimitiveKind::u16;
        const std::uint16_t value = static_cast<std::uint16_t>(raw.value());
        const std::uint8_t low = static_cast<std::uint8_t>(value & 0xFFU);
        const std::uint8_t high = static_cast<std::uint8_t>(value >> 8U);
        if (is_printable(low) && is_printable(high)) return core::PrimitiveKind::character;
        return core::PrimitiveKind::u16;
    }
    case 4: {
        const auto raw = view_.read_uint(offset, 4, order_);
        if (!raw) return core::PrimitiveKind::u32;
        if (plausible_f32(static_cast<std::uint32_t>(raw.value()))) return core::PrimitiveKind::f32;
        return core::PrimitiveKind::u32;
    }
    case 8: {
        const auto raw = view_.read_uint(offset, 8, order_);
        if (!raw) return core::PrimitiveKind::u64;
        if (plausible_f64(raw.value())) return core::PrimitiveKind::f64;
        return core::PrimitiveKind::u64;
    }
    default: return core::PrimitiveKind::u8;
    }
}

}  // namespace typemorph::infer

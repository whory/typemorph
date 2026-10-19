// TypeMorph - multi-sample differential format inference.
//
// The engine reasons over 1..N observations of an unknown format:
//
//   1. bytes that never change identify magic values / invariants;
//   2. integer fields whose values vary linearly with the file size identify
//      array lengths (stride = size delta / count delta, inferred exactly);
//   3. fields that increase monotonically across the samples identify
//      timestamps / sequences;
//   4. the remaining common-prefix bytes are segmented with an alignment-aware
//      primitive hypothesis scorer, zero runs become padding and everything
//      that cannot be explained becomes an opaque payload node;
//   5. a detected array gets a recursively inferred element record when the
//      elements carry enough structure, otherwise an opaque element.
//
// All heuristics are deterministic: field ordering is by offset, names are
// derived from offsets, and every tie is broken explicitly.  The resulting
// TypeNode tree is directly consumable by the three emitters.
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"

#include "typemorph/infer/alignment_oracle.hpp"
#include "typemorph/infer/array_detector.hpp"
#include "typemorph/infer/diff_engine.hpp"

namespace typemorph::infer {

using core::Result;

namespace {

using core::BinaryView;
using core::ByteOrder;
using core::PrimitiveKind;
using core::TypeField;
using core::TypeNode;
using core::TypePtr;

constexpr std::uint64_t kMinSampleSize = 4;
constexpr std::size_t kMaxElementObservations = 64;
constexpr std::uint64_t kMaxElementSize = 1024;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

[[nodiscard]] std::string hex_tag(std::uint64_t value) {
    static constexpr char digits[] = "0123456789abcdef";
    char buffer[17];
    std::size_t used = 0;
    std::uint64_t remaining = value;
    do {
        buffer[used++] = digits[remaining & 0xFU];
        remaining >>= 4U;
    } while (remaining != 0 && used < sizeof(buffer));
    std::string out;
    out.reserve(used);
    while (used > 0) out.push_back(buffer[--used]);
    return out;
}

[[nodiscard]] bool is_printable_byte(std::uint8_t value) noexcept {
    return value >= 0x20U && value <= 0x7EU;
}

[[nodiscard]] std::string quote_bytes(std::span<const std::uint8_t> bytes, std::size_t limit = 16) {
    std::string out = "'";
    const std::size_t count = std::min(bytes.size(), limit);
    for (std::size_t i = 0; i < count; ++i) {
        if (is_printable_byte(bytes[i])) {
            out.push_back(static_cast<char>(bytes[i]));
        } else {
            out.push_back('.');
        }
    }
    if (bytes.size() > limit) out += "...";
    out.push_back('\'');
    return out;
}

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

// A value is "small" when the upper half of its storage is zero.  Across many
// samples this is one of the strongest signals for a real integer field, since
// random payload bytes almost never satisfy it consistently.
[[nodiscard]] bool value_is_small(std::uint64_t value, std::uint8_t width) noexcept {
    switch (width) {
    case 1: return true;
    case 2: return value <= 0x7FFFU;
    case 4: return value <= 0xFFFFU;
    case 8: return value <= 0xFFFFFFFFU;
    default: return false;
    }
}

[[nodiscard]] bool epoch_like(std::uint64_t value, std::uint8_t width) noexcept {
    const long double v = static_cast<long double>(value);
    const long double low_seconds = 946684800.0L;    // 2000-01-01
    const long double high_seconds = 4102444800.0L;  // 2100-01-01
    if (width <= 4) return v >= low_seconds && v <= high_seconds;
    for (const long double scale : {1.0L, 1e3L, 1e6L, 1e9L}) {
        if (v >= low_seconds * scale && v <= high_seconds * scale) return true;
    }
    return false;
}

// Region of analysis: per-view start offset + region-relative length.  The same
// code segments the file prefix, a trailing footer and array elements.
struct Region {
    const std::vector<BinaryView>* views = nullptr;
    std::vector<std::uint64_t> base;
    std::uint64_t length = 0;
};

// Byte-wise invariant/zero maps, region relative.
struct RegionMaps {
    std::vector<bool> same;
    std::vector<bool> zero;
    std::uint64_t length = 0;
};

[[nodiscard]] RegionMaps build_maps(const Region& region, std::uint64_t limit) {
    RegionMaps maps;
    maps.length = limit;
    maps.same.assign(static_cast<std::size_t>(limit), true);
    maps.zero.assign(static_cast<std::size_t>(limit), true);
    if (region.views == nullptr || region.views->empty()) return maps;
    for (std::uint64_t rel = 0; rel < limit; ++rel) {
        const std::uint64_t absolute = region.base[0] + rel;
        const std::uint8_t first = (*(region.views))[0].data()[static_cast<std::size_t>(absolute)];
        if (first != 0) maps.zero[static_cast<std::size_t>(rel)] = false;
        for (std::size_t s = 1; s < region.views->size(); ++s) {
            const std::uint8_t byte =
                (*(region.views))[s].data()[static_cast<std::size_t>(region.base[s] + rel)];
            if (byte != first) maps.same[static_cast<std::size_t>(rel)] = false;
            if (byte != 0) maps.zero[static_cast<std::size_t>(rel)] = false;
        }
    }
    return maps;
}

// ---------------------------------------------------------------------------
// Field hypotheses
// ---------------------------------------------------------------------------

struct ScoredField {
    double score = 0.0;
    std::uint8_t width = 0;
    PrimitiveKind kind = PrimitiveKind::u8;
    std::string rationale;
    bool valid = false;
};

// ---------------------------------------------------------------------------
// Diff builder: owns the analysis state for one comparison level (top level or
// one array element).  The segmentation algorithm is shared.
// ---------------------------------------------------------------------------

class DiffBuilder {
public:
    DiffBuilder(std::vector<BinaryView> views, std::vector<std::optional<std::int64_t>> timestamps,
                const DiffOptions& options, ByteOrder endian)
        : views_(std::move(views)), timestamps_(std::move(timestamps)), options_(options),
          endian_(endian) {}

    [[nodiscard]] const std::vector<BinaryView>& views() const noexcept { return views_; }
    [[nodiscard]] const DiffOptions& options() const noexcept { return options_; }
    [[nodiscard]] ByteOrder endian() const noexcept { return endian_; }
    [[nodiscard]] std::size_t field_count() const noexcept { return fields_.size(); }
    [[nodiscard]] bool at_capacity() const noexcept { return fields_.size() >= options_.max_fields; }

    [[nodiscard]] std::uint8_t byte_at(const Region& region, std::size_t sample,
                                       std::uint64_t rel) const {
        return views_[sample].data()[static_cast<std::size_t>(region.base[sample] + rel)];
    }

    [[nodiscard]] std::optional<std::uint64_t> word_at(const Region& region, std::size_t sample,
                                                       std::uint64_t rel,
                                                       std::uint8_t width) const {
        const auto value = views_[sample].read_uint(region.base[sample] + rel, width, endian_);
        if (!value) return std::nullopt;
        return std::optional<std::uint64_t>(value.value());
    }

    [[nodiscard]] std::optional<std::uint64_t> word_at_all(const Region& region, std::uint64_t rel,
                                                           std::uint8_t width,
                                                           std::vector<std::uint64_t>& out) const {
        out.clear();
        out.reserve(views_.size());
        for (std::size_t s = 0; s < views_.size(); ++s) {
            const auto value = word_at(region, s, rel, width);
            if (!value.has_value()) return std::nullopt;
            out.push_back(value.value());
        }
        return std::optional<std::uint64_t>(0);
    }

    [[nodiscard]] ScoredField score_field(const Region& region, const RegionMaps& maps,
                                          std::uint64_t rel, std::uint8_t width,
                                          std::uint64_t out_base) const {
        ScoredField result;
        if (rel + width > region.length) return result;
        std::vector<std::uint64_t> values;
        if (!word_at_all(region, rel, width, values).has_value()) return result;

        const std::uint64_t absolute = out_base + rel;
        double alignment = 0.15;
        if (width != 0 && absolute % width == 0) {
            alignment = 1.0;
        } else if (width >= 2 && absolute % 2 == 0) {
            alignment = 0.55;
        }

        std::size_t small = 0;
        std::size_t printable = 0;
        std::size_t printable_bytes = 0;
        bool any_variation = false;
        for (const std::uint64_t value : values) {
            if (value_is_small(value, width)) ++small;
            if (values.front() != value) any_variation = true;
        }
        if (!any_variation) return result;  // invariants are handled elsewhere

        if (width == 1) {
            for (const std::uint64_t value : values) {
                if (is_printable_byte(static_cast<std::uint8_t>(value))) ++printable;
                ++printable_bytes;
            }
        }

        double integer_plausibility = 0.30 + 0.70 * static_cast<double>(small) /
                                                 static_cast<double>(values.size());
        if (width == 1 && printable_bytes != 0) {
            const double ratio = static_cast<double>(printable) / static_cast<double>(printable_bytes);
            integer_plausibility = 0.30 + 0.70 * ratio;
        }

        double padding = 0.62;
        if (rel > 0 && maps.zero[static_cast<std::size_t>(rel - 1)]) padding += 0.19;
        if (rel + width < maps.length && maps.zero[static_cast<std::size_t>(rel + width)]) {
            padding += 0.19;
        }
        padding = std::min(padding, 1.0);

        double score = 0.35 * alignment + 0.45 * integer_plausibility + 0.20 * padding;
        switch (width) {
        case 1: score *= 0.90; break;
        case 2: score *= 0.94; break;
        case 4: score *= 1.00; break;
        case 8: score *= 0.99; break;
        default: score *= 0.90; break;
        }
        // Prefer the wider integer when the bytes immediately after a narrow
        // hypothesis are zero everywhere: a u32 whose upper half is zero looks
        // like a u16 followed by padding, and the wide reading is correct.
        if (width < 8) {
            const std::uint64_t next_width = static_cast<std::uint64_t>(width) * 2;
            bool zero_tail = true;
            for (std::uint64_t up = width; up < next_width; ++up) {
                if (rel + up >= maps.length || !maps.zero[static_cast<std::size_t>(rel + up)]) {
                    zero_tail = false;
                    break;
                }
            }
            if (zero_tail) score *= 0.88;
        }
        if (width == 1 && printable_bytes != 0) {
            const double ratio = static_cast<double>(printable) / static_cast<double>(printable_bytes);
            if (ratio >= 0.85) {
                result.kind = PrimitiveKind::character;
            } else {
                result.kind = PrimitiveKind::u8;
            }
        } else if (width == 2) {
            result.kind = PrimitiveKind::u16;
        } else if (width == 4) {
            bool floats = true;
            for (const std::uint64_t value : values) {
                if (!plausible_f32(static_cast<std::uint32_t>(value))) {
                    floats = false;
                    break;
                }
            }
            result.kind = floats ? PrimitiveKind::f32 : PrimitiveKind::u32;
        } else if (width == 8) {
            bool doubles = true;
            for (const std::uint64_t value : values) {
                if (!plausible_f64(value)) {
                    doubles = false;
                    break;
                }
            }
            result.kind = doubles ? PrimitiveKind::f64 : PrimitiveKind::u64;
        } else {
            result.kind = PrimitiveKind::u8;
        }

        result.score = std::clamp(score, 0.0, 1.0);
        result.width = width;
        result.valid = true;
        result.rationale = "aligned " + std::to_string(static_cast<unsigned>(width) * 8U) +
                           "-bit hypothesis at 0x" + hex_tag(absolute) + " (" +
                           std::to_string(static_cast<int>(result.score * 100.0)) +
                           "% across " + std::to_string(values.size()) + " samples)";
        return result;
    }

    // ---------------------------------------------------------------------
    // Monotonic sequences / timestamps
    // ---------------------------------------------------------------------

    [[nodiscard]] bool timestamps_correlate(const std::vector<std::uint64_t>& values) const {
        if (timestamps_.size() < 2) return false;
        long double first_ratio = 0.0L;
        bool have_ratio = false;
        for (std::size_t i = 1; i < values.size(); ++i) {
            if (!timestamps_[i].has_value() || !timestamps_[i - 1].has_value()) return false;
            const long double dt = static_cast<long double>(timestamps_[i].value() -
                                                            timestamps_[i - 1].value());
            if (dt == 0.0L) return false;
            const long double dv = static_cast<long double>(values[i]) -
                                   static_cast<long double>(values[i - 1]);
            if (dv <= 0.0L) return false;
            const long double ratio = dv / dt;
            if (!have_ratio) {
                first_ratio = ratio;
                have_ratio = true;
            } else if (std::fabs(ratio - first_ratio) > 1e-6L * std::max(1.0L, std::fabs(first_ratio))) {
                return false;
            }
        }
        return have_ratio;
    }

    struct MonotonicCandidate {
        std::uint64_t rel = 0;
        std::uint8_t width = 0;
        double confidence = 0.0;
        PrimitiveKind kind = PrimitiveKind::u32;
        bool timestamp = false;
        std::string comment;
    };

    [[nodiscard]] std::optional<MonotonicCandidate> monotonic_at(const Region& region,
                                                                 std::uint64_t rel,
                                                                 std::uint8_t width) const {
        if (region.length < rel + width) return std::nullopt;
        if (views_.size() < 3) return std::nullopt;  // 2 points cannot prove monotonicity
        std::vector<std::uint64_t> values;
        if (!word_at_all(region, rel, width, values).has_value()) return std::nullopt;

        bool strictly_increasing = true;
        bool non_decreasing = true;
        bool constant_delta = true;
        std::optional<std::uint64_t> delta;
        bool small_enough = true;
        bool epoch = true;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) {
                if (values[i] <= values[i - 1]) strictly_increasing = false;
                if (values[i] < values[i - 1]) non_decreasing = false;
                const std::uint64_t step = values[i] - values[i - 1];
                if (!delta.has_value()) {
                    delta = step;
                } else if (delta.value() != step) {
                    constant_delta = false;
                }
            }
            if (!value_is_small(values[i], width)) small_enough = false;
            if (!epoch_like(values[i], width)) epoch = false;
        }
        if (!non_decreasing) return std::nullopt;

        std::size_t distinct = 0;
        for (std::size_t i = 0; i < values.size(); ++i) {
            bool seen = false;
            for (std::size_t j = 0; j < i; ++j) {
                if (values[j] == values[i]) {
                    seen = true;
                    break;
                }
            }
            if (!seen) ++distinct;
        }
        if (distinct < 2) return std::nullopt;

        const bool correlated = timestamps_correlate(values);
        if (!small_enough && !epoch && !constant_delta && !correlated) {
            return std::nullopt;
        }

        double confidence = 0.70;
        confidence += 0.12 * static_cast<double>(std::min<std::size_t>(views_.size() - 2, 3));
        if (strictly_increasing) confidence += 0.04;
        if (constant_delta) confidence += 0.05;
        if (epoch) confidence += 0.10;
        if (correlated) confidence += 0.12;
        confidence = std::clamp(confidence, 0.0, 0.99);

        MonotonicCandidate candidate;
        candidate.rel = rel;
        candidate.width = width;
        candidate.confidence = confidence;
        candidate.kind = width == 8 ? PrimitiveKind::u64 : PrimitiveKind::u32;
        candidate.timestamp = epoch || correlated;
        candidate.comment = std::string(candidate.timestamp ? "monotonic timestamp" : "monotonic sequence") +
                            " across " + std::to_string(values.size()) + " samples: " +
                            std::to_string(values.front()) + " -> " + std::to_string(values.back());
        return candidate;
    }

    [[nodiscard]] bool same_byte_at(const Region& region, std::uint64_t rel) const {
        if (region.views == nullptr || region.views->empty()) return true;
        const std::uint8_t first =
            (*region.views)[0].data()[static_cast<std::size_t>(region.base[0] + rel)];
        for (std::size_t s = 1; s < region.views->size(); ++s) {
            if ((*region.views)[s].data()[static_cast<std::size_t>(region.base[s] + rel)] != first) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] std::map<std::uint64_t, TypeField> detect_monotonic(const Region& region,
                                                                      std::uint64_t out_base) const {
        std::map<std::uint64_t, TypeField> result;
        if (!options_.detect_timestamps || views_.size() < 3) return result;
        const std::uint64_t limit =
            std::min<std::uint64_t>(region.length, options_.field_scan_limit);
        std::vector<MonotonicCandidate> candidates;
        for (std::uint64_t rel = 0; rel < limit; ++rel) {
            for (const std::uint8_t width : {std::uint8_t{8}, std::uint8_t{4}}) {
                if (rel + width > limit) continue;
                if ((out_base + rel) % width != 0) continue;
                const auto candidate = monotonic_at(region, rel, width);
                if (!candidate.has_value()) continue;
                if (candidate->confidence < options_.confidence_threshold) continue;
                // A genuine counter/clock has a varying least-significant byte.
                // Its most-significant byte may well be constant (zero-extended
                // 64-bit timestamps), but only for genuine timestamp-like values;
                // otherwise an invariant header whose concatenation happens to
                // increase across samples would be misread as a counter.
                const std::uint64_t lsb_rel =
                    rel + (endian_ == ByteOrder::little ? 0 : static_cast<std::uint64_t>(width) - 1);
                const std::uint64_t msb_rel =
                    rel + (endian_ == ByteOrder::little ? static_cast<std::uint64_t>(width) - 1 : 0);
                if (same_byte_at(region, lsb_rel)) continue;
                if (same_byte_at(region, msb_rel) && !candidate->timestamp) continue;
                candidates.push_back(candidate.value());
            }
        }
        if (candidates.empty()) return result;

        std::sort(candidates.begin(), candidates.end(),
                  [](const MonotonicCandidate& a, const MonotonicCandidate& b) {
                      if (a.confidence != b.confidence) return a.confidence > b.confidence;
                      if (a.rel != b.rel) return a.rel < b.rel;
                      return a.width > b.width;
                  });

        std::vector<std::pair<std::uint64_t, std::uint64_t>> taken;
        std::vector<MonotonicCandidate> accepted;
        for (const auto& candidate : candidates) {
            const std::uint64_t begin = candidate.rel;
            const std::uint64_t end = begin + candidate.width;
            bool overlap = false;
            for (const auto& [taken_begin, taken_end] : taken) {
                if (begin < taken_end && taken_begin < end) {
                    overlap = true;
                    break;
                }
            }
            if (overlap) continue;
            taken.emplace_back(begin, end);
            accepted.push_back(candidate);
        }
        std::sort(accepted.begin(), accepted.end(),
                  [](const MonotonicCandidate& a, const MonotonicCandidate& b) {
                      return a.rel < b.rel;
                  });

        bool named_timestamp = false;
        for (const auto& candidate : accepted) {
            TypeField field;
            const std::uint64_t absolute = out_base + candidate.rel;
            std::string name;
            if (candidate.timestamp) {
                name = named_timestamp ? "timestamp_" + hex_tag(absolute) : "timestamp";
                named_timestamp = true;
            } else {
                name = "sequence_" + hex_tag(absolute);
            }
            field.name = std::move(name);
            field.type = TypeNode::primitive(candidate.kind, endian_, field.name, candidate.rel,
                                             candidate.width, candidate.confidence);
            field.offset = candidate.rel;
            field.comment = candidate.comment;
            field.confidence = candidate.confidence;
            result.emplace(absolute, std::move(field));
        }
        return result;
    }

    // ---------------------------------------------------------------------
    // Emission helpers
    // ---------------------------------------------------------------------

    void emit_field(TypeField field) {
        fields_.push_back(std::move(field));
    }

    void emit_invariant_run(const Region& region, std::uint64_t rel, std::uint64_t length,
                            std::uint64_t out_base) {
        std::uint64_t cursor = 0;
        while (cursor < length && !at_capacity()) {
            std::uint8_t width = 1;
            const std::uint64_t remaining = length - cursor;
            if (remaining >= 4) {
                width = 4;
            } else if (remaining >= 2) {
                width = 2;
            }
            const std::uint64_t absolute = out_base + rel + cursor;
            const auto bytes = region.views->empty()
                                   ? std::span<const std::uint8_t>{}
                                   : (*region.views)[0].slice_unchecked(
                                         static_cast<std::size_t>(region.base[0] + rel + cursor),
                                         static_cast<std::size_t>(width));

            TypeField field;
            const bool first = fields_.empty() && absolute == 0;
            if (first) {
                field.name = "magic";
            } else {
                field.name = "const_" + hex_tag(absolute);
            }
            PrimitiveKind kind = width == 1 ? PrimitiveKind::u8 : (width == 2 ? PrimitiveKind::u16 : PrimitiveKind::u32);
            if (width == 1 && !bytes.empty() && is_printable_byte(bytes[0])) {
                kind = PrimitiveKind::character;
            }
            field.type = TypeNode::primitive(kind, endian_, field.name, rel + cursor, width, 0.99);
            field.offset = rel + cursor;
            field.confidence = 0.99;
            field.comment = "invariant across " + std::to_string(views_.size()) + " samples: 0x" +
                            hex_tag(static_cast<std::uint64_t>(bytes.empty() ? 0 : bytes[0]));
            if (bytes.size() > 1) {
                field.comment += " " + quote_bytes(bytes);
            }
            fields_.push_back(std::move(field));

            Evidence evidence;
            evidence.kind = EvidenceKind::invariant_bytes;
            evidence.offset = absolute;
            evidence.confidence = 0.99;
            evidence.description = std::to_string(width) + " invariant bytes at 0x" +
                                   hex_tag(absolute) + " across " +
                                   std::to_string(views_.size()) + " samples";
            evidence_.push_back(std::move(evidence));
            cursor += width;
        }
        if (!region.views->empty()) {
            bool printable = true;
            for (std::uint64_t i = 0; i < length; ++i) {
                const std::uint8_t byte =
                    (*region.views)[0].data()[static_cast<std::size_t>(region.base[0] + rel + i)];
                if (!is_printable_byte(byte)) {
                    printable = false;
                    break;
                }
            }
            if (printable && length >= 4) {
                Evidence evidence;
                evidence.kind = EvidenceKind::text;
                evidence.offset = out_base + rel;
                evidence.confidence = 0.75;
                evidence.description = "invariant printable text at 0x" +
                                       hex_tag(out_base + rel);
                evidence_.push_back(std::move(evidence));
            }
        }
    }

    void emit_padding(std::uint64_t rel, std::uint64_t length) {
        if (length == 0) return;
        TypeField field;
        field.name = "padding_" + hex_tag(rel);
        field.type = TypeNode::padding(length, 0, field.name, rel);
        field.offset = rel;
        field.confidence = 1.0;
        field.comment = "zero padding";
        fields_.push_back(std::move(field));
    }

    void emit_unknown(std::uint64_t rel, std::uint64_t length) {
        if (length == 0) return;
        TypeField field;
        field.name = "payload_" + hex_tag(rel);
        field.type = TypeNode::unknown(length, field.name, rel);
        field.offset = rel;
        field.confidence = 0.35;
        field.comment = "opaque payload";
        fields_.push_back(std::move(field));
        Evidence evidence;
        evidence.kind = EvidenceKind::entropy;
        evidence.offset = rel;
        evidence.confidence = 0.4;
        evidence.description = "opaque region at 0x" + hex_tag(rel) + " (" +
                               std::to_string(length) + " bytes)";
        evidence_.push_back(std::move(evidence));
    }

    // Segments [0, region.length) and appends fields with offsets relative to
    // the parent struct.  `specials` maps absolute offsets to already-built
    // fields (array length fields) that must be spliced into the layout.
    void segment(const Region& region, std::uint64_t out_base,
                 const std::map<std::uint64_t, TypeField>& specials) {
        if (region.views == nullptr || region.views->empty() || region.length == 0) return;
        const std::uint64_t limit =
            std::min<std::uint64_t>(region.length, options_.field_scan_limit);
        if (limit == 0) return;
        const RegionMaps maps = build_maps(region, limit);

        std::vector<ScoredField> best(static_cast<std::size_t>(limit));
        for (std::uint64_t rel = 0; rel < limit; ++rel) {
            if (maps.same[static_cast<std::size_t>(rel)] ||
                maps.zero[static_cast<std::size_t>(rel)]) {
                continue;
            }
            for (const std::uint8_t width : {std::uint8_t{8}, std::uint8_t{4},
                                             std::uint8_t{2}, std::uint8_t{1}}) {
                if (rel + width > limit) continue;
                ScoredField scored = score_field(region, maps, rel, width, out_base);
                if (!scored.valid) continue;
                if (!best[static_cast<std::size_t>(rel)].valid ||
                    scored.score > best[static_cast<std::size_t>(rel)].score) {
                    best[static_cast<std::size_t>(rel)] = std::move(scored);
                }
            }
        }

        std::uint64_t pos = 0;
        while (pos < limit) {
            if (at_capacity()) {
                emit_unknown(out_base + pos, limit - pos);
                pos = limit;
                break;
            }
            const std::uint64_t absolute = out_base + pos;
            const auto special = specials.find(absolute);
            if (special != specials.end()) {
                TypeField field = special->second;
                field.offset = pos;
                field.type->offset = pos;
                const std::uint64_t size = field.type->size;
                fields_.push_back(std::move(field));
                pos += std::max<std::uint64_t>(size, 1);
                continue;
            }
            if (maps.zero[static_cast<std::size_t>(pos)]) {
                std::uint64_t run = 0;
                while (pos + run < limit &&
                       maps.zero[static_cast<std::size_t>(pos + run)] &&
                       specials.find(out_base + pos + run) == specials.end()) {
                    ++run;
                }
                emit_padding(out_base + pos, run);
                pos += run;
                continue;
            }
            if (maps.same[static_cast<std::size_t>(pos)]) {
                std::uint64_t run = 0;
                while (pos + run < limit &&
                       maps.same[static_cast<std::size_t>(pos + run)] &&
                       !maps.zero[static_cast<std::size_t>(pos + run)] &&
                       specials.find(out_base + pos + run) == specials.end()) {
                    ++run;
                }
                emit_invariant_run(region, pos, run, out_base);
                pos += run;
                continue;
            }
            const ScoredField& scored = best[static_cast<std::size_t>(pos)];
            if (scored.valid && scored.score >= options_.confidence_threshold) {
                TypeField field;
                field.name = "field_" + hex_tag(absolute);
                field.type = TypeNode::primitive(scored.kind, endian_, field.name, pos,
                                                 scored.width, scored.score);
                field.offset = pos;
                field.comment = scored.rationale;
                field.confidence = scored.score;
                fields_.push_back(std::move(field));
                pos += scored.width;
                continue;
            }
            // Unknown blob: extend until the next explainable position.
            const std::uint64_t begin = pos;
            ++pos;
            while (pos < limit) {
                if (specials.find(out_base + pos) != specials.end()) break;
                if (maps.zero[static_cast<std::size_t>(pos)]) break;
                if (maps.same[static_cast<std::size_t>(pos)]) break;
                const ScoredField& candidate = best[static_cast<std::size_t>(pos)];
                if (candidate.valid && candidate.score >= options_.confidence_threshold) break;
                ++pos;
            }
            emit_unknown(out_base + begin, pos - begin);
        }
        if (limit < region.length) {
            emit_unknown(out_base + limit, region.length - limit);
        }
    }

    // Fills over-capacity gaps and enforces deterministic ordering.
    void finalise(std::uint64_t total_size, std::uint64_t known_size) {
        std::sort(fields_.begin(), fields_.end(), [](const TypeField& a, const TypeField& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            const std::uint64_t a_size = a.type ? a.type->size : 0;
            const std::uint64_t b_size = b.type ? b.type->size : 0;
            return a_size < b_size;
        });
        std::vector<TypeField> ordered;
        ordered.reserve(fields_.size() + 4);
        std::uint64_t cursor = 0;
        for (auto& field : fields_) {
            if (!field.type) continue;
            if (field.offset < cursor) continue;  // overlap defensively
            if (field.offset > cursor) {
                const std::uint64_t gap = field.offset - cursor;
                TypeField filler;
                filler.name = "gap_" + hex_tag(cursor);
                filler.offset = cursor;
                filler.confidence = 0.4;
                if (cursor + gap <= known_size) {
                    filler.type = TypeNode::padding(gap, 0, filler.name, cursor);
                    filler.comment = "unclassified gap";
                } else {
                    filler.type = TypeNode::unknown(gap, filler.name, cursor);
                    filler.comment = "unclassified gap";
                }
                ordered.push_back(std::move(filler));
            }
            cursor = field.offset + field.type->size;
            ordered.push_back(std::move(field));
        }
        if (cursor < total_size) {
            TypeField filler;
            filler.name = "payload_" + hex_tag(cursor);
            filler.offset = cursor;
            filler.confidence = 0.35;
            filler.type = TypeNode::unknown(total_size - cursor, filler.name, cursor);
            filler.comment = "unclassified trailing bytes";
            ordered.push_back(std::move(filler));
        }
        // Hard field-count budget: keep the leading layout and collapse
        // everything else into one opaque tail so the tree stays manageable.
        if (ordered.size() > options_.max_fields) {
            std::vector<TypeField> trimmed;
            const std::size_t keep =
                options_.max_fields > 1 ? static_cast<std::size_t>(options_.max_fields - 1) : 0;
            trimmed.reserve(keep + 1);
            for (std::size_t i = 0; i < keep && i < ordered.size(); ++i) {
                trimmed.push_back(std::move(ordered[i]));
            }
            std::uint64_t covered = 0;
            if (!trimmed.empty()) {
                const TypeField& last = trimmed.back();
                covered = last.offset + (last.type ? last.type->size : 0);
            }
            if (total_size > covered) {
                TypeField tail;
                tail.name = "payload_" + hex_tag(covered);
                tail.offset = covered;
                tail.confidence = 0.3;
                tail.type = TypeNode::unknown(total_size - covered, tail.name, covered);
                tail.comment = "field budget exhausted; remaining bytes are opaque";
                trimmed.push_back(std::move(tail));
            }
            ordered = std::move(trimmed);
        }
        fields_ = std::move(ordered);
    }

    [[nodiscard]] std::vector<TypeField>& fields() noexcept { return fields_; }
    [[nodiscard]] const std::vector<TypeField>& fields() const noexcept { return fields_; }
    [[nodiscard]] std::vector<Evidence>& evidence() noexcept { return evidence_; }
    [[nodiscard]] const std::vector<Evidence>& evidence() const noexcept { return evidence_; }

private:
    std::vector<BinaryView> views_;
    std::vector<std::optional<std::int64_t>> timestamps_;
    const DiffOptions& options_;
    ByteOrder endian_;
    std::vector<TypeField> fields_;
    std::vector<Evidence> evidence_;
};

// ---------------------------------------------------------------------------
// Array correlation (endian-aware; the stride mathematics is delegated to
// ArrayDetector::infer_stride so there is exactly one implementation of it).
// ---------------------------------------------------------------------------

[[nodiscard]] double array_confidence(std::size_t sample_count, std::uint64_t stride,
                                      std::uint64_t data_offset, std::uint8_t width,
                                      std::uint64_t min_count, std::uint64_t max_count,
                                      std::uint64_t min_elements) {
    double confidence = 0.86;
    confidence += 0.04 * static_cast<double>(std::min<std::size_t>(sample_count - 2, 3));
    if (stride % 4 == 0) confidence += 0.02;
    if (data_offset % 8 == 0) confidence += 0.02;
    if (max_count >= min_count + 2 * min_elements) confidence += 0.02;
    if (width >= 4) confidence += 0.01;
    return std::clamp(confidence, 0.0, 0.99);
}

[[nodiscard]] std::optional<ArrayBoundary> detect_primary_array(
    const std::vector<BinaryView>& views, const DiffOptions& options, ByteOrder endian) {
    if (!options.detect_arrays || views.size() < 2) return std::nullopt;
    std::uint64_t min_size = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_size = 0;
    for (const auto& view : views) {
        min_size = std::min<std::uint64_t>(min_size, view.size());
        max_size = std::max<std::uint64_t>(max_size, view.size());
    }
    if (min_size == 0) return std::nullopt;
    const std::uint64_t scan = std::min<std::uint64_t>(min_size, options.field_scan_limit);

    std::vector<ArrayBoundary> candidates;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> observations;
    observations.reserve(views.size());
    for (std::uint64_t offset = 0; offset < scan; ++offset) {
        for (const std::uint8_t width : {std::uint8_t{4}, std::uint8_t{2}, std::uint8_t{1},
                                         std::uint8_t{8}}) {
            if (offset + width > scan) continue;
            observations.clear();
            bool usable = true;
            for (const auto& view : views) {
                const auto value = view.read_uint(offset, width, endian);
                if (!value) {
                    usable = false;
                    break;
                }
                if (value.value() > max_size) {
                    usable = false;
                    break;
                }
                observations.emplace_back(value.value(), view.size());
            }
            if (!usable) continue;

            bool varying = false;
            for (std::size_t i = 1; i < observations.size(); ++i) {
                if (observations[i].first != observations[0].first) varying = true;
            }
            if (!varying) continue;

            const auto stride = ArrayDetector::infer_stride(observations);
            if (!stride.has_value()) continue;
            const std::uint64_t element_size = stride.value();
            if (element_size == 0 || element_size > kMaxElementSize) continue;

            std::optional<std::uint64_t> base;
            std::uint64_t min_count = std::numeric_limits<std::uint64_t>::max();
            std::uint64_t max_count = 0;
            bool consistent = true;
            for (const auto& [count, size] : observations) {
                if (count > std::numeric_limits<std::uint64_t>::max() / element_size) {
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
                min_count = std::min(min_count, count);
                max_count = std::max(max_count, count);
            }
            if (!consistent || !base.has_value()) continue;
            const std::uint64_t data_offset = base.value();
            if (data_offset < offset + width) continue;
            if (data_offset > min_size) continue;
            if (max_count < options.min_array_elements) continue;

            ArrayBoundary boundary;
            boundary.length_offset = offset;
            boundary.length_width = width;
            boundary.data_offset = data_offset;
            boundary.element_size = element_size;
            boundary.observed_count = max_count;
            boundary.confidence = array_confidence(views.size(), element_size, data_offset, width,
                                                   min_count, max_count,
                                                   options.min_array_elements);
            boundary.rationale = "count at 0x" + hex_tag(offset) + " (u" +
                                 std::to_string(static_cast<unsigned>(width) * 8U) +
                                 ") correlates exactly with file size: stride " +
                                 std::to_string(element_size) + ", base " +
                                 std::to_string(data_offset) + " over " +
                                 std::to_string(views.size()) + " samples";
            candidates.push_back(std::move(boundary));
        }
    }
    if (candidates.empty()) return std::nullopt;

    std::sort(candidates.begin(), candidates.end(),
              [](const ArrayBoundary& a, const ArrayBoundary& b) {
                  if (a.confidence != b.confidence) return a.confidence > b.confidence;
                  if (a.length_offset != b.length_offset) return a.length_offset < b.length_offset;
                  return a.length_width > b.length_width;
              });
    // Suppress overlapping interpretations of the same length field.
    for (const auto& candidate : candidates) {
        bool duplicate = false;
        for (const auto& chosen : candidates) {
            if (&chosen == &candidate) break;
            const std::uint64_t chosen_end = chosen.length_offset + chosen.length_width;
            if (candidate.length_offset < chosen_end &&
                chosen.length_offset < candidate.length_offset + candidate.length_width) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) return candidate;
    }
    return candidates.front();
}

// ---------------------------------------------------------------------------
// Structural array fallback.
//
// The size-delta model above only works when the array is the sole source of
// size variation and ends at EOF.  Real formats usually append a variable-sized
// section (string table, trailer, ...) after the records, so `size - count *
// stride` is no longer constant.  This fallback instead looks for a count field
// followed by a dense sequence of fixed-stride records whose bytes are
// invariant at fixed in-record positions (tags, constants, zero padding).  It is
// deliberately cheap: candidates are pruned by count plausibility and the stride
// range is bounded by how many records actually fit in the smallest sample.
// ---------------------------------------------------------------------------

struct StructuralEvidence {
    std::size_t invariant_positions = 0;
    std::size_t nonzero_invariant_positions = 0;
};

[[nodiscard]] StructuralEvidence measure_record_structure(
    const std::vector<BinaryView>& views, const std::vector<std::uint64_t>& counts,
    std::uint64_t data_offset, std::uint64_t stride, std::size_t& work,
    std::size_t work_budget) noexcept {
    StructuralEvidence evidence;
    for (std::uint64_t rel = 0; rel < stride; ++rel) {
        const std::uint8_t* first_data = views[0].data();
        std::uint8_t first = 0;
        bool first_seen = false;
        bool identical = true;
        bool nonzero = false;
        for (std::size_t s = 0; s < views.size() && identical; ++s) {
            const std::uint8_t* data = views[s].data();
            const std::uint64_t records = counts[s];
            for (std::uint64_t i = 0; i < records; ++i) {
                if (++work > work_budget) return evidence;
                const std::uint8_t byte = data[data_offset + i * stride + rel];
                (void)first_data;
                if (!first_seen) {
                    first = byte;
                    first_seen = true;
                    nonzero = byte != 0;
                } else if (byte != first) {
                    identical = false;
                    break;
                }
            }
        }
        if (identical && first_seen) {
            ++evidence.invariant_positions;
            if (nonzero) ++evidence.nonzero_invariant_positions;
        }
    }
    return evidence;
}

[[nodiscard]] std::optional<ArrayBoundary> detect_structural_array(
    const std::vector<BinaryView>& views, const DiffOptions& options, ByteOrder endian) {
    if (!options.detect_arrays || views.size() < 2) return std::nullopt;
    std::uint64_t min_size = std::numeric_limits<std::uint64_t>::max();
    for (const auto& view : views) {
        min_size = std::min<std::uint64_t>(min_size, view.size());
    }
    if (min_size == 0) return std::nullopt;
    const std::uint64_t scan = std::min<std::uint64_t>(min_size, options.field_scan_limit);

    struct Candidate {
        ArrayBoundary boundary;
        StructuralEvidence evidence;
        std::uint64_t count_offset = 0;
    };
    std::vector<Candidate> candidates;
    std::size_t work = 0;
    constexpr std::size_t kWorkBudget = 8U << 20U;

    for (std::uint64_t offset = 0; offset < scan && work <= kWorkBudget; ++offset) {
        for (const std::uint8_t width : {std::uint8_t{4}, std::uint8_t{2}, std::uint8_t{8},
                                         std::uint8_t{1}}) {
            if (offset + width > scan) continue;
            std::vector<std::uint64_t> counts;
            counts.reserve(views.size());
            bool usable = true;
            bool varying = false;
            std::uint64_t min_count = std::numeric_limits<std::uint64_t>::max();
            for (const auto& view : views) {
                const auto value = view.read_uint(offset, width, endian);
                if (!value) {
                    usable = false;
                    break;
                }
                if (!counts.empty() && value.value() != counts.front()) varying = true;
                counts.push_back(value.value());
                min_count = std::min(min_count, value.value());
            }
            if (!usable || !varying) continue;
            if (min_count < options.min_array_elements) continue;
            if (min_count < 2) continue;

            // All counts must be able to describe at least two records each.
            std::size_t samples_with_two = 0;
            bool plausible = true;
            for (std::size_t s = 0; s < counts.size(); ++s) {
                if (counts[s] >= 2) ++samples_with_two;
                if (views[s].size() <= offset + width) {
                    plausible = false;
                    break;
                }
                if (counts[s] > views[s].size() - (offset + width)) {
                    plausible = false;
                    break;
                }
            }
            if (!plausible || samples_with_two < 2) continue;

            // Data offset candidates: the field is normally immediately
            // followed by the first record, but small alignment gaps exist.
            for (std::uint64_t extra = 0; extra <= 64 && work <= kWorkBudget; extra += 1) {
                const std::uint64_t data_offset = offset + width + extra;
                if (data_offset > min_size) break;
                if (data_offset % 2 != 0) continue;
                std::uint64_t max_stride = kMaxElementSize;
                for (std::size_t s = 0; s < views.size(); ++s) {
                    if (data_offset >= views[s].size()) {
                        max_stride = 0;
                        break;
                    }
                    const std::uint64_t available = views[s].size() - data_offset;
                    const std::uint64_t bound = available / counts[s];
                    max_stride = std::min(max_stride, bound);
                }
                if (max_stride == 0 || max_stride > kMaxElementSize) continue;

                for (std::uint64_t stride = 1; stride <= max_stride && work <= kWorkBudget;
                     ++stride) {
                    const StructuralEvidence evidence =
                        measure_record_structure(views, counts, data_offset, stride, work,
                                                 kWorkBudget);
                    // A single invariant zero byte is not evidence of records;
                    // require a non-zero constant (tag, version, ...) or at
                    // least two neighbouring invariant bytes.
                    if (evidence.nonzero_invariant_positions == 0) continue;
                    if (evidence.nonzero_invariant_positions == 1 && stride > 12) continue;

                    double confidence = 0.55;
                    confidence +=
                        0.20 * std::min(1.0, static_cast<double>(
                                                 evidence.nonzero_invariant_positions) /
                                                 2.0);
                    if (stride % 4 == 0) confidence += 0.04;
                    if (data_offset == offset + width) confidence += 0.03;
                    if (width == 4 && offset % 4 == 0) {
                        confidence += 0.06;
                    } else if (width >= 2) {
                        confidence += 0.02;
                    }
                    if (data_offset % 4 == 0) confidence += 0.05;
                    if (views.size() >= 3) confidence += 0.03;
                    confidence = std::clamp(confidence, 0.0, 0.97);

                    Candidate candidate;
                    candidate.boundary.length_offset = offset;
                    candidate.boundary.length_width = width;
                    candidate.boundary.data_offset = data_offset;
                    candidate.boundary.element_size = stride;
                    candidate.boundary.observed_count = 0;
                    for (const std::uint64_t count : counts) {
                        candidate.boundary.observed_count =
                            std::max(candidate.boundary.observed_count, count);
                    }
                    candidate.boundary.confidence = confidence;
                    candidate.boundary.rationale =
                        "count at 0x" + hex_tag(offset) + " (u" +
                        std::to_string(static_cast<unsigned>(width) * 8U) +
                        ") precedes well-formed " + std::to_string(stride) + "-byte records at 0x" +
                        hex_tag(data_offset) + " (" +
                        std::to_string(evidence.nonzero_invariant_positions) +
                        " invariant byte positions, " +
                        std::to_string(candidate.boundary.observed_count) + " records max)";
                    candidate.evidence = evidence;
                    candidate.count_offset = offset;
                    candidates.push_back(std::move(candidate));
                }
            }
        }
    }
    if (candidates.empty()) return std::nullopt;

    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  const ArrayBoundary& left = a.boundary;
                  const ArrayBoundary& right = b.boundary;
                  if (left.confidence != right.confidence) return left.confidence > right.confidence;
                  if (a.evidence.nonzero_invariant_positions !=
                      b.evidence.nonzero_invariant_positions) {
                      return a.evidence.nonzero_invariant_positions >
                             b.evidence.nonzero_invariant_positions;
                  }
                  if (a.evidence.invariant_positions != b.evidence.invariant_positions) {
                      return a.evidence.invariant_positions > b.evidence.invariant_positions;
                  }
                  if (left.data_offset != right.data_offset) {
                      return left.data_offset < right.data_offset;
                  }
                  if (left.element_size != right.element_size) {
                      return left.element_size < right.element_size;
                  }
                  if (left.length_offset != right.length_offset) {
                      return left.length_offset < right.length_offset;
                  }
                  return left.length_width > right.length_width;
              });

    std::vector<ArrayBoundary> accepted;
    for (const auto& candidate : candidates) {
        bool duplicate = false;
        for (const auto& existing : accepted) {
            const std::uint64_t existing_end = existing.length_offset + existing.length_width;
            if (candidate.boundary.length_offset < existing_end &&
                existing.length_offset <
                    candidate.boundary.length_offset + candidate.boundary.length_width) {
                duplicate = true;
                break;
            }
            if (candidate.boundary.data_offset == existing.data_offset &&
                candidate.boundary.element_size == existing.element_size) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) accepted.push_back(candidate.boundary);
        if (accepted.size() >= 4) break;
    }
    if (accepted.empty()) return std::nullopt;
    return accepted.front();
}

// ---------------------------------------------------------------------------
// Recursively inferred array element record
// ---------------------------------------------------------------------------

[[nodiscard]] TypePtr infer_element_type(std::vector<BinaryView> elements, std::uint64_t stride,
                                         const DiffOptions& options, ByteOrder endian,
                                         int depth) {
    const auto opaque = [&]() { return TypeNode::unknown(stride, "item"); };
    if (stride == 0) return TypeNode::unknown(1, "item");
    if (stride == 1) return TypeNode::primitive(PrimitiveKind::u8, endian, "item", 0, 1, 0.5);
    if (depth <= 0) return opaque();
    if (elements.size() > kMaxElementObservations) elements.resize(kMaxElementObservations);
    if (elements.size() < 3) return opaque();

    bool any_variation = false;
    for (std::uint64_t rel = 0; rel < stride && !any_variation; ++rel) {
        const std::uint8_t first = elements[0].data()[static_cast<std::size_t>(rel)];
        for (std::size_t i = 1; i < elements.size(); ++i) {
            if (elements[i].data()[static_cast<std::size_t>(rel)] != first) {
                any_variation = true;
                break;
            }
        }
    }
    if (!any_variation) return opaque();

    std::vector<std::optional<std::int64_t>> no_timestamps;
    DiffBuilder builder(std::move(elements), no_timestamps, options, endian);
    Region region;
    region.views = &builder.views();
    region.base.assign(builder.views().size(), 0);
    region.length = stride;
    std::map<std::uint64_t, TypeField> no_specials;
    builder.segment(region, 0, no_specials);
    if (builder.fields().empty()) return opaque();

    std::uint64_t structured = 0;
    for (const auto& field : builder.fields()) {
        if (!field.type) continue;
        if (field.type->is<core::UnknownNode>() || field.type->is<core::PaddingNode>()) continue;
        if (field.confidence < options.confidence_threshold) continue;
        structured += field.type->size;
    }
    if (structured * 4 < stride) return opaque();

    builder.finalise(stride, stride);
    std::vector<TypeField> fields = builder.fields();
    auto record = TypeNode::structure(std::move(fields), "item", 0, stride, 0.85);
    if (auto* structure = record->get_if<core::StructNode>()) {
        structure->declared_size = stride;
        structure->packed = false;
    }
    record->size = stride;
    return record;
}

// ---------------------------------------------------------------------------
// Single-sample structural inference
// ---------------------------------------------------------------------------

[[nodiscard]] Result<InferenceResult> infer_single_sample(const Sample& sample,
                                                          const DiffOptions& options) {
    const BinaryView& view = sample.view;
    InferenceResult result;
    result.endian = options.endian;
    result.sample_count = 1;
    result.min_size = view.size();
    result.max_size = view.size();
    result.format_name = "recovered";

    AlignmentOptions alignment_options;
    alignment_options.max_scan_bytes =
        std::min<std::uint64_t>(view.size(), options.field_scan_limit);
    AlignmentOracle oracle(view, options.endian, alignment_options);
    const auto oracle_fields = oracle.detect_fields();
    std::map<std::uint64_t, AlignmentField> by_offset;
    for (const auto& field : oracle_fields) by_offset.emplace(field.offset, field);

    const std::uint64_t limit = std::min<std::uint64_t>(view.size(), options.field_scan_limit);
    std::vector<TypeField> fields;
    const auto is_zero = [&view](std::uint64_t offset) { return view.data()[offset] == 0; };
    const auto at_capacity = [&]() { return fields.size() >= options.max_fields; };

    std::uint64_t pos = 0;
    while (pos < limit) {
        if (at_capacity()) {
            TypeField tail;
            tail.name = "payload_" + hex_tag(pos);
            tail.offset = pos;
            tail.confidence = 0.3;
            tail.type = TypeNode::unknown(limit - pos, tail.name, pos);
            fields.push_back(std::move(tail));
            pos = limit;
            break;
        }
        const auto field = by_offset.find(pos);
        if (field != by_offset.end()) {
            TypeField typed;
            typed.name = (pos == 0 && field->second.width >= 4) ? "magic"
                                                               : "field_" + hex_tag(pos);
            typed.type = TypeNode::primitive(field->second.kind, options.endian, typed.name, pos,
                                             field->second.width,
                                             field->second.confidence * 0.55);
            typed.offset = pos;
            typed.confidence = field->second.confidence * 0.55;
            typed.comment = field->second.rationale;
            const std::uint64_t size = typed.type->size;
            fields.push_back(std::move(typed));
            pos += std::max<std::uint64_t>(size, 1);
            continue;
        }
        if (is_zero(pos)) {
            std::uint64_t run = 0;
            while (pos + run < limit && is_zero(pos + run)) ++run;
            TypeField padding;
            padding.name = "padding_" + hex_tag(pos);
            padding.offset = pos;
            padding.confidence = 1.0;
            padding.type = TypeNode::padding(run, 0, padding.name, pos);
            padding.comment = "zero padding";
            fields.push_back(std::move(padding));
            pos += run;
            continue;
        }
        const std::uint64_t begin = pos;
        ++pos;
        while (pos < limit) {
            if (by_offset.find(pos) != by_offset.end()) break;
            if (is_zero(pos)) break;
            ++pos;
        }
        TypeField unknown;
        unknown.name = "payload_" + hex_tag(begin);
        unknown.offset = begin;
        unknown.confidence = 0.3;
        unknown.type = TypeNode::unknown(pos - begin, unknown.name, begin);
        unknown.comment = "opaque region";
        fields.push_back(std::move(unknown));
    }
    if (limit < view.size()) {
        TypeField tail;
        tail.name = "payload_" + hex_tag(limit);
        tail.offset = limit;
        tail.confidence = 0.3;
        tail.type = TypeNode::unknown(view.size() - limit, tail.name, limit);
        fields.push_back(std::move(tail));
    }

    std::uint64_t covered = 0;
    for (const auto& field : fields) {
        if (field.type && !field.type->is<core::PaddingNode>() &&
            !field.type->is<core::UnknownNode>()) {
            covered += field.type->size;
        }
    }
    double coverage = view.size() == 0 ? 0.0
                                       : static_cast<double>(covered) /
                                             static_cast<double>(view.size());
    const double overall = std::clamp(0.20 + 0.35 * coverage, 0.0, 0.55);

    auto root = TypeNode::structure(std::move(fields), "recovered", 0, view.size(), overall);
    if (auto* structure = root->get_if<core::StructNode>()) {
        structure->alignment = oracle.detect_alignment(0, limit);
        structure->declared_size = view.size();
    }
    result.root = std::move(root);
    result.confidence = overall;

    for (const auto& field : result.root->get_if<core::StructNode>()->fields) {
        if (!field.type) continue;
        if (field.type->is<core::PaddingNode>()) continue;
        InferredField inferred;
        inferred.offset = field.offset;
        inferred.name = field.name;
        inferred.confidence = field.confidence;
        inferred.rationale = field.comment;
        inferred.width = static_cast<std::uint8_t>(std::min<std::uint64_t>(field.type->size, 255));
        if (const auto* primitive = field.type->get_if<core::PrimitiveNode>()) {
            inferred.kind = primitive->kind;
            inferred.type_name = std::string(core::to_string(primitive->kind));
        } else if (const auto* array = field.type->get_if<core::ArrayNode>()) {
            inferred.array_element_size = array->element_stride;
            inferred.count_field_offset = array->count_field_offset;
            inferred.element_count = array->count;
            inferred.type_name = "array";
        } else if (const auto* str = field.type->get_if<core::StringNode>()) {
            inferred.type_name = "string";
        } else if (field.type->is<core::StructNode>()) {
            inferred.type_name = "struct";
        } else {
            inferred.type_name = "opaque";
        }
        result.fields.push_back(std::move(inferred));
    }

    Evidence alignment_evidence;
    alignment_evidence.kind = EvidenceKind::alignment;
    alignment_evidence.offset = 0;
    alignment_evidence.confidence = 0.6;
    alignment_evidence.description =
        "structural alignment " + std::to_string(result.root->get_if<core::StructNode>()->alignment) +
        " inferred from a single sample";
    result.evidence.push_back(std::move(alignment_evidence));
    Evidence boundary_evidence;
    boundary_evidence.kind = EvidenceKind::structural_boundary;
    boundary_evidence.offset = 0;
    boundary_evidence.confidence = 0.55;
    boundary_evidence.description = std::to_string(oracle_fields.size()) +
                                    " primitive hypotheses from alignment/entropy analysis";
    result.evidence.push_back(std::move(boundary_evidence));
    return result;
}

// ---------------------------------------------------------------------------
// Multi-sample inference
// ---------------------------------------------------------------------------

[[nodiscard]] InferredField to_inferred_field(const TypeField& field) {
    InferredField inferred;
    inferred.offset = field.offset;
    inferred.name = field.name;
    inferred.confidence = field.confidence;
    inferred.rationale = field.comment;
    inferred.width = static_cast<std::uint8_t>(std::min<std::uint64_t>(field.type->size, 255));
    if (const auto* primitive = field.type->get_if<core::PrimitiveNode>()) {
        inferred.kind = primitive->kind;
        inferred.type_name = std::string(core::to_string(primitive->kind));
        inferred.invariant = field.confidence >= 0.98 &&
                             (field.name == "magic" || field.name.rfind("const_", 0) == 0);
    } else if (const auto* array = field.type->get_if<core::ArrayNode>()) {
        if (array->element) {
            if (const auto* element_primitive =
                    array->element->get_if<core::PrimitiveNode>()) {
                inferred.kind = element_primitive->kind;
                inferred.type_name =
                    "array<" + std::string(core::to_string(element_primitive->kind)) + ">";
            } else if (array->element->is<core::StructNode>()) {
                inferred.type_name = "array<struct>";
            } else {
                inferred.type_name = "array<opaque>";
            }
        } else {
            inferred.type_name = "array";
        }
        inferred.array_element_size = array->element_stride;
        inferred.count_field_offset = array->count_field_offset;
        inferred.element_count = array->count;
    } else if (const auto* str = field.type->get_if<core::StringNode>()) {
        inferred.type_name = "string";
    } else if (field.type->is<core::StructNode>()) {
        inferred.type_name = "struct";
    } else {
        inferred.type_name = "opaque";
    }
    return inferred;
}

[[nodiscard]] Result<InferenceResult> infer_multi_sample(std::span<const Sample> samples,
                                                         const DiffOptions& options) {
    std::vector<BinaryView> views;
    std::vector<std::optional<std::int64_t>> timestamps;
    views.reserve(samples.size());
    timestamps.reserve(samples.size());
    std::uint64_t min_size = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_size = 0;
    std::size_t reference = 0;
    for (std::size_t i = 0; i < samples.size(); ++i) {
        views.push_back(samples[i].view);
        timestamps.push_back(samples[i].timestamp);
        min_size = std::min<std::uint64_t>(min_size, samples[i].view.size());
        if (samples[i].view.size() > max_size) {
            max_size = samples[i].view.size();
            reference = i;
        }
    }
    const std::uint64_t reference_size = views[reference].size();

    DiffBuilder builder(std::move(views), std::move(timestamps), options, options.endian);

    InferenceResult result;
    result.endian = options.endian;
    result.sample_count = samples.size();
    result.min_size = min_size;
    result.max_size = max_size;
    result.format_name = "recovered";

    // 1. Array correlation across samples.
    std::map<std::uint64_t, TypeField> specials;
    std::optional<ArrayBoundary> array;
    std::uint64_t data_offset = min_size;
    std::uint64_t array_stride = 0;
    std::uint64_t reference_count = 0;
    std::uint64_t array_end = min_size;
    std::string count_field_name;
    if (options.detect_arrays) {
        // Two independent detectors: the exact size-delta model (array is the
        // only size source and ends at EOF) and the structural record model
        // (count field followed by dense fixed-stride records, possibly with a
        // variable-size section after the array).  Prefer the more confident.
        std::optional<ArrayBoundary> tail =
            detect_primary_array(builder.views(), options, options.endian);
        std::optional<ArrayBoundary> structural =
            detect_structural_array(builder.views(), options, options.endian);
        const auto effective_confidence = [&](const ArrayBoundary& boundary) {
            return std::max(boundary.confidence,
                            array_confidence(builder.views().size(), boundary.element_size,
                                             boundary.data_offset, boundary.length_width, 0,
                                             boundary.observed_count,
                                             options.min_array_elements));
        };
        bool structural_chosen = false;
        if (tail.has_value() && structural.has_value()) {
            if (effective_confidence(*structural) > effective_confidence(*tail)) {
                array = structural;
                structural_chosen = true;
            } else {
                array = tail;
            }
        } else if (tail.has_value()) {
            array = tail;
        } else if (structural.has_value()) {
            array = structural;
            structural_chosen = true;
        }
        if (array.has_value() && effective_confidence(*array) < options.confidence_threshold) {
            array.reset();
        }
        if (array.has_value()) {
            data_offset = array->data_offset;
            array_stride = array->element_size;
            // The count must be read from the recovered length field: a
            // structural match does not imply that the array ends at EOF.
            if (array_stride != 0 && data_offset <= reference_size) {
                if (const auto count = builder.views()[reference].read_uint(
                        array->length_offset, array->length_width, options.endian);
                    count) {
                    reference_count = count.value();
                }
                const std::uint64_t capacity = (reference_size - data_offset) / array_stride;
                if (reference_count == 0 || reference_count > capacity) {
                    reference_count = capacity;
                }
            }
            array_end = data_offset + reference_count * array_stride;

            const double confidence = effective_confidence(*array);
            count_field_name = "count_" + hex_tag(array->length_offset);
            TypeField count_field;
            count_field.name = count_field_name;
            count_field.offset = array->length_offset;
            count_field.confidence = confidence;
            count_field.comment = "element count for `items` (record stride " +
                                  std::to_string(array_stride) + ")";
            PrimitiveKind count_kind = array->length_width == 1
                                           ? PrimitiveKind::u8
                                           : (array->length_width == 2
                                                  ? PrimitiveKind::u16
                                                  : (array->length_width == 4
                                                         ? PrimitiveKind::u32
                                                         : PrimitiveKind::u64));
            count_field.type = TypeNode::primitive(count_kind, options.endian, count_field_name,
                                                   array->length_offset, array->length_width,
                                                   confidence);
            specials.emplace(array->length_offset, std::move(count_field));

            Evidence evidence;
            evidence.kind = structural_chosen ? EvidenceKind::structural_boundary
                                              : EvidenceKind::size_correlation;
            evidence.offset = array->length_offset;
            evidence.confidence = confidence;
            evidence.description = array->rationale;
            result.evidence.push_back(std::move(evidence));
        }
    }

    // 2. Prefix segmentation: everything before the array payload.  Monotonic
    //    fields (timestamps / sequence numbers) are resolved first and spliced
    //    into the layout as named primitives.
    Region prefix;
    prefix.views = &builder.views();
    prefix.base.assign(builder.views().size(), 0);
    prefix.length = data_offset;
    if (prefix.length > 0) {
        auto monotonic = builder.detect_monotonic(prefix, 0);
        if (array.has_value()) {
            const std::uint64_t count_begin = array->length_offset;
            const std::uint64_t count_end = count_begin + array->length_width;
            for (auto it = monotonic.begin(); it != monotonic.end();) {
                const std::uint64_t begin = it->first;
                const std::uint64_t end = begin + (it->second.type ? it->second.type->size : 0);
                if (begin < count_end && count_begin < end) {
                    it = monotonic.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& [offset, field] : monotonic) {
            Evidence evidence;
            evidence.kind = EvidenceKind::monotonic_sequence;
            evidence.offset = offset;
            evidence.confidence = field.confidence;
            evidence.description = field.comment;
            result.evidence.push_back(std::move(evidence));
            specials.emplace(offset, std::move(field));
        }
        builder.segment(prefix, 0, specials);
    }

    // 3. The array itself.
    if (array.has_value()) {
        const double confidence =
            std::max(array->confidence,
                     array_confidence(builder.views().size(), array_stride, data_offset,
                                      array->length_width, 0, reference_count,
                                      options.min_array_elements));
        std::vector<BinaryView> element_views;
        if (array_stride != 0 && array_stride <= kMaxElementSize) {
            const std::size_t total = std::min<std::size_t>(
                kMaxElementObservations,
                static_cast<std::size_t>(std::min<std::uint64_t>(reference_count, 1U << 20U)));
            const std::uint64_t capacity =
                reference_size >= data_offset ? (reference_size - data_offset) / array_stride : 0;
            const std::size_t usable = static_cast<std::size_t>(
                std::min<std::uint64_t>(total, std::min(reference_count, capacity)));
            element_views.reserve(usable);
            for (std::size_t i = 0; i < usable; ++i) {
                const std::uint64_t start = data_offset + static_cast<std::uint64_t>(i) * array_stride;
                const auto slice = builder.views()[reference].slice(start, array_stride);
                if (!slice) break;
                element_views.push_back(BinaryView::from_external(
                    slice.value(), "element_" + std::to_string(i)));
            }
        }

        TypePtr element;
        if (options.nested_records && array_stride >= 2 &&
            array_stride <= options.max_nested_element_size) {
            element = infer_element_type(std::move(element_views), array_stride, options,
                                         options.endian, 1);
        }
        if (!element) {
            element = array_stride == 1 ? TypeNode::primitive(PrimitiveKind::u8, options.endian,
                                                              "item", 0, 1, 0.5)
                                        : TypeNode::unknown(array_stride, "item");
        }
        auto array_node = TypeNode::array(element, reference_count, "items", data_offset,
                                          array_stride, confidence);
        if (auto* node = array_node->get_if<core::ArrayNode>()) {
            node->count_field_offset = array->length_offset;
            node->count_expression = count_field_name;
        }
        array_node->size = reference_count * array_stride;
        TypeField array_field;
        array_field.name = "items";
        array_field.type = std::move(array_node);
        array_field.offset = data_offset;
        array_field.confidence = confidence;
        array_field.comment = std::to_string(reference_count) + " elements of " +
                              std::to_string(array_stride) + " bytes" +
                              (count_field_name.empty() ? "" : ", counted by " + count_field_name);
        builder.fields().push_back(std::move(array_field));
    }

    // 4. Variable-size section after the array.  When every sample has the same
    //    footer length the footer can be segmented like a normal record;
    //    otherwise it is a genuine variable-length trailer and stays opaque.
    if (array.has_value() && array_end < reference_size) {
        std::vector<std::uint64_t> footer_lengths(builder.views().size(), 0);
        bool readable = true;
        for (std::size_t s = 0; s < builder.views().size(); ++s) {
            const auto count = builder.views()[s].read_uint(array->length_offset,
                                                            array->length_width, options.endian);
            if (!count) {
                readable = false;
                break;
            }
            const std::uint64_t records = count.value();
            if (records > (builder.views()[s].size() - data_offset) / array_stride) {
                readable = false;
                break;
            }
            const std::uint64_t sample_array_end = data_offset + records * array_stride;
            footer_lengths[s] = builder.views()[s].size() - sample_array_end;
        }
        bool consistent = readable;
        if (consistent) {
            for (const std::uint64_t footer : footer_lengths) {
                if (footer != footer_lengths[reference]) {
                    consistent = false;
                    break;
                }
            }
        }
        if (consistent && footer_lengths[reference] > 0) {
            const std::uint64_t footer_length = footer_lengths[reference];
            Region footer;
            footer.views = &builder.views();
            footer.base.resize(builder.views().size());
            for (std::size_t s = 0; s < builder.views().size(); ++s) {
                footer.base[s] = builder.views()[s].size() - footer_length;
            }
            footer.length = footer_length;
            std::map<std::uint64_t, TypeField> no_specials;
            builder.segment(footer, array_end, no_specials);
        } else {
            builder.emit_unknown(array_end, reference_size - array_end);
        }
    }

    builder.finalise(reference_size, min_size);

    // 5. Root node.
    std::vector<TypeField> fields = builder.fields();
    double weighted = 0.0;
    std::uint64_t structured = 0;
    for (const auto& field : fields) {
        if (!field.type) continue;
        if (field.type->is<core::UnknownNode>() || field.type->is<core::PaddingNode>()) continue;
        weighted += field.confidence * static_cast<double>(field.type->size);
        structured += field.type->size;
    }
    const double mean_confidence =
        structured == 0 ? 0.0 : weighted / static_cast<double>(structured);
    const double structured_ratio = reference_size == 0
                                        ? 0.0
                                        : static_cast<double>(structured) /
                                              static_cast<double>(reference_size);
    const double overall =
        std::clamp(0.25 + 0.50 * mean_confidence + 0.25 * structured_ratio, 0.0, 0.99);

    AlignmentOptions alignment_options;
    alignment_options.max_scan_bytes =
        std::min<std::uint64_t>(reference_size, options.field_scan_limit);
    AlignmentOracle oracle(builder.views()[reference], options.endian, alignment_options);
    const std::uint64_t detected_alignment =
        oracle.detect_alignment(0, std::min<std::uint64_t>(reference_size, options.field_scan_limit));

    auto root = TypeNode::structure(std::move(fields), "recovered", 0, reference_size, overall);
    if (auto* structure = root->get_if<core::StructNode>()) {
        structure->alignment = detected_alignment;
        structure->declared_size = reference_size;
    }
    result.root = std::move(root);
    result.confidence = overall;
    result.fields.reserve(result.root->get_if<core::StructNode>()->fields.size());
    for (const auto& field : result.root->get_if<core::StructNode>()->fields) {
        if (!field.type) continue;
        if (field.type->is<core::PaddingNode>()) continue;
        result.fields.push_back(to_inferred_field(field));
    }
    // Cross-link the recovered count field with the array it governs.
    if (array.has_value()) {
        for (auto& inferred : result.fields) {
            if (inferred.offset != array->length_offset) continue;
            inferred.array_element_size = array_stride;
            inferred.count_field_offset = array->length_offset;
            inferred.element_count = reference_count;
        }
    }
    for (auto& evidence : builder.evidence()) result.evidence.push_back(std::move(evidence));
    if (detected_alignment > 1) {
        Evidence evidence;
        evidence.kind = EvidenceKind::alignment;
        evidence.offset = 0;
        evidence.confidence = 0.8;
        evidence.description = "struct alignment " + std::to_string(detected_alignment) +
                               " inferred from field offsets";
        result.evidence.push_back(std::move(evidence));
    }
    return result;
}

}  // namespace

DiffEngine::DiffEngine(DiffOptions options) : options_(options) {
    if (options_.max_fields == 0) options_.max_fields = 1;
    if (options_.field_scan_limit == 0) options_.field_scan_limit = 1;
    if (options_.min_array_elements == 0) options_.min_array_elements = 1;
    if (options_.max_nested_element_size == 0) options_.max_nested_element_size = 1;
    if (options_.confidence_threshold < 0.0) options_.confidence_threshold = 0.0;
    if (options_.confidence_threshold > 1.0) options_.confidence_threshold = 1.0;
}

core::Result<InferenceResult> DiffEngine::infer(std::span<const Sample> samples) const {
    if (samples.empty()) {
        return core::make_error(core::ErrorCode::invalid_argument,
                                "differential inference requires at least one sample");
    }
    for (std::size_t i = 0; i < samples.size(); ++i) {
        if (!samples[i].view.valid()) {
            return core::make_error(core::ErrorCode::invalid_argument,
                                    "sample " + std::to_string(i) + " is not a valid binary view",
                                    samples[i].name);
        }
        if (samples[i].view.empty()) {
            return core::make_error(core::ErrorCode::invalid_argument,
                                    "sample " + std::to_string(i) + " is empty", samples[i].name);
        }
        if (samples[i].view.size() < kMinSampleSize) {
            return core::make_error(core::ErrorCode::invalid_argument,
                                    "sample " + std::to_string(i) + " is too short (" +
                                        std::to_string(samples[i].view.size()) +
                                        " bytes; at least " + std::to_string(kMinSampleSize) +
                                        " required)",
                                    samples[i].name);
        }
    }

    if (samples.size() == 1) {
        return infer_single_sample(samples.front(), options_);
    }
    return infer_multi_sample(samples, options_);
}

core::Result<InferenceResult> DiffEngine::infer(std::span<const core::BinaryView> views) const {
    std::vector<Sample> samples;
    samples.reserve(views.size());
    for (const auto& view : views) {
        Sample sample;
        sample.view = view;
        sample.name = view.valid() ? view.name() : std::string("<invalid>");
        samples.push_back(std::move(sample));
    }
    return infer(std::span<const Sample>(samples));
}

}  // namespace typemorph::infer

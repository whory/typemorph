// TypeMorph - Rust tagged-union and niche-layout reconstruction.
//
// Two independent heuristics live here:
//
//  1. Tagged unions / enums with payload: an array (or struct field sequence)
//     stores a small discriminant at a fixed stride, followed by a payload
//     window.  We detect runs of plausibly-small integers repeated at a fixed
//     stride, require at least `min_repeated_tags` occurrences, a dense
//     discriminant domain (so random data does not explode into candidates) and
//     then describe the payload window and the observed variants.
//
//  2. Niche layouts: Rust optimises `Option<&T>`, `Option<NonZeroU32>`,
//     `Option<EnumWithoutAllValues>` and alignment-tagged pointers by encoding
//     the extra variants in an invalid bit pattern of the payload field.  We
//     look for runs of pointer words mixing null and valid pointers
//     (nullable-pointer niche), runs of small integers mixing zero and non-zero
//     values (non-zero-integer niche), dense small-integer runs leaving unused
//     values (invalid-enum-value niche) and pointer words whose low alignment
//     bits carry a tag while the aligned base is a valid pointer
//     (pointer-alignment-hole niche).
//
// The scan is section aware when an image is supplied: executable/code sections
// are excluded, as are BSS-style zero-fill ranges that have no file bytes.  All
// reads are bounds checked and the amount of scanned data is capped.

#include "typemorph/derust/enum_reconstruct.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace typemorph::derust {
namespace {

struct Range {
    std::size_t offset = 0;
    std::size_t length = 0;
    const core::Section* section = nullptr;
};

[[nodiscard]] bool is_data_section(const core::Section& section) noexcept {
    if (section.file_size == 0) return false;
    if (core::has_flag(section.flags, core::SectionFlag::zero_fill)) return false;
    if (section.executable() || core::has_flag(section.flags, core::SectionFlag::code)) return false;
    return core::has_flag(section.flags, core::SectionFlag::data) ||
           core::has_flag(section.flags, core::SectionFlag::read_only) ||
           core::has_flag(section.flags, core::SectionFlag::writable);
}

[[nodiscard]] std::vector<Range> collect_ranges(const core::BinaryView& view,
                                                const core::ExecutableImage* image,
                                                std::uint64_t max_scan_bytes) {
    std::vector<Range> ranges;
    if (!view.valid() || view.size() == 0 || max_scan_bytes == 0) return ranges;
    const std::size_t view_size = view.size();

    if (image != nullptr && image->view().valid() && !image->sections().empty()) {
        std::uint64_t budget = max_scan_bytes;
        for (const auto& section : image->sections()) {
            if (budget == 0) break;
            if (!is_data_section(section)) continue;
            if (section.file_offset >= view_size) continue;
            const std::size_t available = std::min<std::size_t>(
                static_cast<std::size_t>(section.file_size),
                view_size - static_cast<std::size_t>(section.file_offset));
            if (available == 0) continue;
            const std::size_t take = static_cast<std::size_t>(
                std::min<std::uint64_t>(static_cast<std::uint64_t>(available), budget));
            if (take == 0) continue;
            ranges.push_back(Range{static_cast<std::size_t>(section.file_offset), take, &section});
            budget -= static_cast<std::uint64_t>(take);
        }
    } else {
        const std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(static_cast<std::uint64_t>(view_size), max_scan_bytes));
        ranges.push_back(Range{0, take, nullptr});
    }

    std::sort(ranges.begin(), ranges.end(),
              [](const Range& a, const Range& b) { return a.offset < b.offset; });
    return ranges;
}

[[nodiscard]] std::uint64_t load_unsigned(const std::uint8_t* data, std::size_t width,
                                          core::ByteOrder order) noexcept {
    std::uint64_t value = 0;
    if (order == core::ByteOrder::little) {
        for (std::size_t i = 0; i < width; ++i) {
            value |= static_cast<std::uint64_t>(data[i]) << static_cast<unsigned>(i * 8U);
        }
    } else {
        for (std::size_t i = 0; i < width; ++i) {
            value = (value << 8U) | static_cast<std::uint64_t>(data[i]);
        }
    }
    return value;
}

[[nodiscard]] std::size_t pointer_width(const core::ExecutableImage* image) noexcept {
    return image != nullptr && image->bits() == 32 ? 4U : 8U;
}

[[nodiscard]] std::uint64_t full_mask(std::size_t width) noexcept {
    if (width >= 8) return ~std::uint64_t{0};
    return (std::uint64_t{1} << (width * 8U)) - 1U;
}

[[nodiscard]] std::uint64_t bit_mask_for(std::uint64_t maximum) noexcept {
    if (maximum == 0) return 0;
    std::uint64_t mask = 0;
    while (mask < maximum) mask = (mask << 1U) | 1U;
    return mask;
}

[[nodiscard]] bool plausible_pointer(const core::ExecutableImage* image, std::uint64_t value,
                                     std::size_t width) noexcept {
    if (value == 0) return false;
    if (value % width != 0) return false;
    if (image != nullptr && image->view().valid()) {
        return image->contains_address(value);
    }
    // Without an image fall back to a conservative user-space range heuristic.
    return value >= 0x1000U && (width == 4 || (value >> 48U) == 0);
}

// A word that is either a valid pointer or an alignment-tagged pointer (the
// aligned base is a valid pointer and the low bits carry a tag).  Such words
// must not be mistaken for small integers by the niche scan.
[[nodiscard]] bool pointer_like(const core::ExecutableImage* image, std::uint64_t value,
                                std::size_t width) noexcept {
    if (value == 0) return false;
    if (plausible_pointer(image, value, width)) return true;
    if (width < 2) return false;
    const std::uint64_t aligned = value & ~static_cast<std::uint64_t>(width - 1U);
    return aligned != 0 && aligned != value && plausible_pointer(image, aligned, width);
}

[[nodiscard]] bool is_read_only_data(const Range& range) noexcept {
    return range.section != nullptr && range.section->read_only() &&
           !range.section->writable();
}

[[nodiscard]] std::string section_name(const Range& range) {
    if (range.section == nullptr || range.section->name.empty()) return "unnamed data";
    return range.section->name;
}

// ---------------------------------------------------------------------------
// Tagged unions
// ---------------------------------------------------------------------------

constexpr std::size_t kMaxRunTags = 4096;

[[nodiscard]] bool dense_discriminants(std::uint64_t maximum, std::size_t distinct) noexcept {
    if (distinct == 0) return false;
    // Rust discriminants normally start at 0 and are (nearly) consecutive; a
    // wide gap means the "tags" are more likely ordinary small-integer data.
    return maximum <= static_cast<std::uint64_t>(distinct) * 4U + 4U;
}

void evaluate_tag_run(const Range& range, const std::uint8_t* data, std::size_t start,
                      std::size_t stride, std::size_t tag_width,
                      const std::vector<std::uint64_t>& tags,
                      std::vector<TaggedUnionCandidate>& out) {
    if (tags.size() < 2) return;
    std::vector<std::uint64_t> sorted = tags;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
    const std::size_t distinct = sorted.size();
    const std::uint64_t maximum = sorted.back();
    if (distinct < 2 || !dense_discriminants(maximum, distinct)) return;

    // Rust places the discriminant first and aligns the payload behind it, so
    // with a payload window there is normally at least one zero padding byte
    // immediately after the tag.  Random bytes almost never satisfy that for a
    // whole run, which removes most false positives on non-enum data.
    bool has_tag_padding = false;
    if (stride >= tag_width + 2U) {
        std::size_t checked = std::min<std::size_t>(tags.size(), 8);
        std::size_t padded = 0;
        for (std::size_t k = 0; k < checked; ++k) {
            const std::size_t position = start + k * stride;
            if (position + tag_width >= range.length) {
                checked = k;
                break;
            }
            if (data[position + tag_width] == 0) ++padded;
        }
        if (checked == 0 || padded * 4U < checked * 3U) return;
        has_tag_padding = true;
    }

    const std::size_t payload_size = stride - tag_width;
    TaggedUnionCandidate candidate;
    candidate.offset = range.offset + start;
    candidate.tag_width = static_cast<std::uint8_t>(tag_width);
    candidate.payload_offset = tag_width;
    candidate.variants.reserve(std::min<std::size_t>(distinct, 64));
    for (const std::uint64_t tag : sorted) {
        if (candidate.variants.size() >= 64) break;
        TaggedUnionVariant variant;
        variant.tag = tag;
        variant.payload_offset = tag_width;
        variant.payload_size = payload_size;
        variant.hint = "payload window of " + std::to_string(payload_size) + " byte(s)";
        candidate.variants.push_back(std::move(variant));
    }

    double confidence = 0.30;
    confidence += 0.02 * static_cast<double>(std::min<std::size_t>(tags.size(), 10));
    if (maximum + 1U <= static_cast<std::uint64_t>(distinct) * 2U) {
        confidence += 0.15;
    } else if (dense_discriminants(maximum, distinct)) {
        confidence += 0.08;
    }
    if (tags.size() >= 4) confidence += 0.05;
    if (tag_width == 1 || tag_width == 4) confidence += 0.10;
    else confidence += 0.02;
    if (start % stride == 0) confidence += 0.05;
    if (is_read_only_data(range)) confidence += 0.10;
    if (candidate.tag_width > 1 &&
        maximum <= 0xFFU) {
        confidence -= 0.10;  // a narrower tag width would explain the same data
    }
    candidate.confidence = std::clamp(confidence, 0.05, 0.99);

    std::string rationale;
    rationale.reserve(160);
    rationale += std::to_string(tags.size()) + " repeated tag positions at stride " +
                 std::to_string(stride) + " in " + section_name(range);
    rationale += "; " + std::to_string(distinct) + " distinct discriminant(s) in [0.." +
                 std::to_string(maximum) + "]";
    rationale += "; payload window " + std::to_string(payload_size) + " byte(s)";
    if (has_tag_padding) rationale += "; zero padding behind the discriminant";
    if (is_read_only_data(range)) rationale += "; read-only data";
    candidate.rationale = std::move(rationale);
    out.push_back(std::move(candidate));
}

// ---------------------------------------------------------------------------

}  // namespace

EnumReconstructor::EnumReconstructor(EnumReconstructOptions options) : options_(options) {}

std::vector<TaggedUnionCandidate> EnumReconstructor::scan_tagged_unions(
    const core::BinaryView& view, const core::ExecutableImage* image) const {
    std::vector<TaggedUnionCandidate> candidates;
    if (!view.valid() || view.size() == 0) return candidates;
    const auto ranges = collect_ranges(view, image, options_.max_scan_bytes);
    if (ranges.empty()) return candidates;

    constexpr std::size_t strides[] = {2, 4, 8, 12, 16, 24, 32, 48, 64};
    const std::size_t minimum_tags = std::max<std::size_t>(options_.min_repeated_tags, 2);
    const core::ByteOrder order = image != nullptr ? image->endian() : core::ByteOrder::little;

    for (const auto& range : ranges) {
        if (range.length < 4) continue;
        const std::uint8_t* const data = view.data() + range.offset;
        for (const std::uint8_t width : {std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{4}}) {
            if (width > options_.max_tag_width) continue;
            const std::uint64_t cap = std::min<std::uint64_t>(
                options_.max_discriminant,
                width == 1 ? 63U : (width == 2 ? 1023U : 0xFFFFU));
            const std::size_t positions = range.length / width;
            if (positions < 2) continue;
            std::vector<std::uint8_t> valid(positions, 0);
            for (std::size_t i = 0; i < positions; ++i) {
                const std::size_t offset = i * width;
                if (offset + width > range.length) break;
                valid[i] = load_unsigned(data + offset, width, order) <= cap ? 1U : 0U;
            }
            for (const std::size_t stride : strides) {
                if (stride < width * 2U || stride % width != 0) continue;
                const std::size_t steps = stride / width;
                for (std::size_t i = 0; i < positions; ++i) {
                    if (valid[i] == 0) continue;
                    if (i >= steps && valid[i - steps] != 0) continue;  // not a run start
                    std::vector<std::uint64_t> tags;
                    tags.reserve(std::min<std::size_t>(positions / steps + 1, kMaxRunTags));
                    for (std::size_t k = i; k < positions; k += steps) {
                        if (valid[k] == 0) break;
                        if (tags.size() >= kMaxRunTags) break;
                        tags.push_back(load_unsigned(data + k * width, width, order));
                    }
                    if (tags.size() < minimum_tags) continue;
                    evaluate_tag_run(range, data, i * width, stride, width, tags, candidates);
                    if (candidates.size() >= 4096) break;
                }
                if (candidates.size() >= 4096) break;
            }
            if (candidates.size() >= 4096) break;
        }
        if (candidates.size() >= 4096) break;
    }

    // Prefer the most confident non-overlapping explanation.  The same byte
    // pattern can be described with different width/stride guesses; keeping the
    // best one avoids flooding the caller with duplicates.
    std::sort(candidates.begin(), candidates.end(),
              [](const TaggedUnionCandidate& a, const TaggedUnionCandidate& b) {
                  if (a.confidence != b.confidence) return a.confidence > b.confidence;
                  if (a.tag_width != b.tag_width) return a.tag_width < b.tag_width;
                  return a.offset < b.offset;
              });
    std::vector<std::pair<std::uint64_t, std::uint64_t>> occupied;
    std::vector<TaggedUnionCandidate> kept;
    for (auto& candidate : candidates) {
        const auto extent = static_cast<std::uint64_t>(
            std::max<std::size_t>(candidate.variants.size(), 1U) * 4U);
        const std::uint64_t begin = candidate.offset;
        const std::uint64_t end = candidate.offset + extent;
        bool overlaps = false;
        for (const auto& [other_begin, other_end] : occupied) {
            if (begin < other_end && other_begin < end) {
                overlaps = true;
                break;
            }
        }
        if (overlaps) continue;
        occupied.emplace_back(begin, end);
        kept.push_back(std::move(candidate));
    }
    std::sort(kept.begin(), kept.end(), [](const TaggedUnionCandidate& a,
                                           const TaggedUnionCandidate& b) {
        return a.offset < b.offset;
    });
    return kept;
}

std::vector<NicheCandidate> EnumReconstructor::scan_niches(const core::BinaryView& view,
                                                           const core::ExecutableImage* image) const {
    std::vector<NicheCandidate> candidates;
    if (!view.valid() || view.size() == 0) return candidates;
    const auto ranges = collect_ranges(view, image, options_.max_scan_bytes);
    if (ranges.empty()) return candidates;

    const std::size_t pointer = pointer_width(image);
    const core::ByteOrder order = image != nullptr ? image->endian() : core::ByteOrder::little;
    const std::size_t minimum_run = std::max<std::size_t>(options_.min_repeated_tags, 2);

    for (const auto& range : ranges) {
        if (range.length == 0) continue;
        const std::uint8_t* const data = view.data() + range.offset;

        // ---- pointer niches -------------------------------------------------
        const std::size_t pointer_positions = range.length / pointer;
        std::vector<std::uint64_t> words(pointer_positions);
        for (std::size_t i = 0; i < pointer_positions; ++i) {
            words[i] = load_unsigned(data + i * pointer, pointer, order);
        }

        // nullable_pointer: runs that mix null and valid pointers.
        std::size_t run_start = 0;
        std::size_t run_count = 0;
        std::size_t nulls = 0;
        std::size_t valid_pointers = 0;
        const auto flush_nullable = [&]() {
            if (run_count >= minimum_run && nulls >= 1 && valid_pointers >= 1) {
                NicheCandidate candidate;
                candidate.offset = range.offset + run_start * pointer;
                candidate.width = static_cast<std::uint8_t>(pointer);
                candidate.kind = NicheKind::nullable_pointer;
                candidate.non_niche_bit_mask = full_mask(pointer);
                double confidence = 0.45;
                confidence += 0.05 * static_cast<double>(std::min<std::size_t>(run_count, 6));
                if (static_cast<double>(nulls) / static_cast<double>(run_count) <= 0.5) {
                    confidence += 0.10;  // niches are the minority pattern
                }
                if (valid_pointers >= 2) confidence += 0.05;
                if (is_read_only_data(range)) confidence += 0.05;
                candidate.confidence = std::clamp(confidence, 0.05, 0.99);
                candidate.rationale =
                    std::to_string(nulls) + " null word(s) and " +
                    std::to_string(valid_pointers) + " valid pointer(s) in " +
                    std::to_string(run_count) + " consecutive " + std::to_string(pointer) +
                    "-byte words; null encodes the absent variant in " + section_name(range);
                candidates.push_back(std::move(candidate));
            }
            run_count = 0;
            nulls = 0;
            valid_pointers = 0;
        };
        for (std::size_t i = 0; i < pointer_positions; ++i) {
            const std::uint64_t word = words[i];
            const bool is_null = word == 0;
            const bool is_pointer = plausible_pointer(image, word, pointer);
            if (!is_null && !is_pointer) {
                flush_nullable();
                continue;
            }
            if (run_count == 0) run_start = i;
            ++run_count;
            if (is_null) {
                ++nulls;
            } else {
                ++valid_pointers;
            }
        }
        flush_nullable();

        // pointer_alignment_hole: low alignment bits hold a tag while the
        // aligned base is a valid pointer.
        std::size_t hole_start = 0;
        std::size_t hole_count = 0;
        const auto flush_holes = [&]() {
            if (hole_count >= minimum_run) {
                NicheCandidate candidate;
                candidate.offset = range.offset + hole_start * pointer;
                candidate.width = static_cast<std::uint8_t>(pointer);
                candidate.kind = NicheKind::pointer_alignment_hole;
                candidate.non_niche_bit_mask = ~static_cast<std::uint64_t>(pointer - 1U);
                double confidence = 0.40;
                confidence += 0.06 * static_cast<double>(std::min<std::size_t>(hole_count, 6));
                if (is_read_only_data(range) || (range.section != nullptr && range.section->writable())) {
                    confidence += 0.05;
                }
                candidate.confidence = std::clamp(confidence, 0.05, 0.99);
                candidate.rationale =
                    std::to_string(hole_count) + " pointer-sized word(s) whose low " +
                    std::to_string(pointer) + "-alignment bits carry a tag while the aligned base "
                    "is a valid pointer; unused alignment patterns encode extra variants in " +
                    section_name(range);
                candidates.push_back(std::move(candidate));
            }
            hole_count = 0;
        };
        for (std::size_t i = 0; i < pointer_positions; ++i) {
            const std::uint64_t word = words[i];
            const bool aligned_base = word != 0 && word % pointer != 0 &&
                                      plausible_pointer(image, word & ~(pointer - 1U), pointer);
            if (aligned_base) {
                if (hole_count == 0) hole_start = i;
                ++hole_count;
            } else {
                flush_holes();
            }
        }
        flush_holes();

        // ---- small-integer niches -------------------------------------------
        for (const std::size_t width : {static_cast<std::size_t>(1), static_cast<std::size_t>(2),
                                        static_cast<std::size_t>(4), static_cast<std::size_t>(8)}) {
            const std::uint64_t cap =
                std::min<std::uint64_t>(options_.max_discriminant, 0xFFFFU);
            const std::size_t positions = range.length / width;
            if (positions < minimum_run) continue;
            std::vector<std::uint64_t> values(positions);
            std::vector<std::uint8_t> valid(positions, 0);
            for (std::size_t i = 0; i < positions; ++i) {
                values[i] = load_unsigned(data + i * width, width, order);
                // Valid pointers (and alignment-tagged pointers) are not small
                // integers, even when their numeric value happens to be small
                // in a synthetic image with low virtual addresses.  A narrow
                // integer sample inside a pointer word is pointer data, not a
                // niche field.
                bool pointer_word = pointer_like(image, values[i], width);
                if (!pointer_word && width <= pointer) {
                    const std::size_t word_index = (i * width) / pointer;
                    if (word_index < words.size()) {
                        pointer_word = pointer_like(image, words[word_index], pointer);
                    }
                }
                valid[i] = (values[i] <= cap && !pointer_word) ? 1U : 0U;
            }
            // A run is a maximal sequence of small values; there is only one
            // stride for this pass (the field width itself).
            for (std::size_t i = 0; i < positions; ++i) {
                if (valid[i] == 0) continue;
                if (i > 0 && valid[i - 1] != 0) continue;
                std::size_t count = 0;
                std::size_t zero_values = 0;
                for (std::size_t k = i; k < positions && valid[k] != 0; ++k) {
                    ++count;
                    if (values[k] == 0) ++zero_values;
                }
                if (count < minimum_run) continue;
                // Only inspect the run, not the remainder of the range.
                std::vector<std::uint64_t> run_values(values.begin() +
                                                          static_cast<std::ptrdiff_t>(i),
                                                      values.begin() +
                                                          static_cast<std::ptrdiff_t>(i + count));
                std::sort(run_values.begin(), run_values.end());
                run_values.erase(std::unique(run_values.begin(), run_values.end()),
                                 run_values.end());
                const std::size_t non_zero = run_values.size() - (zero_values != 0 ? 1U : 0U);
                const std::uint64_t maximum = run_values.empty() ? 0 : run_values.back();
                // An exactly dense set starting at zero looks like a normal
                // discriminant domain (with unused values available as a
                // niche), not like a non-zero integer type: prefer
                // invalid_enum_value over non_zero_integer for such runs.
                const bool dense_from_zero =
                    !run_values.empty() && run_values.front() == 0 && maximum + 1U == run_values.size();

                // non_zero_integer: the field is normally non-zero; zero is the
                // invalid pattern that encodes the absent variant.
                if (!dense_from_zero && zero_values >= 1 && non_zero >= 1 &&
                    run_values.size() >= 2) {
                    NicheCandidate candidate;
                    candidate.offset = range.offset + i * width;
                    candidate.width = static_cast<std::uint8_t>(width);
                    candidate.kind = NicheKind::non_zero_integer;
                    candidate.non_niche_bit_mask = full_mask(width);
                    double confidence = 0.40;
                    if (width == pointer) confidence += 0.08;
                    if ((range.offset + i * width) % pointer == 0) confidence += 0.04;
                    confidence += 0.05 * static_cast<double>(std::min<std::size_t>(count, 6));
                    if (non_zero >= 3) confidence += 0.05;
                    const double fraction = static_cast<double>(zero_values) / static_cast<double>(count);
                    if (fraction <= 0.5) confidence += 0.05;
                    candidate.confidence = std::clamp(confidence, 0.05, 0.99);
                    candidate.rationale =
                        std::to_string(width) + "-byte integer field with " +
                        std::to_string(zero_values) + " zero value(s) among " +
                        std::to_string(count) + " small value(s) (max " +
                        std::to_string(maximum) + "); zero encodes the absent variant";
                    candidates.push_back(std::move(candidate));
                }

                // invalid_enum_value: dense small value set that does not use
                // the whole encoding space, so unused values can encode variants.
                if (run_values.size() >= 2 && dense_discriminants(maximum, run_values.size()) &&
                    maximum < full_mask(width)) {
                    NicheCandidate candidate;
                    candidate.offset = range.offset + i * width;
                    candidate.width = static_cast<std::uint8_t>(width);
                    candidate.kind = NicheKind::invalid_enum_value;
                    candidate.non_niche_bit_mask = bit_mask_for(maximum);
                    double confidence = 0.35;
                    if (maximum + 1U == run_values.size()) confidence += 0.15;
                    if (dense_from_zero) confidence += 0.05;
                    confidence += 0.04 * static_cast<double>(std::min<std::size_t>(count, 6));
                    if (width == 1 || width == 4) confidence += 0.05;
                    candidate.confidence = std::clamp(confidence, 0.05, 0.99);
                    candidate.rationale =
                        std::to_string(width) + "-byte field observed with " +
                        std::to_string(run_values.size()) + " dense value(s) in [0.." +
                        std::to_string(maximum) + "]; unused encodings can act as a niche";
                    candidates.push_back(std::move(candidate));
                }
                i += count - 1;  // do not rescan the run
            }
        }
    }

    // Niche candidates can overlap across widths; keep the most confident
    // explanation of each byte region.
    std::sort(candidates.begin(), candidates.end(),
              [](const NicheCandidate& a, const NicheCandidate& b) {
                  if (a.confidence != b.confidence) return a.confidence > b.confidence;
                  if (a.width != b.width) return a.width > b.width;
                  return a.offset < b.offset;
              });
    std::vector<NicheCandidate> kept;
    for (auto& candidate : candidates) {
        bool overlaps = false;
        for (const auto& other : kept) {
            const std::uint64_t begin = candidate.offset;
            const std::uint64_t end = candidate.offset + candidate.width;
            const std::uint64_t other_begin = other.offset;
            const std::uint64_t other_end = other.offset + other.width;
            if (begin < other_end && other_begin < end) {
                overlaps = true;
                break;
            }
        }
        if (overlaps) continue;
        kept.push_back(std::move(candidate));
    }
    std::sort(kept.begin(), kept.end(),
              [](const NicheCandidate& a, const NicheCandidate& b) { return a.offset < b.offset; });
    return kept;
}

}  // namespace typemorph::derust

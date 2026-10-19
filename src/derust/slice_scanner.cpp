// TypeMorph - Rust fat pointer (&str / &[T]) discovery in image data sections.
//
// A Rust ``&str`` is a fat pointer: a (data pointer, byte length) pair.  In a
// linked image such pairs live in data sections (static string literals and
// slice constants).  This scanner sweeps those sections for adjacent
// pointer-sized words, translates the pointer back through the image's virtual
// layout, validates the payload as UTF-8 and assigns a confidence derived from
// alignment, section permissions and text plausibility.
//
// Everything is bounded and hostile-input safe: every read is bounds checked,
// lengths are clamped against the image size, pointer arithmetic cannot wrap
// and the total amount of copied payload is capped.

#include "typemorph/derust/slice_scanner.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace typemorph::derust {
namespace {

// Upper bound on the number of payload bytes copied into RustString::value
// across a single scan.  A hostile image can otherwise make the scanner copy
// gigabytes by pairing a valid pointer with many distinct lengths.
constexpr std::size_t kCaptureBudget = 64U << 20U;

[[nodiscard]] std::size_t pointer_width(const core::ExecutableImage& image) noexcept {
    return image.bits() == 32 ? 4U : 8U;
}

[[nodiscard]] std::uint64_t load_word(const std::uint8_t* data, std::size_t width,
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

[[nodiscard]] bool is_zero_fill(const core::Section& section) noexcept {
    return core::has_flag(section.flags, core::SectionFlag::zero_fill);
}

[[nodiscard]] bool is_executable(const core::Section& section) noexcept {
    return section.executable() || core::has_flag(section.flags, core::SectionFlag::code);
}

// Sections whose file bytes can hold static data: read-only data, writable data
// and relro-style sections.  Zero-fill (BSS) sections have no file bytes.
[[nodiscard]] bool is_data_section(const core::Section& section) noexcept {
    if (section.file_size == 0 || is_zero_fill(section) || is_executable(section)) return false;
    return core::has_flag(section.flags, core::SectionFlag::data) ||
           core::has_flag(section.flags, core::SectionFlag::read_only) ||
           core::has_flag(section.flags, core::SectionFlag::writable);
}

[[nodiscard]] bool is_printable(unsigned char c) noexcept {
    return (c >= 0x20U && c <= 0x7EU) || c == '\t' || c == '\n' || c == '\r';
}

[[nodiscard]] bool looks_like_text(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) return false;
    std::size_t printable = 0;
    for (const std::uint8_t byte : bytes) {
        if (is_printable(byte)) ++printable;
    }
    return printable * 4U >= bytes.size() * 3U;
}

}  // namespace

SliceScanner::SliceScanner(SliceScannerOptions options) : options_(options) {}

bool SliceScanner::valid_utf8(std::span<const std::uint8_t> bytes) noexcept {
    std::size_t i = 0;
    while (i < bytes.size()) {
        const auto lead = static_cast<unsigned>(bytes[i]);
        std::size_t extra = 0;
        std::uint32_t code_point = 0;
        if (lead < 0x80U) {
            ++i;
            continue;
        }
        if ((lead & 0xE0U) == 0xC0U) {
            extra = 1;
            code_point = lead & 0x1FU;
        } else if ((lead & 0xF0U) == 0xE0U) {
            extra = 2;
            code_point = lead & 0x0FU;
        } else if ((lead & 0xF8U) == 0xF0U) {
            extra = 3;
            code_point = lead & 0x07U;
        } else {
            return false;
        }
        if (i + extra >= bytes.size()) return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto continuation = static_cast<unsigned>(bytes[i + k]);
            if ((continuation & 0xC0U) != 0x80U) return false;
            code_point = (code_point << 6U) | (continuation & 0x3FU);
        }
        const std::uint32_t minimum = extra == 1 ? 0x80U : (extra == 2 ? 0x800U : 0x10000U);
        if (code_point < minimum || code_point > 0x10FFFFU) return false;
        if (code_point >= 0xD800U && code_point <= 0xDFFFU) return false;
        i += extra + 1;
    }
    return true;
}

core::Result<std::vector<RustString>> SliceScanner::scan(const core::ExecutableImage& image) const {
    std::vector<RustString> results;
    if (options_.max_results == 0) return results;
    if (!image.view().valid() || image.view().size() == 0) return results;
    if (image.sections().empty()) return results;

    const std::size_t width = pointer_width(image);
    const std::uint64_t pair_width = static_cast<std::uint64_t>(width) * 2U;
    if (pair_width > image.view().size()) return results;

    const core::ByteOrder order = image.endian();
    const std::uint64_t minimum_length =
        options_.allow_empty ? 0U : std::max<std::uint64_t>(options_.min_length, 1U);
    const std::uint64_t maximum_length = std::max<std::uint64_t>(options_.max_length, minimum_length);
    std::size_t captured = 0;

    for (const auto& section : image.sections()) {
        if (results.size() >= options_.max_results) break;
        if (!is_data_section(section)) continue;
        if (!options_.scan_writable_sections && section.writable()) continue;
        const auto section_bytes = image.section_bytes(section);
        if (!section_bytes) continue;
        const std::span<const std::uint8_t> bytes = section_bytes.value();
        if (bytes.size() < pair_width) continue;
        const std::size_t last_offset = bytes.size() - static_cast<std::size_t>(pair_width);

        for (std::size_t offset = 0; offset <= last_offset; ++offset) {
            if (results.size() >= options_.max_results || captured >= kCaptureBudget) break;
            const std::uint8_t* const words = bytes.data() + offset;
            const std::uint64_t data_address = load_word(words, width, order);
            const std::uint64_t length = load_word(words + width, width, order);
            if (data_address == 0) continue;
            if (length < minimum_length || length > maximum_length) continue;

            const auto data_offset = image.va_to_offset(data_address, length);
            if (!data_offset) continue;
            const auto data_view = image.view().slice(data_offset.value(), length);
            if (!data_view) continue;
            const std::span<const std::uint8_t> payload = data_view.value();
            if (options_.require_utf8 && !valid_utf8(payload)) continue;

            // Guard the total amount of copied bytes against hostile inputs.
            if (payload.size() > kCaptureBudget / 2U) continue;
            if (captured + payload.size() > kCaptureBudget) continue;

            RustString entry;
            entry.pair_file_offset = section.file_offset + offset;
            entry.pair_address = section.virtual_address + offset;
            entry.data_address = data_address;
            entry.data_file_offset = data_offset.value();
            entry.length = length;
            entry.value.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
            captured += payload.size();

            // Confidence: base plausibility plus independent corroborating
            // signals.  The scanner is a heuristic, so nothing is ever 1.0.
            double confidence = 0.5;
            if (offset % width == 0) confidence += 0.10;
            if (entry.pair_address % width == 0) confidence += 0.05;
            if (section.read_only() && !section.writable()) confidence += 0.10;
            if (data_address % 4U == 0) confidence += 0.05;
            if (length >= 4) confidence += 0.05;
            if (payload.empty()) {
                confidence = 0.60;  // an empty slice is only plausible when allowed
            } else if (looks_like_text(payload)) {
                confidence += 0.10;
            } else {
                confidence -= 0.10;
            }
            entry.confidence = std::clamp(confidence, 0.05, 0.99);
            results.push_back(std::move(entry));
        }
        if (captured >= kCaptureBudget) break;
    }

    // Deduplicate overlapping results:
    //  * identical (data address, length) pairs are one logical slice, keep the
    //    highest-confidence instance,
    //  * all other entries starting at the same data address are sub-slices of
    //    the range already reported for that address, keep the best instance.
    std::sort(results.begin(), results.end(), [](const RustString& a, const RustString& b) {
        if (a.data_address != b.data_address) return a.data_address < b.data_address;
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        if (a.length != b.length) return a.length > b.length;
        return a.pair_address < b.pair_address;
    });

    std::vector<RustString> deduplicated;
    deduplicated.reserve(results.size());
    for (auto& entry : results) {
        if (!deduplicated.empty() &&
            deduplicated.back().data_address == entry.data_address &&
            deduplicated.back().length == entry.length) {
            continue;
        }
        if (!deduplicated.empty() && deduplicated.back().data_address == entry.data_address) {
            continue;  // shorter sub-slice of a range already kept
        }
        deduplicated.push_back(std::move(entry));
    }

    std::sort(deduplicated.begin(), deduplicated.end(),
              [](const RustString& a, const RustString& b) {
                  if (a.pair_address != b.pair_address) return a.pair_address < b.pair_address;
                  return a.data_address < b.data_address;
              });
    return deduplicated;
}

}  // namespace typemorph::derust

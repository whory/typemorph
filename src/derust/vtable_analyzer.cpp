// TypeMorph - Rust trait object VTable layout resolver.
//
// Rust trait object vtables are arrays in data sections with the layout
//   [drop_in_place, object_size, object_align, method_0, method_1, ...]
// where drop_in_place and every method pointer target executable code and
// object_size / object_align are small, sane integers (align is a power of two
// and size is a multiple of align).  We scan pointer-aligned words in
// non-executable data sections, validate the header, follow the run of code
// pointers that forms the method table and correlate entries with symbols.
//
// The analyzer tolerates images with no vtables at all (returns an empty list),
// never reads past a section's file bytes and treats null drop functions as
// "plausible but only accepted in lenient mode" (Rust does emit null drop glue
// for types without a destructor).

#include "typemorph/derust/vtable_analyzer.hpp"

#include "typemorph/derust/demangle.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace typemorph::derust {
namespace {

// Sanity ceilings for the size/alignment header words.  Real Rust objects are
// far below these; a code pointer misread as a size overflows immediately.
constexpr std::uint64_t kMaxObjectSize = 1U << 24U;   // 16 MiB
constexpr std::uint64_t kMaxObjectAlign = 1U << 16U;  // 64 KiB
constexpr std::size_t kPreambleBytes = 4;

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

[[nodiscard]] bool is_power_of_two(std::uint64_t value) noexcept {
    return value != 0 && (value & (value - 1U)) == 0;
}

[[nodiscard]] bool is_pointer_section(const core::Section& section) noexcept {
    if (section.file_size == 0) return false;
    if (core::has_flag(section.flags, core::SectionFlag::zero_fill)) return false;
    if (section.executable() || core::has_flag(section.flags, core::SectionFlag::code)) return false;
    return core::has_flag(section.flags, core::SectionFlag::data) ||
           core::has_flag(section.flags, core::SectionFlag::read_only) ||
           core::has_flag(section.flags, core::SectionFlag::writable);
}

// Returns the most specific function symbol covering `address`, or nullptr.
// Exact address matches always win over enclosing ranges: adjacent functions in
// a vtable are often covered by the previous function's size, and correlating a
// method to its neighbour would be misleading.
[[nodiscard]] const core::Symbol* find_function_symbol(const core::ExecutableImage& image,
                                                       std::uint64_t address) noexcept {
    const core::Symbol* exact = nullptr;
    const core::Symbol* containing_function = nullptr;
    const core::Symbol* containing_any = nullptr;
    for (const auto& symbol : image.symbols()) {
        if (symbol.name.empty()) continue;
        if (symbol.address == address) {
            if (symbol.kind == core::SymbolKind::function) return &symbol;
            if (exact == nullptr) exact = &symbol;
            continue;
        }
        if (symbol.size == 0 || address <= symbol.address || address - symbol.address >= symbol.size) {
            continue;
        }
        if (symbol.kind == core::SymbolKind::function) {
            if (containing_function == nullptr ||
                symbol.size < containing_function->size) {
                containing_function = &symbol;
            }
        } else if (containing_any == nullptr) {
            containing_any = &symbol;
        }
    }
    if (exact != nullptr) return exact;
    if (containing_function != nullptr) return containing_function;
    return containing_any;
}

[[nodiscard]] std::string describe_symbol(const core::Symbol& symbol) {
    if (symbol.rust || looks_like_rust_symbol(symbol.name)) {
        return demangle_or_original(symbol.name);
    }
    return symbol.name;
}

}  // namespace

VTableAnalyzer::VTableAnalyzer(VTableOptions options) : options_(options) {}

bool VTableAnalyzer::looks_like_function_start(const core::ExecutableImage& image,
                                               std::uint64_t address) const {
    if (address == 0) return false;
    if (!image.is_executable_address(address)) return false;
    const auto offset = image.va_to_offset(address, kPreambleBytes);
    if (!offset) return false;
    const auto bytes = image.view().slice(offset.value(), kPreambleBytes);
    if (!bytes || bytes.value().size() < kPreambleBytes) return false;

    // Reject the usual non-code fills.  Pad bytes are 0x00, 0xCC (int3) or
    // 0xFF; a real function prologue is none of those.
    bool all_zero = true;
    bool all_break = true;
    bool all_ones = true;
    for (const std::uint8_t byte : bytes.value()) {
        if (byte != 0x00U) all_zero = false;
        if (byte != 0xCCU) all_break = false;
        if (byte != 0xFFU) all_ones = false;
    }
    return !(all_zero || all_break || all_ones);
}

core::Result<std::vector<VTableCandidate>> VTableAnalyzer::analyze(
    const core::ExecutableImage& image) const {
    std::vector<VTableCandidate> candidates;
    if (!image.view().valid() || image.sections().empty()) return candidates;

    const std::size_t width = pointer_width(image);
    if (width != 4 && width != 8) return candidates;
    const core::ByteOrder order = image.endian();
    const std::size_t header_words = 3;
    const std::uint64_t header_bytes = static_cast<std::uint64_t>(header_words * width);
    std::uint64_t scanned = 0;

    for (const auto& section : image.sections()) {
        if (scanned >= options_.max_scan_bytes) break;
        if (!is_pointer_section(section)) continue;
        const auto section_bytes = image.section_bytes(section);
        if (!section_bytes) continue;
        const std::span<const std::uint8_t> bytes = section_bytes.value();
        if (bytes.size() < header_bytes) continue;

        // Vtable entries are pointer aligned with respect to their virtual
        // address, not necessarily with respect to the file offset.
        std::size_t start = 0;
        while (start < width && (section.virtual_address + start) % width != 0) ++start;
        const std::size_t last = bytes.size() - static_cast<std::size_t>(header_bytes);

        for (std::size_t offset = start; offset <= last; offset += width) {
            if (scanned >= options_.max_scan_bytes) break;
            scanned += static_cast<std::uint64_t>(width);

            const std::uint8_t* const table = bytes.data() + offset;
            const std::uint64_t drop_in_place = load_word(table, width, order);
            const std::uint64_t object_size = load_word(table + width, width, order);
            const std::uint64_t object_align = load_word(table + 2U * width, width, order);

            // --- header validation ------------------------------------------
            bool drop_ok = true;
            if (drop_in_place == 0) {
                // Null drop glue only exists for types without a destructor.
                drop_ok = !options_.require_drop_function;
            } else if (image.is_executable_address(drop_in_place)) {
                drop_ok = looks_like_function_start(image, drop_in_place);
            } else {
                drop_ok = false;
            }
            if (!drop_ok) continue;

            if (options_.require_size_align) {
                if (object_size > kMaxObjectSize) continue;
                if (!is_power_of_two(object_align) || object_align > kMaxObjectAlign) continue;
                if (object_size != 0 && object_size % object_align != 0) continue;
            }

            // --- method run --------------------------------------------------
            std::vector<std::uint64_t> methods;
            std::size_t method_offset = offset + header_words * width;
            while (method_offset + width <= bytes.size() &&
                   methods.size() < options_.max_methods) {
                const std::uint64_t target = load_word(bytes.data() + method_offset, width, order);
                if (!looks_like_function_start(image, target)) break;
                methods.push_back(target);
                method_offset += width;
            }
            if (methods.size() < options_.min_methods) continue;

            // --- candidate ----------------------------------------------------
            VTableCandidate candidate;
            candidate.address = section.virtual_address + offset;
            candidate.file_offset = section.file_offset + offset;
            candidate.drop_in_place = drop_in_place;
            candidate.object_size = object_size;
            candidate.object_align = object_align;

            candidate.entries.reserve(header_words + methods.size());
            const std::uint64_t slots[3] = {drop_in_place, object_size, object_align};
            const bool code_slots[3] = {
                drop_in_place != 0 && looks_like_function_start(image, drop_in_place), false, false};
            for (std::size_t i = 0; i < header_words; ++i) {
                VTableEntry entry;
                entry.index = i;
                entry.address = slots[i];
                entry.file_offset = section.file_offset + offset + i * width;
                entry.points_to_code = code_slots[i];
                if (entry.points_to_code) {
                    if (const core::Symbol* symbol = find_function_symbol(image, slots[i])) {
                        entry.symbol = describe_symbol(*symbol);
                    }
                }
                candidate.entries.push_back(std::move(entry));
            }
            std::size_t correlated = 0;
            bool rust_correlated = false;
            for (std::size_t i = 0; i < methods.size(); ++i) {
                VTableEntry entry;
                entry.index = header_words + i;
                entry.address = methods[i];
                entry.file_offset = section.file_offset + offset +
                                    static_cast<std::uint64_t>(header_words + i) * width;
                entry.points_to_code = true;
                if (const core::Symbol* symbol = find_function_symbol(image, methods[i])) {
                    entry.symbol = describe_symbol(*symbol);
                    ++correlated;
                    if (symbol->rust || looks_like_rust_symbol(symbol->name)) rust_correlated = true;
                }
                candidate.entries.push_back(std::move(entry));
            }

            // --- confidence + rationale --------------------------------------
            double confidence = 0.35;
            if (drop_in_place != 0) confidence += 0.20;
            if (options_.require_size_align) confidence += 0.15;
            if (object_align != 0 && object_size != 0 && object_size % object_align == 0) {
                confidence += 0.03;
            }
            confidence += 0.05 * static_cast<double>(std::min<std::size_t>(methods.size(), 3));
            if (methods.size() >= 2) confidence += 0.05;
            if (candidate.address % 16U == 0) confidence += 0.02;
            if (correlated != 0) {
                confidence += std::min(0.15, 0.05 * static_cast<double>(correlated));
            }
            if (rust_correlated) confidence += 0.10;
            candidate.confidence = std::clamp(confidence, 0.05, 0.99);

            std::string rationale;
            rationale.reserve(160);
            if (drop_in_place != 0) {
                rationale += "drop_in_place=" + std::to_string(drop_in_place) +
                             " points to executable code";
            } else {
                rationale += "null drop_in_place (no-drop type, lenient mode)";
            }
            rationale += "; object_size=" + std::to_string(object_size) +
                         ", object_align=" + std::to_string(object_align);
            if (options_.require_size_align && object_size != 0 && object_align != 0 &&
                object_size % object_align == 0) {
                rationale += " (size is a multiple of a power-of-two align)";
            }
            rationale += "; " + std::to_string(methods.size()) + " method pointer(s)";
            if (!methods.empty()) {
                rationale += " with plausible prologues";
            }
            if (correlated != 0) {
                rationale += "; " + std::to_string(correlated) +
                             " method(s) correlated with function symbols";
            }
            if (rust_correlated) rationale += " (Rust mangled)";
            candidate.rationale = std::move(rationale);

            candidates.push_back(std::move(candidate));
        }
    }

    // Two scans can never produce the same start address, but keep the output
    // deterministic and duplicate-free regardless.
    std::sort(candidates.begin(), candidates.end(),
              [](const VTableCandidate& a, const VTableCandidate& b) {
                  return a.address < b.address;
              });
    candidates.erase(std::unique(candidates.begin(), candidates.end(),
                                 [](const VTableCandidate& a, const VTableCandidate& b) {
                                     return a.address == b.address;
                                 }),
                     candidates.end());
    return candidates;
}

}  // namespace typemorph::derust

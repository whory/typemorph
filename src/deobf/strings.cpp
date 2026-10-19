// TypeMorph - String Revealer implementation.
#include "typemorph/deobf/strings.hpp"
#include "typemorph/deobf/unxorer.hpp"

#include <algorithm>
#include <cctype>

namespace typemorph::deobf {
namespace {

constexpr bool is_printable_byte(std::uint8_t b) noexcept {
    return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\r' || b == '\n';
}

}  // namespace

StringRevealer::StringRevealer(StringScanOptions options) : options_(options) {
    if (options_.min_length == 0) options_.min_length = 4;
}

std::vector<ExtractedString> StringRevealer::extract_ascii_utf8(const core::BinaryView& view) const {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.empty() || !options_.scan_ascii) return results;

    const auto bytes = view.bytes();
    std::size_t start = 0;
    std::size_t current_len = 0;

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (is_printable_byte(bytes[i])) {
            if (current_len == 0) start = i;
            ++current_len;
        } else {
            if (current_len >= options_.min_length && current_len <= options_.max_length) {
                ExtractedString item;
                item.value = std::string(reinterpret_cast<const char*>(bytes.data() + start), current_len);
                item.offset = start;
                item.raw_length = current_len;
                item.category = StringCategory::ascii;
                item.confidence = 0.95;
                results.push_back(std::move(item));
            }
            current_len = 0;
        }
    }

    if (current_len >= options_.min_length && current_len <= options_.max_length) {
        ExtractedString item;
        item.value = std::string(reinterpret_cast<const char*>(bytes.data() + start), current_len);
        item.offset = start;
        item.raw_length = current_len;
        item.category = StringCategory::ascii;
        item.confidence = 0.95;
        results.push_back(std::move(item));
    }

    return results;
}

std::vector<ExtractedString> StringRevealer::extract_utf16le(const core::BinaryView& view) const {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.size() < 2 || !options_.scan_utf16le) return results;

    const auto bytes = view.bytes();
    std::size_t start = 0;
    std::string current_str;

    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        const std::uint8_t low = bytes[i];
        const std::uint8_t high = bytes[i + 1];

        if (high == 0x00 && is_printable_byte(low)) {
            if (current_str.empty()) start = i;
            current_str.push_back(static_cast<char>(low));
        } else {
            if (current_str.size() >= options_.min_length && current_str.size() <= options_.max_length) {
                ExtractedString item;
                item.value = std::move(current_str);
                item.offset = start;
                item.raw_length = item.value.size() * 2;
                item.category = StringCategory::utf16le;
                item.confidence = 0.98;
                item.note = "UTF-16LE wide string";
                results.push_back(std::move(item));
            }
            current_str.clear();
        }
    }

    if (current_str.size() >= options_.min_length && current_str.size() <= options_.max_length) {
        ExtractedString item;
        item.value = std::move(current_str);
        item.offset = start;
        item.raw_length = item.value.size() * 2;
        item.category = StringCategory::utf16le;
        item.confidence = 0.98;
        item.note = "UTF-16LE wide string";
        results.push_back(std::move(item));
    }

    return results;
}

std::vector<ExtractedString> StringRevealer::extract_stack_strings(const core::BinaryView& view) const {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.size() < 8 || !options_.scan_stack_strings) return results;

    const auto bytes = view.bytes();
    // Scan for immediate mov instructions writing consecutive printable bytes to stack:
    // e.g., C6 45 xx yy (mov byte ptr [rbp-xx], yy)
    // or C7 45 xx yy yy yy yy (mov dword ptr [rbp-xx], imm32)
    for (std::size_t i = 0; i + 8 <= bytes.size(); ++i) {
        // Pattern 1: consecutive byte movs: C6 45 [disp] [imm8]
        if (bytes[i] == 0xC6 && bytes[i + 1] == 0x45) {
            std::string stack_str;
            std::size_t start_offset = i;
            std::size_t curr = i;
            while (curr + 4 <= bytes.size() && bytes[curr] == 0xC6 && bytes[curr + 1] == 0x45) {
                const std::uint8_t imm = bytes[curr + 3];
                if (is_printable_byte(imm)) {
                    stack_str.push_back(static_cast<char>(imm));
                    curr += 4;
                } else if (imm == 0x00) {
                    curr += 4;
                    break;
                } else {
                    break;
                }
            }
            if (stack_str.size() >= options_.min_length) {
                ExtractedString item;
                item.value = std::move(stack_str);
                item.offset = start_offset;
                item.raw_length = curr - start_offset;
                item.category = StringCategory::stack_string;
                item.confidence = 0.92;
                item.note = "reconstructed from byte-wise stack assignments (C6 45)";
                results.push_back(std::move(item));
                i = curr;
                continue;
            }
        }

        // Pattern 2: consecutive dword movs: C7 45 [disp] [imm32]
        if (bytes[i] == 0xC7 && bytes[i + 1] == 0x45) {
            std::string stack_str;
            std::size_t start_offset = i;
            std::size_t curr = i;
            while (curr + 7 <= bytes.size() && bytes[curr] == 0xC7 && bytes[curr + 1] == 0x45) {
                bool printable_dword = true;
                for (int d = 0; d < 4; ++d) {
                    const std::uint8_t imm = bytes[curr + 3 + d];
                    if (is_printable_byte(imm)) {
                        stack_str.push_back(static_cast<char>(imm));
                    } else if (imm == 0x00 && !stack_str.empty()) {
                        // Null terminator in dword
                        printable_dword = true;
                        break;
                    } else {
                        printable_dword = false;
                        break;
                    }
                }
                if (!printable_dword) break;
                curr += 7;
            }
            if (stack_str.size() >= options_.min_length) {
                ExtractedString item;
                item.value = std::move(stack_str);
                item.offset = start_offset;
                item.raw_length = curr - start_offset;
                item.category = StringCategory::stack_string;
                item.confidence = 0.94;
                item.note = "reconstructed from dword stack assignments (C7 45)";
                results.push_back(std::move(item));
                i = curr;
            }
        }
    }

    return results;
}

std::vector<ExtractedString> StringRevealer::extract_xor_strings(const core::BinaryView& view) const {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.size() < 16 || !options_.scan_xor_strings) return results;

    // Run Unxorer over chunks to extract obfuscated strings
    UnxorOptions xor_opts;
    xor_opts.min_printable_ratio = 0.85;
    xor_opts.max_candidates = 2;
    Unxorer unxorer(xor_opts);

    // Scan in blocks of 256 bytes
    const auto bytes = view.bytes();
    for (std::size_t chunk_start = 0; chunk_start + 32 <= bytes.size(); chunk_start += 128) {
        const std::size_t chunk_len = std::min<std::size_t>(256, bytes.size() - chunk_start);
        auto sub_slice = view.slice_unchecked(chunk_start, chunk_len);
        core::BinaryView sub_view = core::BinaryView::from_external(sub_slice);

        auto candidates = unxorer.crack(sub_view);
        for (const auto& cand : candidates) {
            if (cand.confidence >= 0.85 && cand.preview.size() >= options_.min_length) {
                ExtractedString item;
                item.value = cand.preview;
                item.offset = chunk_start;
                item.raw_length = chunk_len;
                item.category = StringCategory::decoded_xor;
                item.confidence = cand.confidence;
                item.note = cand.rationale;
                results.push_back(std::move(item));
                break;
            }
        }
    }

    return results;
}

std::vector<ExtractedString> StringRevealer::extract(const core::BinaryView& view) const {
    std::vector<ExtractedString> all;

    auto ascii = extract_ascii_utf8(view);
    all.insert(all.end(), ascii.begin(), ascii.end());

    auto utf16 = extract_utf16le(view);
    all.insert(all.end(), utf16.begin(), utf16.end());

    auto stack = extract_stack_strings(view);
    all.insert(all.end(), stack.begin(), stack.end());

    auto xor_strs = extract_xor_strings(view);
    all.insert(all.end(), xor_strs.begin(), xor_strs.end());

    std::sort(all.begin(), all.end(), [](const ExtractedString& a, const ExtractedString& b) {
        return a.offset < b.offset;
    });

    return all;
}

}  // namespace typemorph::deobf

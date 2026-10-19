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

std::vector<ExtractedString> scan_ascii_tokens(const core::BinaryView& view, std::size_t min_len, std::size_t max_len) {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.empty()) return results;

    const auto bytes = view.bytes();
    std::size_t start = 0;
    std::size_t current_len = 0;

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (is_printable_byte(bytes[i])) {
            if (current_len == 0) start = i;
            ++current_len;
        } else {
            if (current_len >= min_len && current_len <= max_len) {
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

    if (current_len >= min_len && current_len <= max_len) {
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

std::vector<ExtractedString> StringRevealer::extract_ascii_utf8(const core::BinaryView& view) const {
    if (!options_.scan_ascii) return {};
    return scan_ascii_tokens(view, options_.min_length, options_.max_length);
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

std::vector<ExtractedString> StringRevealer::extract_base64(const core::BinaryView& view) const {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.size() < 8 || !options_.scan_base64) return results;

    auto is_b64 = [](char c) noexcept {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    };

    auto b64_val = [](char c) noexcept -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    const auto bytes = view.bytes();
    for (std::size_t i = 0; i + 8 <= bytes.size(); ++i) {
        if (!is_b64(static_cast<char>(bytes[i]))) continue;

        std::size_t len = 0;
        while (i + len < bytes.size() && is_b64(static_cast<char>(bytes[i + len])) && len < 512) {
            ++len;
        }

        if (len >= 8) {
            std::string_view b64_cand(reinterpret_cast<const char*>(bytes.data() + i), len);

            // True base64 payload heuristic:
            // Must contain padding ('=') or non-alphabetic base64 characters ('0'-'9', '+', '/').
            // Plain alphabetic words like "HelloWorld" or "TestString" are ordinary ASCII tokens.
            bool has_b64_indicator = false;
            for (char c : b64_cand) {
                if (c == '=' || (c >= '0' && c <= '9') || c == '+' || c == '/') {
                    has_b64_indicator = true;
                    break;
                }
            }

            if (has_b64_indicator) {
                std::vector<int> vals;
                for (char c : b64_cand) {
                    if (c == '=') break;
                    int v = b64_val(c);
                    if (v >= 0) vals.push_back(v);
                    else { vals.clear(); break; }
                }

                if (vals.size() >= 2) {
                    std::string decoded;
                    for (std::size_t k = 0; k < vals.size(); k += 4) {
                        int v0 = vals[k];
                        int v1 = (k + 1 < vals.size()) ? vals[k + 1] : 0;
                        int v2 = (k + 2 < vals.size()) ? vals[k + 2] : 0;
                        int v3 = (k + 3 < vals.size()) ? vals[k + 3] : 0;

                        decoded.push_back(static_cast<char>((v0 << 2) | (v1 >> 4)));
                        if (k + 2 < vals.size()) {
                            decoded.push_back(static_cast<char>(((v1 & 0xF) << 4) | (v2 >> 2)));
                        }
                        if (k + 3 < vals.size()) {
                            decoded.push_back(static_cast<char>(((v2 & 0x3) << 6) | v3));
                        }
                    }

                    if (decoded.size() >= options_.min_length) {
                        std::size_t printable = 0;
                        for (char c : decoded) {
                            if (is_printable_byte(static_cast<std::uint8_t>(c))) ++printable;
                        }
                        if (printable >= static_cast<std::size_t>(static_cast<double>(decoded.size()) * 0.85)) {
                            ExtractedString item;
                            item.value = std::move(decoded);
                            item.offset = i;
                            item.raw_length = len;
                            item.category = StringCategory::decoded_base64;
                            item.confidence = 0.95;
                            item.note = "decoded from Base64: " + std::string(b64_cand.substr(0, 32));
                            results.push_back(std::move(item));
                        }
                    }
                }
            }
            i += len - 1;
        }
    }
    return results;
}

std::vector<ExtractedString> StringRevealer::extract_rot13(const core::BinaryView& view) const {
    std::vector<ExtractedString> results;
    if (!view.valid() || view.size() < 4 || !options_.scan_rot13) return results;

    static const std::vector<std::string_view> kKeywords = {
        "http", "powershell", "system", "admin", "password", "kernel", "cmd.exe",
        "select", "insert", "update", "delete", "token", "session", "user", "file", "download"
    };

    auto is_rot_token_char = [](char c) noexcept {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '/' || c == ':';
    };

    const auto bytes = view.bytes();
    for (std::size_t i = 0; i + 4 <= bytes.size(); ++i) {
        if (!is_rot_token_char(static_cast<char>(bytes[i]))) continue;

        std::size_t len = 0;
        while (i + len < bytes.size() && is_rot_token_char(static_cast<char>(bytes[i + len])) && len < 512) {
            ++len;
        }

        if (len >= options_.min_length && len <= options_.max_length) {
            std::string raw(reinterpret_cast<const char*>(bytes.data() + i), len);
            std::string rotated;
            rotated.reserve(len);
            bool has_alpha = false;
            for (char c : raw) {
                if (c >= 'a' && c <= 'z') {
                    rotated.push_back(static_cast<char>('a' + (c - 'a' + 13) % 26));
                    has_alpha = true;
                } else if (c >= 'A' && c <= 'Z') {
                    rotated.push_back(static_cast<char>('A' + (c - 'A' + 13) % 26));
                    has_alpha = true;
                } else {
                    rotated.push_back(c);
                }
            }

            if (has_alpha && rotated != raw) {
                std::string lower_rot = rotated;
                for (char& c : lower_rot) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                bool keyword_found = false;
                for (const auto kw : kKeywords) {
                    if (lower_rot.find(kw) != std::string::npos) {
                        keyword_found = true;
                        break;
                    }
                }

                if (keyword_found) {
                    ExtractedString item;
                    item.value = std::move(rotated);
                    item.offset = i;
                    item.raw_length = len;
                    item.category = StringCategory::decoded_rot13;
                    item.confidence = 0.90;
                    item.note = "ROT13 decoded from: " + raw;
                    results.push_back(std::move(item));
                }
            }
        }
        i += len - 1;
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

    auto base64_strs = extract_base64(view);
    all.insert(all.end(), base64_strs.begin(), base64_strs.end());

    auto rot13_strs = extract_rot13(view);
    all.insert(all.end(), rot13_strs.begin(), rot13_strs.end());

    std::sort(all.begin(), all.end(), [](const ExtractedString& a, const ExtractedString& b) {
        return a.offset < b.offset;
    });

    return all;
}

}  // namespace typemorph::deobf

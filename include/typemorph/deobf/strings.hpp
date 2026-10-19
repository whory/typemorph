// TypeMorph - String Revealer (Extraction and deobfuscation of embedded,
// stack, and XOR-hidden strings).
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::deobf {

enum class StringCategory {
    ascii,
    utf8,
    utf16le,
    stack_string,
    decoded_xor,
    decoded_base64,
    decoded_rot13,
};

[[nodiscard]] constexpr const char* to_string(StringCategory category) noexcept {
    switch (category) {
    case StringCategory::ascii: return "ascii";
    case StringCategory::utf8: return "utf8";
    case StringCategory::utf16le: return "utf16le";
    case StringCategory::stack_string: return "stack";
    case StringCategory::decoded_xor: return "xor";
    case StringCategory::decoded_base64: return "base64";
    case StringCategory::decoded_rot13: return "rot13";
    }
    return "unknown";
}

struct ExtractedString {
    std::string value;
    std::uint64_t offset = 0;
    std::size_t raw_length = 0;
    StringCategory category = StringCategory::ascii;
    double confidence = 1.0;
    std::string note;
};

struct StringScanOptions {
    std::size_t min_length = 4;
    std::size_t max_length = 4096;
    bool scan_ascii = true;
    bool scan_utf16le = true;
    bool scan_stack_strings = true;
    bool scan_xor_strings = true;
    bool scan_base64 = true;
    bool scan_rot13 = true;
};

class StringRevealer {
public:
    explicit StringRevealer(StringScanOptions options = {});

    [[nodiscard]] std::vector<ExtractedString> extract(const core::BinaryView& view) const;

private:
    [[nodiscard]] std::vector<ExtractedString> extract_ascii_utf8(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<ExtractedString> extract_utf16le(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<ExtractedString> extract_stack_strings(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<ExtractedString> extract_xor_strings(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<ExtractedString> extract_base64(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<ExtractedString> extract_rot13(const core::BinaryView& view) const;

    StringScanOptions options_;
};

}  // namespace typemorph::deobf

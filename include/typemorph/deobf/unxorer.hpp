// TypeMorph - UnXORer engine for binary & string deobfuscation.
//
// Automatically discovers XOR keys (single-byte, repeating multi-byte, rolling)
// using character frequency analysis, index of coincidence (IC), and null-run
// exploitation.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace typemorph::deobf {

enum class XorMode {
    single_byte,
    multi_byte,
    rolling,
};

struct XorCandidate {
    std::vector<std::uint8_t> key;
    XorMode mode = XorMode::single_byte;
    double confidence = 0.0;
    double entropy = 0.0;
    double printable_ratio = 0.0;
    std::string preview;
    std::string rationale;
    core::BinaryView decrypted;
};

struct UnxorOptions {
    std::size_t min_key_length = 1;
    std::size_t max_key_length = 32;
    std::size_t max_candidates = 5;
    double min_printable_ratio = 0.65;
    std::vector<std::uint8_t> known_key;
    bool search_rolling = true;
};

class Unxorer {
public:
    explicit Unxorer(UnxorOptions options = {});

    // Automatically attacks the view to discover optimal XOR keys
    [[nodiscard]] std::vector<XorCandidate> crack(const core::BinaryView& view) const;

    // Decrypts directly with a given key
    [[nodiscard]] core::BinaryView decrypt(const core::BinaryView& view,
                                           std::span<const std::uint8_t> key,
                                           XorMode mode = XorMode::multi_byte) const;

    // Derives repeating multi-byte keys by exploiting suspected zero-padded regions
    [[nodiscard]] std::vector<XorCandidate> crack_null_runs(const core::BinaryView& view) const;

private:
    [[nodiscard]] std::vector<XorCandidate> crack_single_byte(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<XorCandidate> crack_multi_byte(const core::BinaryView& view) const;
    [[nodiscard]] std::vector<XorCandidate> crack_rolling(const core::BinaryView& view) const;

    UnxorOptions options_;
};

}  // namespace typemorph::deobf

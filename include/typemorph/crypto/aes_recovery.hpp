// TypeMorph - AES Key Recovery & White-box Cryptographic Analyzer
//
// Specializes in:
// - AES-128 / AES-192 / AES-256 Key Schedule & Expanded Round Key recovery
// - Inverting AES key schedules to recover the original master key
// - White-box AES table detection (Chow et al. T-boxes, Type II/III tables)
// - Hardware AES-NI opcode & key derivation sequence extraction
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::crypto {

enum class AesKeySize {
    aes128 = 16,
    aes192 = 24,
    aes256 = 32
};

[[nodiscard]] constexpr const char* to_string(AesKeySize size) noexcept {
    switch (size) {
    case AesKeySize::aes128: return "AES-128";
    case AesKeySize::aes192: return "AES-192";
    case AesKeySize::aes256: return "AES-256";
    }
    return "AES-Unknown";
}

struct RecoveredAesKey {
    AesKeySize key_size = AesKeySize::aes128;
    std::vector<std::uint8_t> master_key;
    std::string master_key_hex;
    std::uint64_t candidate_offset = 0;
    std::uint32_t round_count = 10;
    std::vector<std::vector<std::uint8_t>> round_keys;
    double confidence = 1.0;
    std::string source;            // "expanded-key-schedule", "static-key-inversion", "aes-ni-keyassist"
};

struct WhiteboxAesTable {
    std::uint64_t table_offset = 0;
    std::size_t table_size = 0;
    std::string scheme;            // "chow-whitebox-tboxes", "karroumi-dual-tables", "bba-wb-aes"
    std::size_t detected_rounds = 0;
    double confidence = 0.90;
    std::string description;
};

struct AesRecoveryReport {
    bool has_aes_artifacts = false;
    std::vector<RecoveredAesKey> recovered_keys;
    std::vector<WhiteboxAesTable> whitebox_tables;
    bool has_aesni_instructions = false;
    std::size_t aesni_instructions_count = 0;
    std::string summary;
};

class AesKeyRecoveryEngine {
public:
    AesKeyRecoveryEngine() = default;

    [[nodiscard]] AesRecoveryReport analyze(const core::BinaryView& view) const;
    [[nodiscard]] static std::string to_text_report(const AesRecoveryReport& report);
    [[nodiscard]] static std::string to_json(const AesRecoveryReport& report);

    // Key schedule inversion utilities
    [[nodiscard]] static std::vector<std::uint8_t> invert_aes128_round_key(
        const std::uint8_t* round_key,
        std::uint8_t round_index);

private:
    void scan_expanded_key_schedules(
        const core::BinaryView& view,
        AesRecoveryReport& report) const;

    void scan_whitebox_tables(
        const core::BinaryView& view,
        AesRecoveryReport& report) const;

    void scan_aesni_opcodes(
        const core::BinaryView& view,
        AesRecoveryReport& report) const;
};

}  // namespace typemorph::crypto

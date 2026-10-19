// TypeMorph - Cryptographic and hash constant detector implementation.
#include "typemorph/crypto/crypto_scanner.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::crypto {

std::string_view to_string(CryptoCategory cat) {
    switch (cat) {
    case CryptoCategory::cipher: return "cipher";
    case CryptoCategory::hash: return "hash";
    case CryptoCategory::checksum: return "checksum";
    case CryptoCategory::prng: return "prng";
    }
    return "unknown";
}

namespace {

struct SignatureDefinition {
    const char* algorithm;
    const char* role;
    CryptoCategory category;
    const char* endianness;
    const char* description;
    std::vector<std::uint8_t> bytes;
};

// Converts an array of 32-bit integers to little-endian byte vector
std::vector<std::uint8_t> u32_to_le(std::span<const std::uint32_t> words) {
    std::vector<std::uint8_t> out;
    out.reserve(words.size() * 4);
    for (std::uint32_t w : words) {
        out.push_back(static_cast<std::uint8_t>(w & 0xFF));
        out.push_back(static_cast<std::uint8_t>((w >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((w >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((w >> 24) & 0xFF));
    }
    return out;
}

// Converts an array of 32-bit integers to big-endian byte vector
std::vector<std::uint8_t> u32_to_be(std::span<const std::uint32_t> words) {
    std::vector<std::uint8_t> out;
    out.reserve(words.size() * 4);
    for (std::uint32_t w : words) {
        out.push_back(static_cast<std::uint8_t>((w >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((w >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((w >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(w & 0xFF));
    }
    return out;
}

std::vector<SignatureDefinition> build_signatures() {
    std::vector<SignatureDefinition> sigs;

    // 1. AES Forward S-Box (first 64 bytes)
    static const std::uint8_t kAesSbox[64] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    };
    sigs.push_back({
        "AES", "Forward S-Box", CryptoCategory::cipher, "byte",
        "Rijndael AES forward non-linear substitution box (SubBytes)",
        std::vector<std::uint8_t>(kAesSbox, kAesSbox + sizeof(kAesSbox))
    });

    // 2. AES Inverse S-Box (first 64 bytes)
    static const std::uint8_t kAesInvSbox[64] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
    };
    sigs.push_back({
        "AES", "Inverse S-Box", CryptoCategory::cipher, "byte",
        "Rijndael AES inverse non-linear substitution box (InvSubBytes)",
        std::vector<std::uint8_t>(kAesInvSbox, kAesInvSbox + sizeof(kAesInvSbox))
    });

    // 3. ChaCha20 / Salsa20 Constants
    static const std::uint8_t kChaCha32[16] = {
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };
    sigs.push_back({
        "ChaCha20 / Salsa20", "Sigma Constant (32-byte key)", CryptoCategory::cipher, "ascii",
        "ChaCha20/Salsa20 128-bit constant for 256-bit keys (\"expand 32-byte k\")",
        std::vector<std::uint8_t>(kChaCha32, kChaCha32 + sizeof(kChaCha32))
    });

    static const std::uint8_t kChaCha16[16] = {
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '1', '6', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };
    sigs.push_back({
        "ChaCha20 / Salsa20", "Tau Constant (16-byte key)", CryptoCategory::cipher, "ascii",
        "ChaCha20/Salsa20 128-bit constant for 128-bit keys (\"expand 16-byte k\")",
        std::vector<std::uint8_t>(kChaCha16, kChaCha16 + sizeof(kChaCha16))
    });

    // 4. SHA-256 Initial State
    static const std::uint32_t kSha256H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sigs.push_back({
        "SHA-256", "Initial State (H0..H7)", CryptoCategory::hash, "little-endian",
        "SHA-256 fractional parts of square roots of first 8 primes",
        u32_to_le(kSha256H)
    });
    sigs.push_back({
        "SHA-256", "Initial State (H0..H7)", CryptoCategory::hash, "big-endian",
        "SHA-256 fractional parts of square roots of first 8 primes",
        u32_to_be(kSha256H)
    });

    // 5. SHA-256 Round Constants K[0..15]
    static const std::uint32_t kSha256K[16] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    };
    sigs.push_back({
        "SHA-256", "Round Constants K[0..63]", CryptoCategory::hash, "little-endian",
        "SHA-256 round constant sequence (fractional cube roots of first primes)",
        u32_to_le(kSha256K)
    });
    sigs.push_back({
        "SHA-256", "Round Constants K[0..63]", CryptoCategory::hash, "big-endian",
        "SHA-256 round constant sequence (fractional cube roots of first primes)",
        u32_to_be(kSha256K)
    });

    // 6. SHA-1 Initial State
    static const std::uint32_t kSha1H[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    sigs.push_back({
        "SHA-1", "Initial State (H0..H4)", CryptoCategory::hash, "little-endian",
        "SHA-1 160-bit initial buffer words",
        u32_to_le(kSha1H)
    });
    sigs.push_back({
        "SHA-1", "Initial State (H0..H4)", CryptoCategory::hash, "big-endian",
        "SHA-1 160-bit initial buffer words",
        u32_to_be(kSha1H)
    });

    // 7. MD5 Initial State
    static const std::uint32_t kMd5Init[4] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    };
    sigs.push_back({
        "MD5", "Initial State (A,B,C,D)", CryptoCategory::hash, "little-endian",
        "MD5 128-bit initial chaining variables",
        u32_to_le(kMd5Init)
    });

    // 8. MD5 Sine Table T[0..7]
    static const std::uint32_t kMd5T[8] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
    };
    sigs.push_back({
        "MD5", "Sine Table T[1..64]", CryptoCategory::hash, "little-endian",
        "MD5 transformation table (integer parts of 4294967296 * abs(sin(i)))",
        u32_to_le(kMd5T)
    });

    // 9. CRC32 IEEE 802.3 Table (first 8 entries)
    static const std::uint32_t kCrc32[8] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3
    };
    sigs.push_back({
        "CRC-32", "Polynomial Table (IEEE 802.3)", CryptoCategory::checksum, "little-endian",
        "Precomputed CRC-32 table generated from polynomial 0xEDB88320",
        u32_to_le(kCrc32)
    });

    return sigs;
}

}  // namespace

std::vector<CryptoMatch> CryptoScanner::scan(const core::BinaryView& view) const {
    std::vector<CryptoMatch> matches;
    if (view.empty()) return matches;

    const std::uint64_t start_off = std::min<std::uint64_t>(options_.min_offset, view.size());
    const std::uint64_t end_off = options_.max_offset > start_off
                                      ? std::min<std::uint64_t>(options_.max_offset, view.size())
                                      : view.size();
    if (start_off >= end_off) return matches;

    const auto data_slice = view.slice_unchecked(static_cast<std::size_t>(start_off),
                                                  static_cast<std::size_t>(end_off - start_off));
    const auto signatures = build_signatures();

    for (const auto& sig : signatures) {
        if (sig.category == CryptoCategory::cipher && !options_.detect_ciphers) continue;
        if (sig.category == CryptoCategory::hash && !options_.detect_hashes) continue;
        if (sig.category == CryptoCategory::checksum && !options_.detect_checksums) continue;
        if (sig.bytes.empty() || sig.bytes.size() > data_slice.size()) continue;

        auto it = data_slice.begin();
        while (true) {
            it = std::search(it, data_slice.end(), sig.bytes.begin(), sig.bytes.end());
            if (it == data_slice.end()) break;

            const std::size_t offset_in_slice = static_cast<std::size_t>(std::distance(data_slice.begin(), it));
            CryptoMatch match;
            match.offset = start_off + offset_in_slice;
            match.size = sig.bytes.size();
            match.algorithm = sig.algorithm;
            match.role = sig.role;
            match.category = sig.category;
            match.endianness = sig.endianness;
            match.confidence = 1.0;
            match.description = sig.description;
            matches.push_back(std::move(match));

            ++it;
        }
    }

    std::sort(matches.begin(), matches.end(), [](const CryptoMatch& a, const CryptoMatch& b) {
        return a.offset < b.offset;
    });

    return matches;
}

}  // namespace typemorph::crypto

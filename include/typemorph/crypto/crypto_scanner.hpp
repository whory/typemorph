// TypeMorph - Cryptographic and hash constant detector.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::crypto {

enum class CryptoCategory {
    cipher,
    hash,
    checksum,
    prng
};

[[nodiscard]] std::string_view to_string(CryptoCategory cat);

struct CryptoMatch {
    std::uint64_t offset = 0;
    std::size_t size = 0;
    std::string algorithm;
    std::string role;
    CryptoCategory category = CryptoCategory::cipher;
    std::string endianness = "any";
    double confidence = 1.0;
    std::string description;
};

struct CryptoScanOptions {
    bool detect_ciphers = true;
    bool detect_hashes = true;
    bool detect_checksums = true;
    std::uint64_t min_offset = 0;
    std::uint64_t max_offset = 0;  // 0 = scan entire view
};

class CryptoScanner {
public:
    explicit CryptoScanner(CryptoScanOptions options = {})
        : options_(std::move(options)) {}

    [[nodiscard]] std::vector<CryptoMatch> scan(const core::BinaryView& view) const;

private:
    CryptoScanOptions options_;
};

}  // namespace typemorph::crypto

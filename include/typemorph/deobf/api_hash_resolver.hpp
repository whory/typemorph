// TypeMorph - API Hashing resolver and scanner.
//
// Identifies obfuscated Windows & POSIX API calls hidden behind popular
// hash functions (ROR13, DJB2, SDBM, FNV-1a, CRC32).
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::deobf {

enum class HashAlgorithm {
    ror13,
    djb2,
    sdbm,
    fnv1a32,
    crc32,
};

[[nodiscard]] constexpr const char* to_string(HashAlgorithm algo) noexcept {
    switch (algo) {
    case HashAlgorithm::ror13: return "ror13";
    case HashAlgorithm::djb2: return "djb2";
    case HashAlgorithm::sdbm: return "sdbm";
    case HashAlgorithm::fnv1a32: return "fnv1a32";
    case HashAlgorithm::crc32: return "crc32";
    }
    return "unknown";
}

struct ApiHashMatch {
    std::uint64_t offset = 0;
    std::uint32_t hash_value = 0;
    HashAlgorithm algorithm = HashAlgorithm::ror13;
    std::string module_name;
    std::string api_name;
    double confidence = 0.95;
    std::string note;
};

class ApiHashResolver {
public:
    ApiHashResolver();

    // Resolves a single 32-bit hash value against the database
    [[nodiscard]] std::vector<ApiHashMatch> resolve(std::uint32_t hash_value) const;

    // Scans binary view for immediate/dword constants that match known API hashes
    [[nodiscard]] std::vector<ApiHashMatch> scan(const core::BinaryView& view, double min_confidence = 0.80) const;

    // Direct hash algorithms
    static std::uint32_t compute_ror13(std::string_view name);
    static std::uint32_t compute_djb2(std::string_view name);
    static std::uint32_t compute_sdbm(std::string_view name);
    static std::uint32_t compute_fnv1a(std::string_view name);
    static std::uint32_t compute_crc32(std::string_view name);

private:
    struct ApiEntry {
        std::string module_name;
        std::string api_name;
        std::uint32_t ror13_hash = 0;
        std::uint32_t djb2_hash = 0;
        std::uint32_t sdbm_hash = 0;
        std::uint32_t fnv1a_hash = 0;
        std::uint32_t crc32_hash = 0;
    };

    void init_database();
    std::vector<ApiEntry> database_;
};

}  // namespace typemorph::deobf

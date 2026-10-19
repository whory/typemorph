// TypeMorph - API Hash Resolver tests.
#include "test_framework.hpp"

#include "typemorph/deobf/api_hash_resolver.hpp"

using namespace typemorph::deobf;
using namespace typemorph::core;

TEST_CASE("apihash: algorithm hashing consistency") {
    // Check ROR13
    auto ror_val = ApiHashResolver::compute_ror13("VirtualAlloc");
    CHECK(ror_val != 0);

    // Check DJB2
    auto djb_val = ApiHashResolver::compute_djb2("LoadLibraryA");
    CHECK(djb_val != 0);

    // Check FNV1a
    auto fnv_val = ApiHashResolver::compute_fnv1a("CreateProcessA");
    CHECK(fnv_val != 0);

    // Check CRC32
    auto crc_val = ApiHashResolver::compute_crc32("kernel32.dll");
    CHECK(crc_val != 0);
}

TEST_CASE("apihash: resolve known API hashes") {
    ApiHashResolver resolver;

    // Resolve VirtualAlloc ror13
    auto valloc_ror13 = ApiHashResolver::compute_ror13("VirtualAlloc");
    auto matches = resolver.resolve(valloc_ror13);
    REQUIRE(!matches.empty());
    CHECK(matches[0].api_name == "VirtualAlloc");
    CHECK(matches[0].algorithm == HashAlgorithm::ror13);

    // Resolve LoadLibraryA djb2
    auto loadlib_djb2 = ApiHashResolver::compute_djb2("LoadLibraryA");
    auto matches2 = resolver.resolve(loadlib_djb2);
    REQUIRE(!matches2.empty());
    CHECK(matches2[0].api_name == "LoadLibraryA");
    CHECK(matches2[0].algorithm == HashAlgorithm::djb2);
}

TEST_CASE("apihash: scan buffer for embedded API hashes") {
    ApiHashResolver resolver;

    const std::uint32_t hash_loadlib = ApiHashResolver::compute_ror13("LoadLibraryA");
    const std::uint32_t hash_vprotect = ApiHashResolver::compute_ror13("VirtualProtect");

    // Synthetic bytecode:
    // mov eax, <hash_loadlib> (B8 [imm32])
    // mov edx, <hash_vprotect> (BA [imm32])
    std::vector<std::uint8_t> buffer = {
        0x90, 0x90,
        0xB8,
        static_cast<std::uint8_t>(hash_loadlib & 0xFF),
        static_cast<std::uint8_t>((hash_loadlib >> 8) & 0xFF),
        static_cast<std::uint8_t>((hash_loadlib >> 16) & 0xFF),
        static_cast<std::uint8_t>((hash_loadlib >> 24) & 0xFF),
        0xBA,
        static_cast<std::uint8_t>(hash_vprotect & 0xFF),
        static_cast<std::uint8_t>((hash_vprotect >> 8) & 0xFF),
        static_cast<std::uint8_t>((hash_vprotect >> 16) & 0xFF),
        static_cast<std::uint8_t>((hash_vprotect >> 24) & 0xFF),
        0xC3
    };

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto scanned = resolver.scan(view);

    REQUIRE(scanned.size() >= 2);
    bool found_loadlib = false;
    bool found_vprotect = false;
    for (const auto& m : scanned) {
        if (m.api_name == "LoadLibraryA") found_loadlib = true;
        if (m.api_name == "VirtualProtect") found_vprotect = true;
    }
    CHECK(found_loadlib);
    CHECK(found_vprotect);
}

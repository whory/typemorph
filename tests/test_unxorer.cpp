#include "test_framework.hpp"

#include "typemorph/deobf/unxorer.hpp"

#include <string>
#include <vector>

using namespace typemorph::deobf;
using namespace typemorph::core;

TEST_CASE("unxorer: single byte xor cracking") {
    const std::string original =
        "The quick brown fox jumps over the lazy dog. Reverse engineering encrypted payloads!";
    const std::uint8_t key = 0x5A;
    std::vector<std::uint8_t> encrypted(original.size());
    for (std::size_t i = 0; i < original.size(); ++i) {
        encrypted[i] = static_cast<std::uint8_t>(original[i]) ^ key;
    }

    BinaryView view = BinaryView::from_owned(std::move(encrypted));
    Unxorer unxorer;
    auto candidates = unxorer.crack(view);

    REQUIRE(!candidates.empty());
    CHECK_EQ(candidates[0].key.size(), std::size_t{1});
    CHECK_EQ(candidates[0].key[0], key);
    CHECK(candidates[0].confidence > 0.8);
    CHECK_EQ(candidates[0].preview.substr(0, 15), std::string("The quick brown"));
}

TEST_CASE("unxorer: multi byte xor cracking") {
    const std::string original =
        "This is a longer secret message containing sensitive data and configuration parameters "
        "for the malicious backdoor network connection. Host: evil.domain.com:8080";
    const std::vector<std::uint8_t> key = {'S', 'E', 'C', 'R', 'E', 'T'};
    std::vector<std::uint8_t> encrypted(original.size());
    for (std::size_t i = 0; i < original.size(); ++i) {
        encrypted[i] = static_cast<std::uint8_t>(original[i]) ^ key[i % key.size()];
    }

    BinaryView view = BinaryView::from_owned(std::move(encrypted));
    UnxorOptions options;
    options.min_key_length = 2;
    options.max_key_length = 8;
    Unxorer unxorer(options);
    auto candidates = unxorer.crack(view);

    REQUIRE(!candidates.empty());
    CHECK(candidates[0].confidence > 0.7);
    CHECK(candidates[0].preview.find("This is a longer") != std::string::npos);
}

TEST_CASE("unxorer: direct decryption with known key") {
    const std::string original = "Testing direct decrypt with known key";
    const std::vector<std::uint8_t> key = {0xAA, 0xBB, 0xCC};
    std::vector<std::uint8_t> encrypted(original.size());
    for (std::size_t i = 0; i < original.size(); ++i) {
        encrypted[i] = static_cast<std::uint8_t>(original[i]) ^ key[i % key.size()];
    }

    BinaryView view = BinaryView::from_owned(std::move(encrypted));
    Unxorer unxorer;
    BinaryView decrypted = unxorer.decrypt(view, key, XorMode::multi_byte);
    REQUIRE_EQ(decrypted.size(), original.size());
    std::string decrypted_str(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    CHECK_EQ(decrypted_str, original);
}

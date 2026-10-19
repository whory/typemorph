// TypeMorph - tests for cryptographic constant scanner.
#include "test_framework.hpp"

#include "typemorph/core/binary_view.hpp"
#include "typemorph/crypto/crypto_scanner.hpp"

#include <vector>

namespace {

using typemorph::core::BinaryView;
using typemorph::crypto::CryptoCategory;
using typemorph::crypto::CryptoScanner;
using typemorph::crypto::CryptoScanOptions;

TEST_CASE("crypto scanner: detects ChaCha20 sigma constant") {
    std::vector<std::uint8_t> buffer(128, 0x00);
    const char sigma[] = "expand 32-byte k";
    std::copy(sigma, sigma + 16, buffer.begin() + 32);

    auto view = BinaryView::from_external(buffer, "chacha_test");
    CryptoScanner scanner;
    auto matches = scanner.scan(view);

    REQUIRE_EQ(matches.size(), 1);
    CHECK_EQ(matches[0].offset, 32);
    CHECK_EQ(matches[0].size, 16);
    CHECK(matches[0].algorithm.find("ChaCha20") != std::string::npos);
    CHECK(matches[0].category == CryptoCategory::cipher);
}

TEST_CASE("crypto scanner: detects AES forward S-box") {
    std::vector<std::uint8_t> buffer(256, 0x90);
    static const std::uint8_t kAesSbox[64] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    };
    std::copy(kAesSbox, kAesSbox + 64, buffer.begin() + 16);

    auto view = BinaryView::from_external(buffer, "aes_test");
    CryptoScanner scanner;
    auto matches = scanner.scan(view);

    REQUIRE_EQ(matches.size(), 1);
    CHECK_EQ(matches[0].offset, 16);
    CHECK(matches[0].algorithm == "AES");
    CHECK(matches[0].role == "Forward S-Box");
}

TEST_CASE("crypto scanner: handles empty and plain data cleanly") {
    std::vector<std::uint8_t> zeros(1024, 0x00);
    auto view = BinaryView::from_external(zeros, "zero_test");
    CryptoScanner scanner;
    auto matches = scanner.scan(view);
    CHECK(matches.empty());
}

}  // namespace

// TypeMorph - MSVC Rich Header tests.
#include "test_framework.hpp"

#include "typemorph/pe/rich_header.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace typemorph::pe;
using namespace typemorph::core;

TEST_CASE("rich: tool id and build number resolution") {
    CHECK_EQ(RichHeaderParser::tool_id_to_name(0x0103), std::string("Utc1900_C"));
    CHECK_EQ(RichHeaderParser::tool_id_to_name(0x0104), std::string("Utc1900_CPP"));
    CHECK_EQ(RichHeaderParser::tool_id_to_name(0x0113), std::string("Linker1410"));
    CHECK_EQ(RichHeaderParser::tool_id_to_name(0x0106), std::string("Cvtres1400"));

    CHECK(RichHeaderParser::build_to_vs_version(30133).find("2019") != std::string::npos);
    CHECK(RichHeaderParser::build_to_vs_version(31328).find("2022") != std::string::npos);
    CHECK(RichHeaderParser::build_to_vs_version(35200).find("2026") != std::string::npos);
}

TEST_CASE("rich: synthetic PE Rich header extraction") {
    std::vector<std::uint8_t> buffer(256, 0x00);

    // MZ signature
    buffer[0] = 'M';
    buffer[1] = 'Z';

    // PE offset at 0x3C = 0x80
    *reinterpret_cast<std::uint32_t*>(&buffer[0x3C]) = 0x80;

    constexpr std::uint32_t kXorKey = 0xA1B2C3D4;
    constexpr std::size_t kDansPos = 0x40;

    // DanS marker ^ xor_key
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 0]) = 0x536E6144 ^ kXorKey;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 4]) = kXorKey;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 8]) = kXorKey;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 12]) = kXorKey;

    // Record 1: Utc1900_C (0x0103), build 30133, count 7
    const std::uint32_t comp1 = (0x0103U << 16U) | 30133U;
    const std::uint32_t count1 = 7;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 16]) = comp1 ^ kXorKey;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 20]) = count1 ^ kXorKey;

    // Record 2: Linker1410 (0x0113), build 30133, count 1
    const std::uint32_t comp2 = (0x0113U << 16U) | 30133U;
    const std::uint32_t count2 = 1;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 24]) = comp2 ^ kXorKey;
    *reinterpret_cast<std::uint32_t*>(&buffer[kDansPos + 28]) = count2 ^ kXorKey;

    // "Rich" marker and xor_key
    constexpr std::size_t kRichPos = kDansPos + 32;
    *reinterpret_cast<std::uint32_t*>(&buffer[kRichPos + 0]) = 0x68636952; // "Rich"
    *reinterpret_cast<std::uint32_t*>(&buffer[kRichPos + 4]) = kXorKey;

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    RichHeaderParser parser;
    auto rep = parser.parse(view);

    REQUIRE(rep.present);
    CHECK_EQ(rep.xor_key, kXorKey);
    CHECK_EQ(rep.offset, static_cast<std::uint64_t>(kDansPos));
    REQUIRE_EQ(rep.records.size(), std::size_t{2});

    CHECK_EQ(rep.records[0].tool_id, std::uint16_t{0x0103});
    CHECK_EQ(rep.records[0].tool_name, std::string("Utc1900_C"));
    CHECK_EQ(rep.records[0].build_number, std::uint16_t{30133});
    CHECK_EQ(rep.records[0].count, std::uint32_t{7});

    CHECK_EQ(rep.records[1].tool_id, std::uint16_t{0x0113});
    CHECK_EQ(rep.records[1].tool_name, std::string("Linker1410"));
    CHECK_EQ(rep.records[1].build_number, std::uint16_t{30133});
    CHECK_EQ(rep.records[1].count, std::uint32_t{1});

    REQUIRE(!rep.compiler_versions.empty());
    CHECK(rep.compiler_versions[0].find("2019") != std::string::npos);
    CHECK(!rep.hash.empty());
}

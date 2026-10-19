// TypeMorph - Security and Hardening (checksec) Analyzer tests.
#include "test_framework.hpp"

#include "typemorph/security/security_analyzer.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace typemorph::security;
using namespace typemorph::core;

TEST_CASE("security: W^X section anomaly and expansion ratio") {
    constexpr std::uint64_t kImageBase = 0x400000;
    std::vector<std::uint8_t> buffer(0x3000, 0x00);

    // Section 1: .text with W+X violation (writable & executable)
    Section text_sec;
    text_sec.name = ".text";
    text_sec.virtual_address = kImageBase + 0x1000;
    text_sec.virtual_size = 0x1000;
    text_sec.file_offset = 0x1000;
    text_sec.file_size = 0x1000;
    text_sec.flags = SectionFlag::readable | SectionFlag::writable | SectionFlag::executable;

    // Section 2: .packed with high expansion ratio (raw 512, virtual 16384)
    Section packed_sec;
    packed_sec.name = ".packed";
    packed_sec.virtual_address = kImageBase + 0x2000;
    packed_sec.virtual_size = 16384;
    packed_sec.file_offset = 0x2000;
    packed_sec.file_size = 512;
    packed_sec.flags = SectionFlag::readable | SectionFlag::executable;

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = 32;
    parts.image_base = kImageBase;
    parts.entry_point = kImageBase + 0x1000;
    parts.sections = {text_sec, packed_sec};

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto image = ExecutableImage::from_parts(view, std::move(parts));
    REQUIRE(image.valid());

    SecurityAnalyzer analyzer;
    auto report = analyzer.analyze(image);

    REQUIRE_EQ(report.section_anomalies.size(), std::size_t{2});
    CHECK(report.section_anomalies[0].is_wx);
    CHECK_EQ(report.section_anomalies[0].name, std::string(".text"));

    CHECK(report.section_anomalies[1].expansion_ratio >= 3.0);
    CHECK_EQ(report.section_anomalies[1].name, std::string(".packed"));
}

TEST_CASE("security: packer detection via section names and magic") {
    constexpr std::uint64_t kImageBase = 0x400000;
    std::vector<std::uint8_t> buffer = {
        'U', 'P', 'X', '!', 0x00, 0x00, 0x00, 0x00
    };
    buffer.resize(0x2000, 0x00);

    Section upx0;
    upx0.name = "UPX0";
    upx0.virtual_address = kImageBase + 0x1000;
    upx0.virtual_size = 0x1000;
    upx0.file_offset = 0;
    upx0.file_size = 0;
    upx0.flags = SectionFlag::readable | SectionFlag::writable | SectionFlag::executable;

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = 32;
    parts.image_base = kImageBase;
    parts.entry_point = kImageBase + 0x1000;
    parts.sections = {upx0};

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto image = ExecutableImage::from_parts(view, std::move(parts));
    REQUIRE(image.valid());

    SecurityAnalyzer analyzer;
    auto report = analyzer.analyze(image);

    REQUIRE(!report.packers.empty());
    CHECK_EQ(report.packers[0].name, std::string("UPX"));
}

TEST_CASE("security: overlay and anti-analysis detection") {
    constexpr std::uint64_t kImageBase = 0x400000;
    // 0x1000 bytes for section, plus 0x500 bytes trailing overlay
    std::vector<std::uint8_t> buffer(0x1500, 0x90);

    // Embed RDTSC (0F 31) in code section at offset 0x200
    buffer[0x200] = 0x0F;
    buffer[0x201] = 0x31;

    Section text_sec;
    text_sec.name = ".text";
    text_sec.virtual_address = kImageBase + 0x1000;
    text_sec.virtual_size = 0x1000;
    text_sec.file_offset = 0;
    text_sec.file_size = 0x1000; // Ends at 0x1000
    text_sec.flags = SectionFlag::readable | SectionFlag::executable;

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = 64;
    parts.image_base = kImageBase;
    parts.entry_point = kImageBase + 0x1000;
    parts.sections = {text_sec};

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto image = ExecutableImage::from_parts(view, std::move(parts));
    REQUIRE(image.valid());

    SecurityAnalyzer analyzer;
    auto report = analyzer.analyze(image);

    // Check overlay
    CHECK(report.overlay.present);
    CHECK_EQ(report.overlay.offset, std::uint64_t{0x1000});
    CHECK_EQ(report.overlay.size, std::uint64_t{0x500});

    // Check RDTSC anti-analysis
    REQUIRE(!report.anti_analysis_indicators.empty());
    CHECK(report.anti_analysis_indicators[0].find("RDTSC") != std::string::npos);
}

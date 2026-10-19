// TypeMorph - Deep Compiler, Packer, and Protection Detection Engine Tests.
#include "test_framework.hpp"

#include "typemorph/detect/detect_engine.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace typemorph::detect;
using namespace typemorph::core;

TEST_CASE("detect: UPX entry point pattern and section detection") {
    constexpr std::uint64_t kImageBase = 0x400000;
    // 60 BE 00 10 40 00 8D BE 00 20 40 00 57 83 CD FF
    std::vector<std::uint8_t> buffer = {
        0x60, 0xBE, 0x00, 0x10, 0x40, 0x00, 0x8D, 0xBE,
        0x00, 0x20, 0x40, 0x00, 0x57, 0x83, 0xCD, 0xFF,
        0x90, 0x90, 0x90, 0x90
    };
    buffer.resize(0x2000, 0x00);

    Section sec0;
    sec0.name = "UPX0";
    sec0.virtual_address = kImageBase + 0x1000;
    sec0.virtual_size = 0x1000;
    sec0.file_offset = 0;
    sec0.file_size = 0;
    sec0.flags = SectionFlag::readable | SectionFlag::writable;

    Section sec1;
    sec1.name = "UPX1";
    sec1.virtual_address = kImageBase + 0x2000;
    sec1.virtual_size = 0x1000;
    sec1.file_offset = 0x1000;
    sec1.file_size = 0x1000;
    sec1.flags = SectionFlag::readable | SectionFlag::executable;

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = 32;
    parts.image_base = kImageBase;
    parts.entry_point = kImageBase + 0x2000;
    parts.sections = {sec0, sec1};

    // Place the EP bytes at offset 0x1000 in buffer
    std::memcpy(buffer.data() + 0x1000, "\x60\xBE\x00\x10\x40\x00\x8D\xBE\x00\x20\x40\x00\x57\x83\xCD\xFF", 16);

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto image = ExecutableImage::from_parts(view, std::move(parts));
    REQUIRE(image.valid());

    DetectorEngine engine;
    auto rep = engine.detect(image);

    CHECK(rep.is_packed());
    CHECK_EQ(rep.primary_packer.substr(0, 3), std::string("UPX"));
    CHECK(!rep.matches.empty());

    std::string summary = DetectorEngine::to_text_summary(rep);
    CHECK(summary.find("UPX") != std::string::npos);
}

TEST_CASE("detect: MSVC x64 CRT startup pattern detection") {
    constexpr std::uint64_t kImageBase = 0x140000000;
    // 48 83 EC 28 E8 11 22 33 44 48 83 C4 28 E9 55 66 77 88
    std::vector<std::uint8_t> buffer(0x2000, 0x00);
    const std::uint8_t msvc_ep[] = {
        0x48, 0x83, 0xEC, 0x28, 0xE8, 0x05, 0x00, 0x00,
        0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9, 0x10, 0x00,
        0x00, 0x00
    };
    std::memcpy(buffer.data() + 0x400, msvc_ep, sizeof(msvc_ep));

    Section text_sec;
    text_sec.name = ".text";
    text_sec.virtual_address = kImageBase + 0x1000;
    text_sec.virtual_size = 0x1000;
    text_sec.file_offset = 0x400;
    text_sec.file_size = 0x1000;
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

    DetectorEngine engine;
    auto rep = engine.detect(image);

    CHECK(!rep.is_packed());
    CHECK(rep.primary_compiler.find("Visual C/C++") != std::string::npos);
}

TEST_CASE("detect: AutoIt and ConfuserEx signatures detection") {
    std::vector<std::uint8_t> buffer(0x1000, 0x00);
    // Embed "ConfuserEx" signature
    std::memcpy(buffer.data() + 0x200, "ConfuserEx v1.0.0", 17);
    // Embed AutoIt signature
    std::memcpy(buffer.data() + 0x400, "AU3!EA06", 8);

    BinaryView view = BinaryView::from_owned(std::move(buffer));

    DetectorEngine engine;
    auto rep = engine.detect_view(view);

    bool found_confuser = false;
    bool found_autoit = false;
    for (const auto& m : rep.matches) {
        if (m.name.find("ConfuserEx") != std::string::npos) found_confuser = true;
        if (m.name.find("AutoIt") != std::string::npos) found_autoit = true;
    }

    CHECK(found_confuser);
    CHECK(found_autoit);
    CHECK(rep.is_packed());
}

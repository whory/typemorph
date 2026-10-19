// TypeMorph - Universal PE Unpacker & Header Recovery Tests (unipacker / UPX / ASPack)
#include "typemorph/unpack/universal_unpacker.hpp"
#include "typemorph/core/binary_view.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <string>
#include <vector>

TEST_CASE("unpack: non-packed binary rejected") {
    std::vector<std::uint8_t> plain(1024, 0x90);
    auto view = typemorph::core::BinaryView::from_owned(plain);
    CHECK(!typemorph::unpack::UniversalUnpacker::is_packed(view));

    auto target = typemorph::unpack::UniversalUnpacker::detect(view);
    CHECK(!target.is_packed);
    CHECK(target.packer_type == typemorph::unpack::PackerKind::none);
}

TEST_CASE("unpack: UPX packed binary detection and header recovery") {
    std::vector<std::uint8_t> upx_bin(4096, 0);

    // Minimal DOS + PE Header
    upx_bin[0] = 'M'; upx_bin[1] = 'Z';
    std::uint32_t pe_off = 0x80;
    std::memcpy(upx_bin.data() + 0x3C, &pe_off, 4);
    upx_bin[pe_off] = 'P'; upx_bin[pe_off + 1] = 'E';

    // Section names: UPX0 and UPX1
    std::memcpy(upx_bin.data() + 0x180, "UPX0\0\0\0\0", 8);
    std::memcpy(upx_bin.data() + 0x1A8, "UPX1\0\0\0\0", 8);

    // UPX! tag
    std::memcpy(upx_bin.data() + 0x200, "UPX!", 4);

    // POPAD (0x61) + JMP rel32 (0xE9) to OEP
    // Address of POPAD: 0x300. Image base = 0x00400000 -> site VA = 0x00400306
    // Want target OEP = 0x00401120. rel = 0x00401120 - 0x00400306 = 0xE1A
    upx_bin[0x300] = 0x61;
    upx_bin[0x301] = 0xE9;
    std::int32_t rel = 0x00000E1A;
    std::memcpy(upx_bin.data() + 0x302, &rel, 4);

    auto view = typemorph::core::BinaryView::from_owned(upx_bin);
    CHECK(typemorph::unpack::UniversalUnpacker::is_packed(view));

    auto target = typemorph::unpack::UniversalUnpacker::detect(view);
    CHECK(target.is_packed);
    CHECK(target.packer_type == typemorph::unpack::PackerKind::upx);
    CHECK_EQ(target.recovered_oep_va, 0x00401120ULL);
    CHECK(!target.has_scrambled_headers);

    // Unpack and verify patched sections and entry point
    auto unpack_res = typemorph::unpack::UniversalUnpacker::unpack(view);
    CHECK(unpack_res.success);
    CHECK(std::memcmp(unpack_res.unpacked_payload.data() + 0x180, ".text\0\0\0", 8) == 0);
    CHECK(std::memcmp(unpack_res.unpacked_payload.data() + 0x1A8, ".data\0\0\0", 8) == 0);

    // Check report format
    std::string report = typemorph::unpack::UniversalUnpacker::format_report(target);
    CHECK(report.find("UPX") != std::string::npos);
    CHECK(report.find("401120") != std::string::npos);
}

TEST_CASE("unpack: scrambled UPX headers detected") {
    std::vector<std::uint8_t> scrambled(2048, 0);
    // Section has UPX0, but UPX! magic has been zeroed/stripped
    std::memcpy(scrambled.data() + 0x100, "UPX0\0\0\0\0", 8);

    auto view = typemorph::core::BinaryView::from_owned(scrambled);
    auto target = typemorph::unpack::UniversalUnpacker::detect(view);
    CHECK(target.is_packed);
    CHECK(target.has_scrambled_headers);
    CHECK(!target.warnings.empty());
}

TEST_CASE("unpack: ASPack and PECompact detected") {
    std::vector<std::uint8_t> aspack_bin(1024, 0);
    const std::string aspack_sec = ".aspack";
    std::copy(aspack_sec.begin(), aspack_sec.end(), aspack_bin.begin() + 100);

    auto view1 = typemorph::core::BinaryView::from_owned(aspack_bin);
    auto target1 = typemorph::unpack::UniversalUnpacker::detect(view1);
    CHECK(target1.is_packed);
    CHECK(target1.packer_type == typemorph::unpack::PackerKind::aspack);

    std::vector<std::uint8_t> pec_bin(1024, 0);
    const std::string pec_sec = "PECompact2";
    std::copy(pec_sec.begin(), pec_sec.end(), pec_bin.begin() + 100);

    auto view2 = typemorph::core::BinaryView::from_owned(pec_bin);
    auto target2 = typemorph::unpack::UniversalUnpacker::detect(view2);
    CHECK(target2.is_packed);
    CHECK(target2.packer_type == typemorph::unpack::PackerKind::pecompact);
}

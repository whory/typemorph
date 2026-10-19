// TypeMorph - VFS Payload Extractor unit tests
#include "typemorph/unpack/vfs_extractor.hpp"
#include "test_framework.hpp"

#include <vector>
#include <string>
#include <algorithm>

namespace {

using typemorph::core::BinaryView;
using typemorph::unpack::VfsExtractor;
using typemorph::unpack::VfsContainerReport;

std::vector<std::uint8_t> create_synthetic_vfs_container() {
    std::vector<std::uint8_t> buf(4096, 0);

    // 1. Inject Spoon container signature
    const std::string sig = "Spoon.Container";
    std::copy(sig.begin(), sig.end(), buf.begin() + 0x100);

    // 2. Inject virtual files
    const std::string f1 = "@PROGRAMFILES@\\SecureApp\\core_engine.dll";
    std::copy(f1.begin(), f1.end(), buf.begin() + 0x200);

    const std::string f2 = "@APPDATA@\\SecureApp\\license.dat";
    std::copy(f2.begin(), f2.end(), buf.begin() + 0x300);

    // 3. Inject virtual registry key
    const std::string reg1 = "HKEY_CURRENT_USER\\Software\\ProtectedStudio\\LicenseStatus";
    std::copy(reg1.begin(), reg1.end(), buf.begin() + 0x400);

    return buf;
}

} // namespace

TEST_CASE("vfs_extractor: reject non-container binary") {
    std::vector<std::uint8_t> dummy(512, 0);
    auto view = BinaryView::from_owned(dummy);
    CHECK(!VfsExtractor::is_container(view));

    auto rep = VfsExtractor::analyze(view);
    CHECK(!rep.is_container);
    CHECK(rep.files.empty());
}

TEST_CASE("vfs_extractor: parse synthetic Spoon / Enigma VFS container") {
    auto vfs_bytes = create_synthetic_vfs_container();
    auto view = BinaryView::from_owned(vfs_bytes);

    CHECK(VfsExtractor::is_container(view));

    auto rep = VfsExtractor::analyze(view);
    CHECK(rep.is_container);
    CHECK(rep.container_type.find("Spoon") != std::string::npos);
    CHECK_EQ(rep.files.size(), 2U);

    bool found_dll = false;
    bool found_dat = false;
    for (const auto& f : rep.files) {
        if (f.virtual_path.find("core_engine.dll") != std::string::npos) found_dll = true;
        if (f.virtual_path.find("license.dat") != std::string::npos) found_dat = true;
    }
    CHECK(found_dll);
    CHECK(found_dat);

    // Verify virtual registry keys
    CHECK_EQ(rep.registry_keys.size(), 1U);
    CHECK(rep.registry_keys[0].key_path.find("ProtectedStudio") != std::string::npos);

    // Verify text report
    std::string report_txt = VfsExtractor::format_report(rep);
    CHECK(report_txt.find("Virtual Filesystem") != std::string::npos);
    CHECK(report_txt.find("core_engine.dll") != std::string::npos);
    CHECK(report_txt.find("ProtectedStudio") != std::string::npos);
}

// TypeMorph - VM Analyzer & Profiler Tests (VMDragonSlayer / NoVmp)
#include "typemorph/vm/vm_analyzer.hpp"
#include "typemorph/core/binary_view.hpp"
#include "test_framework.hpp"
#include <string>
#include <vector>
#include <algorithm>

TEST_CASE("vm: recognizes non-virtualized binary") {
    std::vector<std::uint8_t> plain(1024, 0x90); // NOP sled
    auto view = typemorph::core::BinaryView::from_owned(plain);
    CHECK(!typemorph::vm::VmProfiler::is_virtualized(view));

    auto rep = typemorph::vm::VmProfiler::analyze(view);
    CHECK(!rep.is_virtualized);
    CHECK_EQ(rep.vm_entries.size(), 0U);
}

TEST_CASE("vm: detects VMProtect signature and entry points") {
    std::vector<std::uint8_t> vmp(2048, 0x00);
    // Write ".vmp0" section marker
    const std::string sec = ".vmp0";
    std::copy(sec.begin(), sec.end(), vmp.begin() + 100);

    // Write pushfd; pushad (0x9C, 0x60)
    vmp[300] = 0x9C;
    vmp[301] = 0x60;

    auto view = typemorph::core::BinaryView::from_owned(vmp);
    CHECK(typemorph::vm::VmProfiler::is_virtualized(view));

    auto rep = typemorph::vm::VmProfiler::analyze(view);
    CHECK(rep.is_virtualized);
    CHECK_EQ(rep.detected_protector, std::string("VMProtect 3.x (Bytecode VM)"));
    CHECK_EQ(rep.vm_entries.size(), 1U);
    CHECK_EQ(rep.vm_entries[0].entry_rva, 300ULL);
    CHECK_EQ(rep.vm_entries[0].entry_va, 0x00400000ULL + 300ULL);
    CHECK_EQ(rep.vm_entries[0].identified_handlers.size(), 6U);
    CHECK_EQ(rep.total_handlers, 6U);

    std::string text = typemorph::vm::VmProfiler::format_report(rep);
    CHECK(text.find("VMProtect") != std::string::npos);
    CHECK(text.find("VM_PUSH") != std::string::npos);
    CHECK(text.find("VM_EXIT") != std::string::npos);
}

TEST_CASE("vm: detects Themida / WinLicense RISC virtual machine") {
    std::vector<std::uint8_t> themida(2048, 0xCC);
    const std::string tag = ".themida";
    std::copy(tag.begin(), tag.end(), themida.begin() + 50);

    auto view = typemorph::core::BinaryView::from_owned(themida);
    CHECK(typemorph::vm::VmProfiler::is_virtualized(view));

    auto rep = typemorph::vm::VmProfiler::analyze(view);
    CHECK(rep.is_virtualized);
    CHECK(rep.detected_protector.find("Themida") != std::string::npos);
    CHECK_EQ(rep.vm_entries.size(), 1U);
    CHECK(rep.total_handlers >= 5U);
}

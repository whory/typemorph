// TypeMorph - Visual Basic 5.0/6.0 Native & P-Code Analyzer unit tests
#include "typemorph/vb/vb_analyzer.hpp"
#include "test_framework.hpp"

#include <vector>
#include <string>
#include <algorithm>

namespace {

using typemorph::core::BinaryView;
using typemorph::vb::VbAnalyzer;
using typemorph::vb::VbReport;

std::vector<std::uint8_t> create_synthetic_vb6_binary(bool pcode) {
    std::vector<std::uint8_t> buf(4096, 0);

    // 1. Inject "VB5!" magic at offset 0x200
    buf[0x200] = 'V'; buf[0x201] = 'B'; buf[0x202] = '5'; buf[0x203] = '!';

    // 2. Inject runtime import string "MSVBVM60.DLL"
    const std::string runtime = "MSVBVM60.DLL";
    std::copy(runtime.begin(), runtime.end(), buf.begin() + 0x300);

    // 3. Inject P-Code dispatch if requested
    if (pcode) {
        const std::string engine = "ProcCallEngine";
        std::copy(engine.begin(), engine.end(), buf.begin() + 0x400);
    }

    // 4. Inject controls & event procedures
    const std::string ev1 = "Command1_Click";
    std::copy(ev1.begin(), ev1.end(), buf.begin() + 0x500);

    const std::string ev2 = "Form_Load";
    std::copy(ev2.begin(), ev2.end(), buf.begin() + 0x550);

    const std::string ctrl1 = "Command1";
    std::copy(ctrl1.begin(), ctrl1.end(), buf.begin() + 0x600);

    const std::string ctrl2 = "Text1";
    std::copy(ctrl2.begin(), ctrl2.end(), buf.begin() + 0x650);

    return buf;
}

} // namespace

TEST_CASE("vb: reject non-vb binary") {
    std::vector<std::uint8_t> dummy(512, 0);
    auto view = BinaryView::from_owned(dummy);
    CHECK(!VbAnalyzer::is_vb(view));

    auto rep = VbAnalyzer::analyze(view);
    CHECK(!rep.is_vb);
}

TEST_CASE("vb: analyze synthetic VB6 Native and P-Code binaries") {
    // Native Code
    auto native_bytes = create_synthetic_vb6_binary(false);
    auto native_view = BinaryView::from_owned(native_bytes);

    CHECK(VbAnalyzer::is_vb(native_view));
    auto rep_native = VbAnalyzer::analyze(native_view);
    CHECK(rep_native.is_vb);
    CHECK(!rep_native.is_pcode);
    CHECK(rep_native.runtime_version.find("Visual Basic 6.0") != std::string::npos);
    CHECK_EQ(rep_native.vb_header_offset, 0x200U);

    // Verify events
    bool found_cmd_click = false;
    bool found_form_load = false;
    for (const auto& ev : rep_native.events) {
        if (ev.full_name == "Command1_Click") {
            found_cmd_click = true;
            CHECK(ev.code_va != 0);
        }
        if (ev.full_name == "Form_Load") {
            found_form_load = true;
        }
    }
    CHECK(found_cmd_click);
    CHECK(found_form_load);

    // Verify VB source code generation
    std::string vb_src = VbAnalyzer::to_vb_source(rep_native);
    CHECK(vb_src.find("Begin VB.Form Form1") != std::string::npos);
    CHECK(vb_src.find("Begin VB.CommandButton Command1") != std::string::npos);
    CHECK(vb_src.find("Private Sub Command1_Click()") != std::string::npos);
    CHECK(vb_src.find("Private Sub Form_Load()") != std::string::npos);

    // Verify text report
    std::string report_txt = VbAnalyzer::format_report(rep_native);
    CHECK(report_txt.find("Visual Basic 6.0") != std::string::npos);
    CHECK(report_txt.find("Native x86 Code") != std::string::npos);
    CHECK(report_txt.find("Command1_Click") != std::string::npos);

    // P-Code
    auto pcode_bytes = create_synthetic_vb6_binary(true);
    auto pcode_view = BinaryView::from_owned(pcode_bytes);
    auto rep_pcode = VbAnalyzer::analyze(pcode_view);
    CHECK(rep_pcode.is_vb);
    CHECK(rep_pcode.is_pcode);
}

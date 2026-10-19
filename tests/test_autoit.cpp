// TypeMorph - AutoIt v3 Script Extractor & Decompiler unit tests
#include "typemorph/autoit/autoit_decompiler.hpp"
#include "test_framework.hpp"

#include <vector>
#include <string>
#include <algorithm>

namespace {

using typemorph::core::BinaryView;
using typemorph::autoit::AutoItDecompiler;
using typemorph::autoit::AutoItReport;

std::vector<std::uint8_t> create_synthetic_autoit_binary() {
    std::vector<std::uint8_t> buf(2048, 0);

    // 1. Inject AU3!EA06 signature at offset 0x100
    const std::uint8_t ea06_magic[8] = {'A', 'U', '3', '!', 'E', 'A', '0', '6'};
    std::copy(ea06_magic, ea06_magic + 8, buf.begin() + 0x100);

    // 2. Tokenized script stream starting at 0x108
    // Func Main()
    //   $title = "AutoItKeygen"
    //   MsgBox 0, $title
    // EndFunc
    std::size_t cur = 0x108;

    // Token 0x01: Func, length 4, "Main"
    buf[cur++] = 0x01;
    buf[cur++] = 4;
    buf[cur++] = 'M'; buf[cur++] = 'a'; buf[cur++] = 'i'; buf[cur++] = 'n';
    buf[cur++] = 0x2A; // ')'
    buf[cur++] = 0x00; // newline

    // Token 0x10: Variable, length 5, "title"
    buf[cur++] = 0x10;
    buf[cur++] = 5;
    buf[cur++] = 't'; buf[cur++] = 'i'; buf[cur++] = 't'; buf[cur++] = 'l'; buf[cur++] = 'e';

    // Token 0x20: '='
    buf[cur++] = 0x20;

    // Token 0x12: String, length 12, "AutoItKeygen"
    buf[cur++] = 0x12;
    std::string str_val = "AutoItKeygen";
    buf[cur++] = static_cast<std::uint8_t>(str_val.size());
    for (char c : str_val) buf[cur++] = static_cast<std::uint8_t>(c);
    buf[cur++] = 0x00; // newline

    // Token 0x11: Func call "MsgBox"
    buf[cur++] = 0x11;
    std::string fn_val = "MsgBox";
    buf[cur++] = static_cast<std::uint8_t>(fn_val.size());
    for (char c : fn_val) buf[cur++] = static_cast<std::uint8_t>(c);

    buf[cur++] = 0x29; // '('
    // Token 0x13: int 0
    buf[cur++] = 0x13;
    buf[cur++] = 0; buf[cur++] = 0; buf[cur++] = 0; buf[cur++] = 0;
    buf[cur++] = 0x28; // ','

    // Token 0x10: Variable $title
    buf[cur++] = 0x10;
    buf[cur++] = 5;
    buf[cur++] = 't'; buf[cur++] = 'i'; buf[cur++] = 't'; buf[cur++] = 'l'; buf[cur++] = 'e';
    buf[cur++] = 0x2A; // ')'
    buf[cur++] = 0x00; // newline

    // Token 0x02: EndFunc
    buf[cur++] = 0x02;

    return buf;
}

} // namespace

TEST_CASE("autoit: reject non-autoit binary") {
    std::vector<std::uint8_t> dummy(512, 0);
    auto view = BinaryView::from_owned(dummy);
    CHECK(!AutoItDecompiler::is_autoit(view));

    auto rep = AutoItDecompiler::analyze(view);
    CHECK(!rep.is_autoit);
    CHECK(rep.files.empty());
}

TEST_CASE("autoit: parse synthetic AU3!EA06 binary and decompile tokens") {
    auto au3_bytes = create_synthetic_autoit_binary();
    auto view = BinaryView::from_owned(au3_bytes);

    CHECK(AutoItDecompiler::is_autoit(view));

    auto rep = AutoItDecompiler::analyze(view);
    CHECK(rep.is_autoit);
    CHECK(rep.version.find("EA06") != std::string::npos);
    CHECK_EQ(rep.script_offset, 0x100U);
    CHECK(!rep.files.empty());

    // Check decompiled script
    const auto& src = rep.primary_script;
    CHECK(src.find("Func Main()") != std::string::npos);
    CHECK(src.find("$title = \"AutoItKeygen\"") != std::string::npos);
    CHECK(src.find("MsgBox(0 , $title )") != std::string::npos);
    CHECK(src.find("EndFunc") != std::string::npos);

    // Check text report
    std::string report_txt = AutoItDecompiler::format_report(rep);
    CHECK(report_txt.find("AutoIt v3 Script Extractor") != std::string::npos);
    CHECK(report_txt.find("EA06") != std::string::npos);
    CHECK(report_txt.find("script.au3") != std::string::npos);
}

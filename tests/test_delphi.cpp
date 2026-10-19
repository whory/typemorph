// TypeMorph - Delphi / C++Builder VCL & Form Rescuer unit tests
#include "typemorph/delphi/delphi_analyzer.hpp"
#include "test_framework.hpp"

#include <vector>
#include <string>

namespace {

using typemorph::core::BinaryView;
using typemorph::delphi::DelphiAnalyzer;
using typemorph::delphi::DelphiReport;
using typemorph::delphi::DfmForm;

// Build a synthetic binary DFM buffer with TPF0 header
std::vector<std::uint8_t> create_synthetic_tpf0_form() {
    std::vector<std::uint8_t> buf;

    // Header: 'TPF0'
    buf.push_back('T');
    buf.push_back('P');
    buf.push_back('F');
    buf.push_back('0');

    // Root component: type = "TForm1", name = "Form1"
    // Identifiers in TPF0 are 1-byte length followed by chars
    std::string type1 = "TForm1";
    buf.push_back(static_cast<std::uint8_t>(type1.size()));
    buf.insert(buf.end(), type1.begin(), type1.end());

    std::string name1 = "Form1";
    buf.push_back(static_cast<std::uint8_t>(name1.size()));
    buf.insert(buf.end(), name1.begin(), name1.end());

    // Property 1: Caption = 'KeygenMe Delphi' (token 0x04 = string)
    std::string p1_name = "Caption";
    buf.push_back(static_cast<std::uint8_t>(p1_name.size()));
    buf.insert(buf.end(), p1_name.begin(), p1_name.end());
    buf.push_back(0x04); // string token
    std::string p1_val = "KeygenMe Delphi";
    buf.push_back(static_cast<std::uint8_t>(p1_val.size()));
    buf.insert(buf.end(), p1_val.begin(), p1_val.end());

    // Child component: object btnCheck: TButton
    // In TPF0, child objects start with "object" identifier
    std::string child_kw = "object";
    buf.push_back(static_cast<std::uint8_t>(child_kw.size()));
    buf.insert(buf.end(), child_kw.begin(), child_kw.end());

    // child type and name
    std::string ctype = "TButton";
    buf.push_back(static_cast<std::uint8_t>(ctype.size()));
    buf.insert(buf.end(), ctype.begin(), ctype.end());

    std::string cname = "btnCheck";
    buf.push_back(static_cast<std::uint8_t>(cname.size()));
    buf.insert(buf.end(), cname.begin(), cname.end());

    // child property: Caption = 'Verify Key'
    std::string cp_name = "Caption";
    buf.push_back(static_cast<std::uint8_t>(cp_name.size()));
    buf.insert(buf.end(), cp_name.begin(), cp_name.end());
    buf.push_back(0x04);
    std::string cp_val = "Verify Key";
    buf.push_back(static_cast<std::uint8_t>(cp_val.size()));
    buf.insert(buf.end(), cp_val.begin(), cp_val.end());

    // child event: OnClick = btnCheckClick (token 0x05 = ident)
    std::string ev_name = "OnClick";
    buf.push_back(static_cast<std::uint8_t>(ev_name.size()));
    buf.insert(buf.end(), ev_name.begin(), ev_name.end());
    buf.push_back(0x05); // ident token
    std::string ev_val = "btnCheckClick";
    buf.push_back(static_cast<std::uint8_t>(ev_val.size()));
    buf.insert(buf.end(), ev_val.begin(), ev_val.end());

    // End of child component (0x00)
    buf.push_back(0x00);

    // End of root component (0x00)
    buf.push_back(0x00);

    return buf;
}

} // namespace

TEST_CASE("delphi: reject non-delphi binary") {
    std::vector<std::uint8_t> dummy(1024, 0x90);
    auto view = BinaryView::from_owned(dummy);
    CHECK(!DelphiAnalyzer::is_delphi(view));

    auto rep = DelphiAnalyzer::analyze(view);
    CHECK(!rep.is_delphi);
    CHECK_EQ(rep.forms.size(), 0U);
}

TEST_CASE("delphi: decompile binary DFM TPF0 stream") {
    auto tpf = create_synthetic_tpf0_form();
    std::string dfm_text = DelphiAnalyzer::decompile_dfm_binary(tpf);

    CHECK(!dfm_text.empty());
    CHECK(dfm_text.find("object Form1: TForm1") != std::string::npos);
    CHECK(dfm_text.find("Caption = 'KeygenMe Delphi'") != std::string::npos);
    CHECK(dfm_text.find("object btnCheck: TButton") != std::string::npos);
    CHECK(dfm_text.find("OnClick = btnCheckClick") != std::string::npos);
    CHECK(dfm_text.find("end") != std::string::npos);
}

TEST_CASE("delphi: detect delphi signatures and recover forms and events") {
    std::vector<std::uint8_t> bin(4096, 0);

    // Inject Delphi signature string
    const std::string sig = "Software\\Borland\\Delphi\\Locales";
    std::copy(sig.begin(), sig.end(), bin.begin() + 100);

    const std::string ver = "Borland Delphi 7.0";
    std::copy(ver.begin(), ver.end(), bin.begin() + 200);

    // Inject synthetic TPF0 form
    auto tpf = create_synthetic_tpf0_form();
    std::copy(tpf.begin(), tpf.end(), bin.begin() + 500);

    // Inject ShortStrings for VMT classes (len byte + string)
    std::string cls1 = "TForm1";
    bin[1500] = static_cast<std::uint8_t>(cls1.size());
    std::copy(cls1.begin(), cls1.end(), bin.begin() + 1501);

    std::string cls2 = "TButton";
    bin[1600] = static_cast<std::uint8_t>(cls2.size());
    std::copy(cls2.begin(), cls2.end(), bin.begin() + 1601);

    auto view = BinaryView::from_owned(bin);
    CHECK(DelphiAnalyzer::is_delphi(view));

    auto rep = DelphiAnalyzer::analyze(view);
    CHECK(rep.is_delphi);
    CHECK(rep.compiler_version.find("Delphi 7.0") != std::string::npos);
    CHECK_EQ(rep.forms.size(), 1U);
    CHECK_EQ(rep.forms[0].form_name, "Form1");
    CHECK_EQ(rep.forms[0].class_name, "TForm1");

    // Check event mapping
    CHECK(!rep.mapped_events.empty());
    bool found_click = false;
    for (const auto& ev : rep.mapped_events) {
        if (ev.event_name == "OnClick" && ev.handler_name == "btnCheckClick") {
            found_click = true;
            CHECK(ev.handler_va != 0);
        }
    }
    CHECK(found_click);

    // Check Pascal unit source reconstruction
    std::string pas = DelphiAnalyzer::to_pascal_source(rep);
    CHECK(pas.find("unit Form1Unit;") != std::string::npos);
    CHECK(pas.find("TForm1 = class(TForm)") != std::string::npos);
    CHECK(pas.find("btnCheck: TButton;") != std::string::npos);
    CHECK(pas.find("procedure btnCheckClick(Sender: TObject);") != std::string::npos);

    // Check formatted text report
    std::string report_txt = DelphiAnalyzer::format_report(rep);
    CHECK(report_txt.find("TypeMorph Delphi") != std::string::npos);
    CHECK(report_txt.find("Form1") != std::string::npos);
    CHECK(report_txt.find("btnCheckClick") != std::string::npos);
}

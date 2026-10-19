// TypeMorph - Unit tests for advanced .NET deobfuscator engine
#include "typemorph/dotnet/dotnet_deobf.hpp"
#include "test_framework.hpp"

#include <vector>

namespace typemorph::dotnet {

TEST_CASE("dotnet_deobf: non-pe and non-dotnet detection") {
    // Non-PE dummy data
    const std::vector<std::uint8_t> dummy = {0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
    auto view = core::BinaryView::from_external(dummy, "dummy.elf");

    DotNetDeobfuscator deobfuscator;
    auto rep = deobfuscator.deobfuscate_view(view);

    CHECK(!rep.is_dotnet);
    CHECK(rep.total_proxies_inlined == 0);
    CHECK(rep.total_strings_decrypted == 0);
    CHECK(rep.total_switches_killed == 0);

    auto summary = DotNetDeobfuscator::to_text_summary(rep);
    CHECK(summary.find("Not a valid .NET") != std::string::npos);

    auto json = DotNetDeobfuscator::to_json(rep);
    CHECK(json.find("\"is_dotnet\": false") != std::string::npos);
}

TEST_CASE("dotnet_deobf: report formatting and proxy inlining") {
    DotNetDeobfReport rep;
    rep.is_dotnet = true;
    rep.detected_protector = DotNetObfuscatorFlavor::confuserex;
    rep.protector_details = "ConfuserEx v1.0.0 (Proxy Call Inliner + String Decryptor + Switch Killer)";

    DotNetProxyCall proxy;
    proxy.proxy_method_name = "Proxy_Invoke_0";
    proxy.target_name = "WriteLine";
    proxy.target_type = "System.Console";
    proxy.target_token = 0x06000010;
    proxy.call_sites_fixed = 5;
    rep.inlined_proxies.push_back(proxy);
    rep.total_proxies_inlined = 1;

    DotNetDecryptedString ds;
    ds.token = 0x70000001;
    ds.algorithm = "confuserex-xor-dynamic";
    ds.decrypted_value = "SensitiveLicenseKey2026";
    ds.call_site_offset = 0x1234;
    rep.decrypted_strings.push_back(ds);
    rep.total_strings_decrypted = 1;

    DotNetCflowBlock cb;
    cb.method_name = "DecryptPayload";
    cb.switch_table_cases = 12;
    cb.dispatcher_flattened = true;
    cb.strategy = "state-var-constant-folding";
    rep.reconstructed_methods.push_back(cb);
    rep.total_switches_killed = 1;

    auto summary = DotNetDeobfuscator::to_text_summary(rep);
    CHECK(summary.find("ConfuserEx") != std::string::npos);
    CHECK(summary.find("SensitiveLicenseKey2026") != std::string::npos);
    CHECK(summary.find("System.Console::WriteLine") != std::string::npos);
    CHECK(summary.find("DecryptPayload") != std::string::npos);

    auto json = DotNetDeobfuscator::to_json(rep);
    CHECK(json.find("\"is_dotnet\": true") != std::string::npos);
    CHECK(json.find("ConfuserEx") != std::string::npos);
    CHECK(json.find("SensitiveLicenseKey2026") != std::string::npos);
}

}  // namespace typemorph::dotnet

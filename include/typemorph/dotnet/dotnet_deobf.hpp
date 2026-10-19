// TypeMorph - Advanced .NET / C# Deobfuscator Engine
//
// Specializes in unpacking, deobfuscating, and repairing .NET binaries protected by:
// - ConfuserEx (Proxy calls, String encryption, Control flow flattening / Switch killer, Anti-tamper)
// - .NET Reactor (Proxy call delegates, String decoders, Native/PE packing stubs)
// - Eazfuscator, Babel, Agile.NET, and vanilla CIL obfuscation.
//
// Replaces opaque delegates, decrypts string heaps (#US / #Blob), and reconstructs
// linear control flow from dispatcher switches.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/dotnet/dotnet_analyzer.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::dotnet {

// Detected obfuscator signature / protection flavor
enum class DotNetObfuscatorFlavor {
    unknown,
    none,
    confuserex,
    dotnet_reactor,
    eazfuscator,
    agile_net,
    babel,
    smartassembly,
    crypto_obfuscator
};

[[nodiscard]] constexpr const char* to_string(DotNetObfuscatorFlavor flavor) noexcept {
    switch (flavor) {
    case DotNetObfuscatorFlavor::confuserex: return "ConfuserEx";
    case DotNetObfuscatorFlavor::dotnet_reactor: return ".NET Reactor";
    case DotNetObfuscatorFlavor::eazfuscator: return "Eazfuscator.NET";
    case DotNetObfuscatorFlavor::agile_net: return "Agile.NET";
    case DotNetObfuscatorFlavor::babel: return "Babel .NET";
    case DotNetObfuscatorFlavor::smartassembly: return "SmartAssembly";
    case DotNetObfuscatorFlavor::crypto_obfuscator: return "Crypto Obfuscator";
    case DotNetObfuscatorFlavor::none: return "None (Clean .NET)";
    case DotNetObfuscatorFlavor::unknown: return "Generic / Unknown Obfuscator";
    }
    return "Unknown";
}

// Proxy Call Information (ConfuserEx / .NET Reactor proxy calls)
struct DotNetProxyCall {
    std::uint32_t proxy_method_token = 0;
    std::string proxy_method_name;
    std::uint32_t target_token = 0;       // Target MethodDef or MemberRef token
    std::string target_name;
    std::string target_type;
    bool is_pinvoke = false;
    std::string pinvoke_dll;
    std::string pinvoke_entry;
    std::size_t call_sites_fixed = 0;
};

// Decrypted String Entry
struct DotNetDecryptedString {
    std::uint32_t token = 0;              // #US user string token or call parameter key
    std::string decrypted_value;
    std::uint32_t decryptor_method_token = 0;
    std::string decryptor_method_name;
    std::string algorithm;                // "xor", "aes128-cbc", "des", "dynamic-custom"
    std::uint64_t call_site_offset = 0;
};

// Control Flow Switch / Dispatcher Repair Information
struct DotNetCflowBlock {
    std::uint32_t method_token = 0;
    std::string method_name;
    std::size_t switch_table_cases = 0;
    std::size_t state_transitions_resolved = 0;
    bool dispatcher_flattened = false;
    std::string strategy;                 // "state-var-constant-folding", "switch-inliner"
};

// Summary report of .NET Deobfuscation
struct DotNetDeobfReport {
    bool is_dotnet = false;
    DotNetObfuscatorFlavor detected_protector = DotNetObfuscatorFlavor::none;
    std::string protector_details;

    // Fixed / Inlined Proxy Calls
    std::vector<DotNetProxyCall> inlined_proxies;
    std::size_t total_proxies_inlined = 0;

    // Decrypted Strings
    std::vector<DotNetDecryptedString> decrypted_strings;
    std::size_t total_strings_decrypted = 0;

    // Control Flow / Switch Killer
    std::vector<DotNetCflowBlock> reconstructed_methods;
    std::size_t total_switches_killed = 0;

    // Anti-Tamper & Metadata Fixes
    bool anti_tamper_detected = false;
    bool anti_tamper_removed = false;
    std::size_t invalid_metadata_tokens_fixed = 0;

    // Reconstructed deobfuscated C# source
    std::string clean_csharp_source;
};

class DotNetDeobfuscator {
public:
    DotNetDeobfuscator() = default;

    [[nodiscard]] DotNetDeobfReport deobfuscate(const core::ExecutableImage& image) const;
    [[nodiscard]] DotNetDeobfReport deobfuscate_view(const core::BinaryView& view) const;

    // Format summary as human-readable report or JSON
    [[nodiscard]] static std::string to_text_summary(const DotNetDeobfReport& report);
    [[nodiscard]] static std::string to_json(const DotNetDeobfReport& report);

private:
    [[nodiscard]] DotNetObfuscatorFlavor identify_protector(
        const core::ExecutableImage& image,
        const DotNetReport& base_report,
        std::string& details) const;

    void inline_proxy_calls(
        const core::ExecutableImage& image,
        const DotNetReport& base_report,
        DotNetDeobfReport& out_report) const;

    void decrypt_strings(
        const core::ExecutableImage& image,
        const DotNetReport& base_report,
        DotNetDeobfReport& out_report) const;

    void kill_switch_cflow(
        const core::ExecutableImage& image,
        const DotNetReport& base_report,
        DotNetDeobfReport& out_report) const;
};

}  // namespace typemorph::dotnet

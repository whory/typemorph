// TypeMorph - Advanced Deep File / Compiler / Packer / Protection Detection Engine implementation
#include "typemorph/detect/detect_engine.hpp"
#include "typemorph/core/entropy.hpp"
#include "typemorph/pe/rich_header.hpp"
#include "typemorph/dotnet/dotnet_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace typemorph::detect {

const char* to_string(DetectionCategory cat) noexcept {
    switch (cat) {
    case DetectionCategory::compiler: return "Compiler";
    case DetectionCategory::linker: return "Linker";
    case DetectionCategory::packer: return "Packer";
    case DetectionCategory::protector: return "Protector";
    case DetectionCategory::runtime: return "Runtime/Library";
    case DetectionCategory::installer: return "Installer/SFX";
    case DetectionCategory::tool: return "Tool/Generator";
    case DetectionCategory::overlay_payload: return "Overlay Payload";
    case DetectionCategory::unknown: return "Unknown";
    }
    return "Unknown";
}

namespace {

// Helper: pattern with wildcard byte -1
struct SigByte {
    int val = -1; // -1 = ?? wildcard, 0x00..0xFF = match
};

bool match_pattern(std::span<const std::uint8_t> data, std::span<const SigByte> sig) noexcept {
    if (data.size() < sig.size()) return false;
    for (std::size_t i = 0; i < sig.size(); ++i) {
        if (sig[i].val != -1 && static_cast<std::uint8_t>(sig[i].val) != data[i]) {
            return false;
        }
    }
    return true;
}

std::vector<SigByte> parse_hex_sig(std::string_view hex) {
    std::vector<SigByte> result;
    std::size_t i = 0;
    while (i < hex.size()) {
        while (i < hex.size() && (hex[i] == ' ' || hex[i] == '\t')) ++i;
        if (i >= hex.size()) break;
        if (hex[i] == '?') {
            if (i + 1 < hex.size() && hex[i + 1] == '?') ++i;
            result.push_back({-1});
            ++i;
        } else if (i + 1 < hex.size()) {
            char buf[3] = {hex[i], hex[i + 1], '\0'};
            char* end = nullptr;
            unsigned long val = std::strtoul(buf, &end, 16);
            if (end != buf) {
                result.push_back({static_cast<int>(val & 0xFF)});
            }
            i += 2;
        } else {
            break;
        }
    }
    return result;
}

struct EpSignatureRule {
    DetectionCategory category;
    const char* name;
    const char* version;
    double confidence;
    const char* pattern;
    const char* rationale;
};

// High-confidence EP patterns for major compilers, packers, and protectors
const EpSignatureRule kEpRules[] = {
    // --- UPX ---
    {DetectionCategory::packer, "UPX", "3.X / 4.X", 0.99,
     "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF",
     "UPX x86 standard decompression stub (pushad; mov esi, ...)"},
    {DetectionCategory::packer, "UPX", "3.X / 4.X (x64)", 0.99,
     "50 53 51 52 56 57 55 41 50 41 51 41 52 41 53 41 54 41 55 48 8D 35",
     "UPX x64 standard entry point stub (push regs; lea rsi, ...)"},

    // --- ASPack ---
    {DetectionCategory::packer, "ASPack", "2.12 - 2.42", 0.98,
     "60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01",
     "ASPack x86 entry point call $+8 trick"},

    // --- PECompact ---
    {DetectionCategory::packer, "PECompact", "2.X - 3.X", 0.98,
     "B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 00",
     "PECompact SEH setup & INT3/Exception trigger"},

    // --- Themida / WinLicense ---
    {DetectionCategory::protector, "Themida / WinLicense", "2.X - 3.X", 0.95,
     "B8 00 00 00 00 60 0F B7 ?? ?? ?? ?? ?? 2B",
     "Themida entry point initialization stub"},

    // --- VMProtect ---
    {DetectionCategory::protector, "VMProtect", "2.X - 3.X", 0.96,
     "68 ?? ?? ?? ?? E9 ?? ?? ?? ??",
     "VMProtect entry point push constant & jump to VM handler"},

    // --- Enigma Protector ---
    {DetectionCategory::protector, "Enigma Protector", "5.X - 7.X", 0.96,
     "60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ??",
     "Enigma standard x86 delta-offset entry point"},

    // --- Armadillo ---
    {DetectionCategory::protector, "Armadillo", "3.X - 9.X", 0.95,
     "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 60",
     "Armadillo Software Passport wrapper startup"},

    // --- Microsoft Visual C/C++ & Clang-cl ---
    {DetectionCategory::compiler, "Microsoft Visual C/C++", "2015-2026 (x64)", 0.98,
     "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ??",
     "MSVC x64 CRT startup (sub rsp, 28h; call init; add rsp, 28h; jmp mainCRTStartup)"},
    {DetectionCategory::compiler, "Clang / LLVM (clang-cl)", "15.x - 22.x (x64)", 0.98,
     "48 89 4C 24 08 48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3",
     "Clang / LLVM x64 Windows CRT startup thunk (mov [rsp+8], rcx; sub rsp, 28h; call; add rsp, 28h; ret)"},
    {DetectionCategory::compiler, "Microsoft Visual C/C++", "2015-2026 (x86)", 0.98,
     "E8 ?? ?? ?? ?? E9 ?? ?? ?? ??",
     "MSVC x86 standard CRT jump entry thunk"},
    {DetectionCategory::compiler, "Microsoft Visual C/C++", "2005-2013 (x86)", 0.95,
     "55 8B EC 83 EC ?? 53 56 57 FF 15 ?? ?? ?? ??",
     "MSVC classic x86 security cookie initialization (__security_init_cookie)"},

    // --- GCC / MinGW ---
    {DetectionCategory::compiler, "GCC (MinGW)", "4.x - 14.x (x86)", 0.96,
     "83 EC 0C FC E8 00 00 00 00 58 83 C0 00",
     "GCC / MinGW __main initialization sequence"},
    {DetectionCategory::compiler, "GCC (MinGW)", "4.x - 14.x (x64)", 0.96,
     "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3",
     "GCC / MinGW-w64 CRT startup thunk"},

    // --- Borland Delphi / C++ Builder ---
    {DetectionCategory::compiler, "Borland Delphi", "2.0 - 7.0 / XE", 0.98,
     "55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ??",
     "Borland Delphi System.InitExe entry pattern"},

    // --- FreePascal (FPC) ---
    {DetectionCategory::compiler, "FreePascal (FPC)", "2.x - 3.x", 0.96,
     "E8 ?? ?? ?? ?? 31 ED 49 89 D1",
     "FreePascal x64 entry point initialization"},

    // --- Go (Golang) ---
    {DetectionCategory::runtime, "Go (Golang)", "1.2 - 1.23", 0.99,
     "FC 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ??",
     "Go runtime._rt0_amd64 entry point sequence"},

    // --- Rust ---
    {DetectionCategory::compiler, "Rust (rustc)", "1.x", 0.97,
     "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28",
     "Rust mainCRTStartup / std::rt::lang_start entry bridge"},

    // --- AutoIt ---
    {DetectionCategory::runtime, "AutoIt3 Script Engine", "v3.x", 0.98,
     "A3 X! EA 06",
     "AutoIt v3 compiled script header"},

    // --- Inno Setup ---
    {DetectionCategory::installer, "Inno Setup", "5.x - 6.x", 0.98,
     "55 8B EC 53 56 57 A1 ?? ?? ?? ?? C6 00 00",
     "Inno Setup SFX installer entry routine"},

    // --- NSIS (Nullsoft Scriptable Install System) ---
    {DetectionCategory::installer, "NSIS", "2.x - 3.x", 0.98,
     "55 8B EC 83 EC ?? 53 56 57 6A 00 FF 15 ?? ?? ?? ??",
     "Nullsoft Scriptable Install System (NSIS) stub"}
};

std::string bytes_to_hex_str(std::span<const std::uint8_t> data) {
    std::ostringstream ss;
    for (std::size_t i = 0; i < data.size(); ++i) {
        if (i > 0) ss << ' ';
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

} // namespace

DetectionReport DetectorEngine::detect(const core::ExecutableImage& image) const {
    DetectionReport report;
    report.format = image.format();
    report.bits = image.bits();
    report.arch = (image.bits() == 64) ? "x86_64" : "x86_32";
    report.entry_point = image.entry_point();

    const auto view = image.view();
    const auto bytes = view.bytes();
    bool is_dotnet = false;

    // 1. Calculate EP file offset and extract EP sample bytes
    std::uint64_t ep_offset = 0;
    bool ep_found = false;

    for (const auto& sec : image.sections()) {
        if (sec.contains(image.entry_point())) {
            const std::uint64_t offset_in_sec = image.entry_point() - sec.virtual_address;
            if (offset_in_sec < sec.file_size) {
                ep_offset = sec.file_offset + offset_in_sec;
                ep_found = true;
                break;
            }
        }
    }

    if (!ep_found && image.entry_point() != 0 && image.entry_point() < bytes.size()) {
        // Raw view fallback or file-offset entry point
        ep_offset = image.entry_point();
        ep_found = true;
    }

    report.entry_point_file_offset = ep_offset;

    if (ep_offset < bytes.size()) {
        const std::size_t sample_len = std::min<std::size_t>(bytes.size() - ep_offset, 32);
        report.ep_bytes_sample.assign(bytes.data() + ep_offset, bytes.data() + ep_offset + sample_len);
    }

    // 2. EP Pattern Matching (DIE Style)
    if (!report.ep_bytes_sample.empty()) {
        for (const auto& rule : kEpRules) {
            auto sig = parse_hex_sig(rule.pattern);
            if (match_pattern(report.ep_bytes_sample, sig)) {
                DetectionRecord rec;
                rec.category = rule.category;
                rec.name = rule.name;
                rec.version = rule.version;
                rec.confidence = rule.confidence;
                rec.rationale = rule.rationale;
                rec.matched_offset = ep_offset;
                report.matches.push_back(std::move(rec));
            }
        }
    }

    // 2b. PE Rich Header Inspection for Compiler/Linker Fingerprinting
    if (image.format() == core::ImageFormat::pe) {
        pe::RichHeaderParser rich_parser;
        auto rich_rep = rich_parser.parse(view);
        if (rich_rep.present && !rich_rep.compiler_versions.empty()) {
            std::string ver_summary;
            for (std::size_t i = 0; i < rich_rep.compiler_versions.size(); ++i) {
                if (i > 0) ver_summary += ", ";
                ver_summary += rich_rep.compiler_versions[i];
            }
            report.matches.push_back({
                DetectionCategory::compiler, "Microsoft Visual C/C++", ver_summary, 0.99,
                "PE MSVC Rich header validated checksum (XOR key 0x" + std::to_string(rich_rep.xor_key) + ")",
                rich_rep.offset
            });
        }

        dotnet::DotNetAnalyzer dotnet_analyzer;
        auto dotnet_rep = dotnet_analyzer.analyze(image);
        if (dotnet_rep.is_dotnet) {
            is_dotnet = true;
            report.matches.push_back({
                DetectionCategory::runtime, ".NET CLR Runtime", dotnet_rep.runtime_version, 0.99,
                "ECMA-335 CLI metadata header present (BSJB root)", dotnet_rep.cli_header_rva
            });
        }
    }

    // 3. Section Names & Structure Heuristics
    std::uint64_t max_file_end = 0;
    for (const auto& sec : image.sections()) {
        if (sec.file_offset + sec.file_size > max_file_end) {
            max_file_end = sec.file_offset + sec.file_size;
        }
        std::string sname = sec.name;
        for (char& c : sname) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (sname == "upx0" || sname == "upx1" || sname == "upx2") {
            report.matches.push_back({
                DetectionCategory::packer, "UPX", "3.x/4.x", 0.99,
                "UPX section marker '" + sec.name + "'", sec.file_offset
            });
        } else if (sname.starts_with(".aspack") || sname.starts_with("aspack")) {
            report.matches.push_back({
                DetectionCategory::packer, "ASPack", "2.x", 0.98,
                "ASPack section marker '" + sec.name + "'", sec.file_offset
            });
        } else if (sname.starts_with(".pec") || sname.starts_with("pec2")) {
            report.matches.push_back({
                DetectionCategory::packer, "PECompact", "2.x/3.x", 0.96,
                "PECompact section marker '" + sec.name + "'", sec.file_offset
            });
        } else if (sname.starts_with(".vmp") || sname.starts_with("vmp0") || sname.starts_with("vmp1")) {
            report.matches.push_back({
                DetectionCategory::protector, "VMProtect", "2.x/3.x", 0.98,
                "VMProtect virtual section '" + sec.name + "'", sec.file_offset
            });
        } else if (sname.starts_with(".themida") || sname.starts_with("themida")) {
            report.matches.push_back({
                DetectionCategory::protector, "Themida", "2.x/3.x", 0.98,
                "Themida protection section '" + sec.name + "'", sec.file_offset
            });
        } else if (sname.starts_with(".enigma") || sname.starts_with("enigma")) {
            report.matches.push_back({
                DetectionCategory::protector, "Enigma Protector", "5.x/7.x", 0.98,
                "Enigma protector section '" + sec.name + "'", sec.file_offset
            });
        } else if (sname == ".armid" || sname == "armid") {
            report.matches.push_back({
                DetectionCategory::protector, "Armadillo", "3.x-9.x", 0.98,
                "Armadillo Software Passport section '" + sec.name + "'", sec.file_offset
            });
        } else if (sname == ".confuser" || sname == "confuser") {
            report.matches.push_back({
                DetectionCategory::protector, "ConfuserEx", "1.x", 0.99,
                "ConfuserEx marker section '" + sec.name + "'", sec.file_offset
            });
        } else if (sname == ".spoon" || sname == "spoon") {
            report.matches.push_back({
                DetectionCategory::packer, "Spoon Studio / Turbo", "11.x+", 0.98,
                "Spoon Studio virtual environment section", sec.file_offset
            });
        }
    }

    // 4. Magic Signatures Scanning (e.g. Inno, NSIS, AutoIt, PyInstaller, ConfuserEx, .NET)
    if (bytes.size() >= 16) {
        // Search header and overlay/end for special signatures
        for (std::size_t i = 0; i + 8 <= bytes.size(); ++i) {
            // "UPX!" (validate that it is not just a string literal in read-only data unless confirmed by section or EP)
            if (bytes[i] == 'U' && bytes[i + 1] == 'P' && bytes[i + 2] == 'X' && bytes[i + 3] == '!') {
                bool has_upx_section = false;
                for (const auto& sec : image.sections()) {
                    std::string sn = sec.name;
                    for (char& c : sn) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (sn.find("upx") != std::string::npos) {
                        has_upx_section = true;
                        break;
                    }
                }
                if (has_upx_section || i < 0x400 || i + 0x400 >= bytes.size()) {
                    report.matches.push_back({
                        DetectionCategory::packer, "UPX", "3.x/4.x", 0.99,
                        "UPX! magic header at offset 0x" + std::to_string(i), i
                    });
                    break;
                }
            }
            // AutoIt: "AU3!EA06"
            if (bytes[i] == 'A' && bytes[i + 1] == 'U' && bytes[i + 2] == '3' && bytes[i + 3] == '!' &&
                bytes[i + 4] == 'E' && bytes[i + 5] == 'A' && bytes[i + 6] == 0x06) {
                report.matches.push_back({
                    DetectionCategory::runtime, "AutoIt", "v3 (compiled)", 0.99,
                    "AutoIt AU3!EA06 token found at offset 0x" + std::to_string(i), i
                });
                break;
            }
            // PyInstaller: "MEI\x0c\x0b\x0a\x0b" (must be in overlay / end of file)
            if (i >= max_file_end && bytes[i] == 'M' && bytes[i + 1] == 'E' && bytes[i + 2] == 'I' &&
                bytes[i + 3] == 0x0C && bytes[i + 4] == 0x0B && bytes[i + 5] == 0x0A && bytes[i + 6] == 0x0B) {
                report.matches.push_back({
                    DetectionCategory::installer, "PyInstaller", "2.0+", 0.99,
                    "PyInstaller archive magic MEI at offset 0x" + std::to_string(i), i
                });
                break;
            }
            // Inno Setup signature: "Inno Setup Setup Data" (must be in overlay / end of file)
            if (i >= max_file_end && i + 20 <= bytes.size() && std::memcmp(bytes.data() + i, "Inno Setup Setup Data", 20) == 0) {
                report.matches.push_back({
                    DetectionCategory::installer, "Inno Setup", "5.x/6.x", 0.99,
                    "Inno Setup payload stream header", i
                });
                break;
            }
            // Nullsoft NSIS: "NullsoftInst" (must be in overlay / end of file)
            if (i >= max_file_end && i + 12 <= bytes.size() && std::memcmp(bytes.data() + i, "NullsoftInst", 12) == 0) {
                report.matches.push_back({
                    DetectionCategory::installer, "NSIS", "2.x/3.x", 0.99,
                    "NullsoftInst installer archive header", i
                });
                break;
            }
            // ConfuserEx string marker (only within .NET managed assemblies)
            if (is_dotnet && i + 11 <= bytes.size() && std::memcmp(bytes.data() + i, "ConfuserEx ", 11) == 0) {
                report.matches.push_back({
                    DetectionCategory::protector, "ConfuserEx", "1.x", 0.99,
                    "ConfuserEx watermark identifier found in .NET assembly", i
                });
                break;
            }
            // SmartAssembly: "Powered by SmartAssembly" (only within .NET managed assemblies)
            if (is_dotnet && i + 14 <= bytes.size() && std::memcmp(bytes.data() + i, "SmartAssembly", 13) == 0) {
                report.matches.push_back({
                    DetectionCategory::protector, "SmartAssembly", "6.x - 8.x", 0.98,
                    "SmartAssembly obfuscator signature in .NET assembly", i
                });
                break;
            }
            // .NET Reactor: "DotNetPaging" / "Reactor" (only within .NET managed assemblies)
            if (is_dotnet && i + 13 <= bytes.size() && std::memcmp(bytes.data() + i, "DotNetReactor", 13) == 0) {
                report.matches.push_back({
                    DetectionCategory::protector, ".NET Reactor", "5.x - 6.x", 0.98,
                    ".NET Reactor protection marker in .NET assembly", i
                });
                break;
            }
        }
    }

    // 5. Deduplicate matches by (category, name) keeping highest confidence
    std::vector<DetectionRecord> deduped;
    for (const auto& match : report.matches) {
        auto it = std::find_if(deduped.begin(), deduped.end(), [&](const DetectionRecord& r) {
            return r.name == match.name;
        });
        if (it == deduped.end()) {
            deduped.push_back(match);
        } else if (match.confidence > it->confidence) {
            *it = match;
        }
    }
    report.matches = std::move(deduped);

    // 6. Assign primary classifications
    for (const auto& m : report.matches) {
        if (m.category == DetectionCategory::compiler && report.primary_compiler.empty()) {
            report.primary_compiler = m.name + (m.version.empty() ? "" : (" " + m.version));
        } else if (m.category == DetectionCategory::packer && report.primary_packer.empty()) {
            report.primary_packer = m.name + (m.version.empty() ? "" : (" " + m.version));
        } else if (m.category == DetectionCategory::protector && report.primary_protector.empty()) {
            report.primary_protector = m.name + (m.version.empty() ? "" : (" " + m.version));
        } else if (m.category == DetectionCategory::runtime && report.primary_runtime.empty()) {
            report.primary_runtime = m.name + (m.version.empty() ? "" : (" " + m.version));
        }
    }

    return report;
}

DetectionReport DetectorEngine::detect_view(const core::BinaryView& view) const {
    auto img_res = core::ExecutableImage::parse(view);
    if (img_res) {
        return detect(img_res.value());
    }

    // Fallback: parse raw buffer
    DetectionReport report;
    report.format = core::ImageFormat::unknown;
    report.bits = 0;
    report.arch = "unknown";
    report.entry_point = 0;

    const auto bytes = view.bytes();
    if (!bytes.empty()) {
        const std::size_t sample_len = std::min<std::size_t>(bytes.size(), 32);
        report.ep_bytes_sample.assign(bytes.data(), bytes.data() + sample_len);
    }

    // Scan signatures in raw buffer as well
    bool found_upx_magic = false;
    bool found_autoit_magic = false;
    bool found_confuser_magic = false;

    if (bytes.size() >= 8) {
        for (std::size_t i = 0; i + 8 <= bytes.size(); ++i) {
            if (!found_upx_magic && bytes[i] == 'U' && bytes[i + 1] == 'P' && bytes[i + 2] == 'X' && bytes[i + 3] == '!') {
                report.matches.push_back({
                    DetectionCategory::packer, "UPX", "3.x/4.x", 0.99,
                    "UPX! magic header at offset 0x" + std::to_string(i), i
                });
                found_upx_magic = true;
            }
            if (!found_autoit_magic && bytes[i] == 'A' && bytes[i + 1] == 'U' && bytes[i + 2] == '3' && bytes[i + 3] == '!' &&
                bytes[i + 4] == 'E' && bytes[i + 5] == 'A' && (bytes[i + 6] == 0x06 || (bytes[i + 6] == '0' && bytes[i + 7] == '6'))) {
                report.matches.push_back({
                    DetectionCategory::runtime, "AutoIt", "v3 (compiled)", 0.99,
                    "AutoIt AU3!EA06 token found at offset 0x" + std::to_string(i), i
                });
                found_autoit_magic = true;
            }
            if (!found_confuser_magic && i + 10 <= bytes.size() && std::memcmp(bytes.data() + i, "ConfuserEx", 10) == 0) {
                report.matches.push_back({
                    DetectionCategory::protector, "ConfuserEx", "1.x", 0.99,
                    "ConfuserEx watermark identifier found", i
                });
                found_confuser_magic = true;
            }
        }
    }

    for (const auto& m : report.matches) {
        if (m.category == DetectionCategory::compiler && report.primary_compiler.empty()) {
            report.primary_compiler = m.name;
        } else if (m.category == DetectionCategory::packer && report.primary_packer.empty()) {
            report.primary_packer = m.name;
        } else if (m.category == DetectionCategory::protector && report.primary_protector.empty()) {
            report.primary_protector = m.name;
        } else if (m.category == DetectionCategory::runtime && report.primary_runtime.empty()) {
            report.primary_runtime = m.name;
        }
    }

    return report;
}

std::string DetectorEngine::to_text_summary(const DetectionReport& report) {
    std::ostringstream out;
    out << "TypeMorph Deep Identifier (DIE Engine)\n"
        << "  Format:      " << core::to_string(report.format) << " (" << report.bits << "-bit " << report.arch << ")\n";

    char ep_buf[32];
    std::snprintf(ep_buf, sizeof(ep_buf), "0x%llx", static_cast<unsigned long long>(report.entry_point));
    out << "  Entry Point: " << ep_buf;
    if (report.entry_point_file_offset > 0) {
        out << " (Raw offset: 0x" << std::hex << report.entry_point_file_offset << std::dec << ")";
    }
    out << "\n";

    if (!report.ep_bytes_sample.empty()) {
        out << "  EP Opcodes:  " << bytes_to_hex_str(report.ep_bytes_sample) << "\n";
    }
    out << "\n";

    out << "Verdict Summary:\n";
    out << "  Compiler:    " << (report.primary_compiler.empty() ? "Unknown / Not detected" : report.primary_compiler) << "\n";
    out << "  Packer:      " << (report.primary_packer.empty() ? "None (Not packed)" : report.primary_packer) << "\n";
    out << "  Protector:   " << (report.primary_protector.empty() ? "None (Unprotected)" : report.primary_protector) << "\n";
    if (!report.primary_runtime.empty()) {
        out << "  Runtime:     " << report.primary_runtime << "\n";
    }
    out << "\n";

    if (!report.matches.empty()) {
        out << "Detailed Signatures Matched (" << report.matches.size() << "):\n";
        for (const auto& m : report.matches) {
            out << "  - [" << to_string(m.category) << "] " << m.name;
            if (!m.version.empty()) out << " (" << m.version << ")";
            out << " [" << std::fixed << std::setprecision(1) << (m.confidence * 100.0) << "%]: "
                << m.rationale << "\n";
        }
    }

    return out.str();
}

}  // namespace typemorph::detect

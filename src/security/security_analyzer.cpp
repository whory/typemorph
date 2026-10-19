// TypeMorph - Security, Hardening (checksec), Packer & Anomaly Analyzer implementation.
#include "typemorph/security/security_analyzer.hpp"
#include "typemorph/core/entropy.hpp"

#include <algorithm>
#include <cstring>

namespace typemorph::security {
namespace {

inline std::uint16_t read_u16_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

inline std::uint32_t read_u32_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::uint16_t read_u16_be(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint16_t>(p[0]) << 8) | static_cast<std::uint16_t>(p[1]);
}

}  // namespace

SecurityReport SecurityAnalyzer::analyze(const core::ExecutableImage& image) const {
    SecurityReport report;
    report.format = image.format();
    report.bits = image.bits();
    report.entry_point = image.entry_point();

    const auto& sections = image.sections();
    const auto view = image.view();
    const auto bytes = view.bytes();

    // 1. Analyze sections for anomalies and packers
    std::uint64_t max_file_end = 0;
    bool ep_found_in_code = false;

    for (const auto& sec : sections) {
        SectionAnomaly anom;
        anom.name = sec.name;
        anom.virtual_address = sec.virtual_address;
        anom.virtual_size = sec.virtual_size;
        anom.file_offset = sec.file_offset;
        anom.file_size = sec.file_size;

        // W^X violation
        if (sec.writable() && sec.executable()) {
            anom.is_wx = true;
            anom.note += "W^X violation (Writable & Executable); ";
        }

        // Empty raw in executable section
        if (sec.virtual_size > 0 && sec.file_size == 0 && sec.executable()) {
            anom.is_empty_raw = true;
            anom.note += "Virtual code with zero file bytes (BSS code); ";
        }

        // High expansion ratio
        if (sec.file_size > 0) {
            anom.expansion_ratio = static_cast<double>(sec.virtual_size) / static_cast<double>(sec.file_size);
            if (anom.expansion_ratio >= 3.0 && sec.virtual_size >= 4096) {
                anom.note += "High memory expansion ratio (>=" + std::to_string(static_cast<int>(anom.expansion_ratio)) + "x); ";
            }
        }

        if (sec.executable() && sec.contains(image.entry_point())) {
            ep_found_in_code = true;
        }

        if (sec.file_offset + sec.file_size > max_file_end) {
            max_file_end = sec.file_offset + sec.file_size;
        }

        // Packer signature checks by section name
        std::string sname = sec.name;
        for (char& c : sname) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (sname.find("upx0") != std::string::npos || sname.find("upx1") != std::string::npos || sname.find("upx2") != std::string::npos) {
            report.packers.push_back({"UPX", 0.99, "UPX section name detected: " + sec.name});
        } else if (sname.find("aspack") != std::string::npos) {
            report.packers.push_back({"ASPack", 0.98, "ASPack section name detected: " + sec.name});
        } else if (sname.find("pec") != std::string::npos || sname.find("pecompact") != std::string::npos) {
            report.packers.push_back({"PECompact", 0.95, "PECompact section name detected: " + sec.name});
        } else if (sname.find("vmp") != std::string::npos) {
            report.packers.push_back({"VMProtect", 0.98, "VMProtect virtualized section detected: " + sec.name});
        } else if (sname.find("themida") != std::string::npos) {
            report.packers.push_back({"Themida", 0.98, "Themida protector section detected: " + sec.name});
        } else if (sname.find("enigma") != std::string::npos) {
            report.packers.push_back({"Enigma", 0.98, "Enigma protector section detected: " + sec.name});
        }

        if (anom.is_wx || anom.is_empty_raw || anom.expansion_ratio >= 3.0) {
            report.section_anomalies.push_back(std::move(anom));
        }
    }

    report.entry_point_outside_code = (!ep_found_in_code && image.entry_point() != 0);

    // 2. Overlay detection
    if (view.size() > max_file_end + 128 && max_file_end > 0) {
        report.overlay.present = true;
        report.overlay.offset = max_file_end;
        report.overlay.size = view.size() - max_file_end;
        auto overlay_slice = view.slice_unchecked(max_file_end, report.overlay.size);
        report.overlay.entropy = core::shannon_entropy(overlay_slice);
    }

    // 3. Raw byte search for packer signatures
    if (bytes.size() >= 4) {
        for (std::size_t i = 0; i + 4 <= bytes.size(); ++i) {
            // "UPX!"
            if (bytes[i] == 'U' && bytes[i + 1] == 'P' && bytes[i + 2] == 'X' && bytes[i + 3] == '!') {
                bool already = false;
                for (const auto& p : report.packers) {
                    if (p.name == "UPX") { already = true; break; }
                }
                if (!already) {
                    report.packers.push_back({"UPX", 0.99, "UPX! magic header detected at offset " + std::to_string(i)});
                }
                break;
            }
            // PyInstaller: "MEI\x0c\x0b\x0a\x0b"
            if (i + 7 <= bytes.size() && bytes[i] == 'M' && bytes[i + 1] == 'E' && bytes[i + 2] == 'I' &&
                bytes[i + 3] == 0x0C && bytes[i + 4] == 0x0B && bytes[i + 5] == 0x0A && bytes[i + 6] == 0x0B) {
                report.packers.push_back({"PyInstaller", 0.99, "PyInstaller archive magic detected at offset " + std::to_string(i)});
                break;
            }
        }
    }

    // 4. PE-specific security mitigations
    if (image.format() == core::ImageFormat::pe && bytes.size() >= 0x40) {
        const std::uint32_t pe_offset = read_u32_le(bytes.data() + 0x3C);
        if (pe_offset + 0x18 <= bytes.size() && bytes[pe_offset] == 'P' && bytes[pe_offset + 1] == 'E') {
            const std::size_t opt_offset = pe_offset + 24;
            if (opt_offset + 72 <= bytes.size()) {
                const std::uint16_t magic = read_u16_le(bytes.data() + opt_offset);
                const bool is_pe32_plus = (magic == 0x20B);

                const std::uint16_t dll_char = read_u16_le(bytes.data() + opt_offset + 70);
                if (dll_char & 0x0040) report.mitigations.aslr = true;
                if (dll_char & 0x0020) report.mitigations.high_entropy_va = true;
                if (dll_char & 0x0100) report.mitigations.dep_nx = true;
                if (dll_char & 0x4000) report.mitigations.cfg = true;
                if (dll_char & 0x2000) report.mitigations.isolated = true;

                // SafeSEH: if not NO_SEH (0x0400) on 32-bit PE
                if (!is_pe32_plus && !(dll_char & 0x0400)) {
                    report.mitigations.safe_seh = true;
                }

                // Data directories
                const std::size_t dd_offset = opt_offset + (is_pe32_plus ? 112 : 96);
                if (dd_offset + 16 * 8 <= bytes.size()) {
                    // Security directory (index 4)
                    const std::uint32_t sec_rva = read_u32_le(bytes.data() + dd_offset + 4 * 8);
                    const std::uint32_t sec_size = read_u32_le(bytes.data() + dd_offset + 4 * 8 + 4);
                    if (sec_rva != 0 && sec_size != 0) {
                        report.mitigations.signed_binary = true;
                    }

                    // TLS directory (index 9)
                    const std::uint32_t tls_rva = read_u32_le(bytes.data() + dd_offset + 9 * 8);
                    const std::uint32_t tls_size = read_u32_le(bytes.data() + dd_offset + 9 * 8 + 4);
                    if (tls_rva != 0 && tls_size != 0) {
                        report.has_tls_callbacks = true;
                        report.anti_analysis_indicators.push_back("TLS Directory present (TLS callbacks for pre-entrypoint execution)");
                    }

                    // LoadConfig directory (index 10)
                    const std::uint32_t lc_rva = read_u32_le(bytes.data() + dd_offset + 10 * 8);
                    const std::uint32_t lc_size = read_u32_le(bytes.data() + dd_offset + 10 * 8 + 4);
                    if (lc_rva != 0 && lc_size >= 0x48) {
                        // In 64-bit load config, GuardFlags at offset 0x58
                        report.mitigations.cfg = true;
                    }
                }
            }
        }
    }

    // 5. ELF-specific security mitigations
    if (image.format() == core::ImageFormat::elf && bytes.size() >= 0x30) {
        // e_type at offset 16
        const std::uint16_t e_type = read_u16_le(bytes.data() + 16);
        if (e_type == 3) { // ET_DYN
            report.mitigations.pie = true;
            report.mitigations.aslr = true;
        }

        // Stack canary check via symbols
        for (const auto& sym : image.symbols()) {
            if (sym.name.find("__stack_chk_fail") != std::string::npos ||
                sym.name.find("__stack_chk_guard") != std::string::npos) {
                report.mitigations.stack_canary = true;
                break;
            }
        }

        report.mitigations.dep_nx = true; // Modern ELF standard default unless executable stack
    }

    // 6. Anti-analysis scans in executable code
    for (const auto& sec : sections) {
        if (!sec.executable() || sec.file_size < 4) continue;
        const std::size_t start = static_cast<std::size_t>(sec.file_offset);
        const std::size_t len = static_cast<std::size_t>(sec.file_size);
        if (start + len > bytes.size()) continue;

        for (std::size_t i = start; i + 3 <= start + len; ++i) {
            // RDTSC (0F 31)
            if (bytes[i] == 0x0F && bytes[i + 1] == 0x31) {
                report.anti_analysis_indicators.push_back("RDTSC instruction detected at file offset 0x" +
                    std::to_string(i) + " (anti-debugging timing check)");
                i += 1;
                if (report.anti_analysis_indicators.size() > 5) break;
            }
            // PEB BeingDebugged: fs:[0x30] (64 A1 30 00 00 00 or 64 8B ... 30)
            if (bytes[i] == 0x64 && bytes[i + 1] == 0xA1 && i + 5 <= start + len && bytes[i + 2] == 0x30) {
                report.anti_analysis_indicators.push_back("PEB.BeingDebugged direct check via fs:[0x30] at offset 0x" + std::to_string(i));
                i += 5;
                if (report.anti_analysis_indicators.size() > 5) break;
            }
            // PEB x64: gs:[0x60] (65 48 8B ... 60)
            if (bytes[i] == 0x65 && bytes[i + 1] == 0x48 && bytes[i + 2] == 0x8B && i + 7 <= start + len && bytes[i + 4] == 0x60) {
                report.anti_analysis_indicators.push_back("x64 PEB access via gs:[0x60] at offset 0x" + std::to_string(i));
                i += 6;
                if (report.anti_analysis_indicators.size() > 5) break;
            }
        }
    }

    return report;
}

SecurityReport SecurityAnalyzer::analyze_view(const core::BinaryView& view) const {
    auto img_res = core::ExecutableImage::parse(view);
    if (img_res) {
        return analyze(img_res.value());
    }

    SecurityReport report;
    report.format = core::ImageFormat::unknown;
    return report;
}

}  // namespace typemorph::security

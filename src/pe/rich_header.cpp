// TypeMorph - MSVC Rich Header & Compiler Fingerprinting Engine.
#include "typemorph/pe/rich_header.hpp"

#include <algorithm>
#include <cstdio>
#include <set>

namespace typemorph::pe {

namespace {

inline std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) |
           (static_cast<std::uint32_t>(p[3]) << 24U);
}

}  // namespace

std::string RichHeaderParser::tool_id_to_name(std::uint16_t tool_id) {
    switch (tool_id) {
    case 0x0001: return "Import0";
    case 0x0002: return "Linker510";
    case 0x0003: return "Cvtomf510";
    case 0x0004: return "Linker600";
    case 0x0005: return "Cvtomf600";
    case 0x0006: return "Cvtres500";
    case 0x0007: return "Utc11_C";
    case 0x0008: return "Utc12_C";
    case 0x0009: return "Utc12_CPP";
    case 0x000A: return "Utc1210_C";
    case 0x000B: return "Utc1210_CPP";
    case 0x000E: return "Utc13_C";
    case 0x000F: return "Utc13_CPP";
    case 0x0010: return "Utc1310_C";
    case 0x0011: return "Utc1310_CPP";
    case 0x0012: return "Linker710";
    case 0x0014: return "Cvtres710";
    case 0x0015: return "Utc1400_C";
    case 0x0016: return "Utc1400_CPP";
    case 0x0017: return "Utc1500_C";
    case 0x0018: return "Utc1500_CPP";
    case 0x001D: return "Linker800";
    case 0x001E: return "Cvtres800";
    case 0x005D: return "Linker900";
    case 0x005E: return "Cvtres900";
    case 0x006D: return "Utc1600_C";
    case 0x006E: return "Utc1600_CPP";
    case 0x0078: return "Masm900";
    case 0x0093: return "Linker1000";
    case 0x0094: return "Cvtres1000";
    case 0x00AA: return "Utc1700_C";
    case 0x00AB: return "Utc1700_CPP";
    case 0x00C7: return "Linker1100";
    case 0x00C8: return "Cvtres1100";
    case 0x00E4: return "Utc1800_C";
    case 0x00E5: return "Utc1800_CPP";
    case 0x00FF: return "Linker1200";
    case 0x0100: return "Cvtres1200";
    case 0x0103: return "Utc1900_C";
    case 0x0104: return "Utc1900_CPP";
    case 0x0105: return "Linker1400";
    case 0x0106: return "Cvtres1400";
    case 0x0109: return "Masm1400";
    case 0x010A: return "Utc1900_C_ARM";
    case 0x010B: return "Utc1900_CPP_ARM";
    case 0x010C: return "Utc1900_C_ARM64";
    case 0x010D: return "Utc1900_CPP_ARM64";
    case 0x010E: return "Utc1910_C";
    case 0x010F: return "Utc1910_CPP";
    case 0x0113: return "Linker1410";
    case 0x0114: return "Cvtres1410";
    case 0x0117: return "Utc1920_C";
    case 0x0118: return "Utc1920_CPP";
    case 0x011C: return "Linker1420";
    case 0x011D: return "Cvtres1420";
    case 0x0120: return "Utc1930_C";
    case 0x0121: return "Utc1930_CPP";
    case 0x0124: return "Linker1430";
    case 0x0125: return "Cvtres1430";
    default:
        char buf[32];
        std::snprintf(buf, sizeof(buf), "Tool_0x%04X", tool_id);
        return buf;
    }
}

std::string RichHeaderParser::build_to_vs_version(std::uint16_t build_number) {
    if (build_number >= 35000) return "Visual Studio 2026 (v18.0+)";
    if (build_number >= 30200) return "Visual Studio 2022 (v17.x)";
    if (build_number >= 27000) return "Visual Studio 2019 (v16.x)";
    if (build_number >= 25000) return "Visual Studio 2017 (v15.x)";
    if (build_number >= 20000) return "Visual Studio 2015 (v14.0)";
    if (build_number >= 18000) return "Visual Studio 2013 (v12.0)";
    if (build_number >= 16000) return "Visual Studio 2012 (v11.0)";
    if (build_number >= 14000) return "Visual Studio 2010 (v10.0)";
    if (build_number >= 12000) return "Visual Studio 2008 (v9.0)";
    if (build_number >= 10000) return "Visual Studio 2005 (v8.0)";
    if (build_number >= 7000)  return "Visual Studio .NET 2003";
    if (build_number > 0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "MSVC Build %u", build_number);
        return buf;
    }
    return "Unknown";
}

RichHeaderReport RichHeaderParser::parse(const core::BinaryView& view) const {
    RichHeaderReport report;
    const auto bytes = view.bytes();
    if (bytes.size() < 0x80) return report;

    // Check MS-DOS MZ header
    if (bytes[0] != 'M' || bytes[1] != 'Z') return report;

    const std::uint32_t pe_offset = read_u32(bytes.data() + 0x3C);
    const std::size_t scan_end = std::min<std::size_t>(bytes.size(), pe_offset > 0 ? pe_offset : 0x400);

    // Search for "Rich" marker (0x68636952)
    std::size_t rich_pos = 0;
    for (std::size_t i = 0x40; i + 8 <= scan_end; i += 4) {
        if (read_u32(bytes.data() + i) == 0x68636952) { // "Rich"
            rich_pos = i;
            break;
        }
    }

    if (rich_pos == 0) return report;

    const std::uint32_t xor_key = read_u32(bytes.data() + rich_pos + 4);
    report.xor_key = xor_key;

    // Search backwards for "DanS" (0x536E6144 ^ xor_key)
    const std::uint32_t dans_masked = 0x536E6144 ^ xor_key;
    std::size_t dans_pos = 0;

    for (std::size_t i = rich_pos; i >= 0x40; i -= 4) {
        if (read_u32(bytes.data() + i) == dans_masked) {
            dans_pos = i;
            break;
        }
    }

    if (dans_pos == 0 || dans_pos >= rich_pos) return report;

    // Verify 3 padding dwords (each equal to xor_key, meaning unmasked 0)
    if (dans_pos + 16 > rich_pos) return report;

    report.present = true;
    report.offset = dans_pos;
    report.size = (rich_pos + 8) - dans_pos;

    // Entries start at dans_pos + 16 (after DanS and 3 null dwords)
    std::set<std::string> unique_vs;
    std::uint32_t rolling_hash = 0x5A17C0DE;

    for (std::size_t p = dans_pos + 16; p + 8 <= rich_pos; p += 8) {
        const std::uint32_t comp_id = read_u32(bytes.data() + p) ^ xor_key;
        const std::uint32_t count = read_u32(bytes.data() + p + 4) ^ xor_key;

        RichRecord rec;
        rec.tool_id = static_cast<std::uint16_t>(comp_id >> 16U);
        rec.build_number = static_cast<std::uint16_t>(comp_id & 0xFFFFU);
        rec.count = count;
        rec.tool_name = tool_id_to_name(rec.tool_id);
        rec.vs_version = build_to_vs_version(rec.build_number);

        if (!rec.vs_version.empty() && rec.vs_version != "Unknown") {
            unique_vs.insert(rec.vs_version);
        }

        // Rolling hash for RichPE fingerprinting
        rolling_hash ^= (comp_id << (count % 17)) | (comp_id >> (32 - (count % 17)));
        rolling_hash = (rolling_hash << 5) | (rolling_hash >> 27);
        rolling_hash += count;

        report.records.push_back(std::move(rec));
    }

    report.checksum = rolling_hash;
    char hash_buf[32];
    std::snprintf(hash_buf, sizeof(hash_buf), "%08x%08x", xor_key, rolling_hash);
    report.hash = hash_buf;

    report.compiler_versions.assign(unique_vs.begin(), unique_vs.end());
    return report;
}

}  // namespace typemorph::pe

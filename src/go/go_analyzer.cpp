// TypeMorph - Golang pclntab & Symbol Metadata Reconstructor.
#include "typemorph/go/go_analyzer.hpp"

#include <algorithm>
#include <cstring>
#include <set>

namespace typemorph::golang {

namespace {

inline std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) |
           (static_cast<std::uint32_t>(p[3]) << 24U);
}

inline std::int32_t read_i32(const std::uint8_t* p) noexcept {
    return static_cast<std::int32_t>(read_u32(p));
}

inline std::uint64_t read_u64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(read_u32(p)) |
           (static_cast<std::uint64_t>(read_u32(p + 4)) << 32U);
}

inline std::uint64_t read_uintptr(const std::uint8_t* p, std::size_t ptr_size) noexcept {
    return ptr_size == 8 ? read_u64(p) : static_cast<std::uint64_t>(read_u32(p));
}

}  // namespace

std::string GoAnalyzer::extract_package(std::string_view full_name) {
    if (full_name.empty()) return {};

    // Remove receiver syntax like "(*Server)." or "(Server)."
    auto last_slash = full_name.rfind('/');
    std::size_t search_start = (last_slash == std::string_view::npos) ? 0 : last_slash + 1;

    auto dot = full_name.find('.', search_start);
    if (dot != std::string_view::npos) {
        return std::string(full_name.substr(0, dot));
    }
    return std::string(full_name);
}

GoAnalysisReport GoAnalyzer::parse_pclntab(const core::ExecutableImage& image,
                                           const std::uint8_t* base,
                                           std::size_t offset,
                                           std::size_t max_len,
                                           std::uint64_t pclntab_va) const {
    (void)image;
    GoAnalysisReport report;
    if (max_len < 16) return report;

    const std::uint8_t* p = base + offset;
    const std::uint32_t magic = read_u32(p);

    if (magic == 0xFFFFFFFB) {
        report.version = GoPclnVersion::go12;
    } else if (magic == 0xFFFFFFFA) {
        report.version = GoPclnVersion::go116;
    } else if (magic == 0xFFFFFFF0 || magic == 0xFFFFFFF1) {
        report.version = GoPclnVersion::go118;
    } else {
        return report;
    }

    report.detected = true;
    report.quantum = p[6];
    report.ptr_size = p[7];
    report.pclntab_va = pclntab_va;

    if (report.ptr_size != 4 && report.ptr_size != 8) {
        report.detected = false;
        return report;
    }

    const std::size_t ptr_sz = report.ptr_size;
    std::set<std::string> unique_pkgs;

    // Helper to read string from pclntab offset
    auto read_pcln_string = [&](std::size_t str_offset) -> std::string {
        if (str_offset >= max_len) return {};
        const std::uint8_t* s_ptr = p + str_offset;
        std::size_t cur = str_offset;
        std::string s;
        while (cur < max_len && *s_ptr != '\0') {
            s.push_back(static_cast<char>(*s_ptr));
            ++s_ptr;
            ++cur;
        }
        return s;
    };

    if (report.version == GoPclnVersion::go12) {
        if (max_len < 8 + ptr_sz) return report;
        const std::uint64_t nfunc_raw = read_uintptr(p + 8, ptr_sz);
        const std::size_t nfunc = static_cast<std::size_t>(std::min<std::uint64_t>(nfunc_raw, 250000));
        report.function_count = nfunc;

        const std::size_t functab_offset = 8 + ptr_sz;
        const std::size_t entry_size = 2 * ptr_sz;

        for (std::size_t i = 0; i < nfunc; ++i) {
            const std::size_t cur_entry = functab_offset + i * entry_size;
            if (cur_entry + entry_size > max_len) break;

            const std::uint64_t func_va = read_uintptr(p + cur_entry, ptr_sz);
            const std::uint64_t func_data_off = read_uintptr(p + cur_entry + ptr_sz, ptr_sz);

            if (func_data_off + ptr_sz + 4 > max_len) continue;

            const std::int32_t name_off = read_i32(p + func_data_off + ptr_sz);
            if (name_off <= 0) continue;

            std::string name = read_pcln_string(static_cast<std::size_t>(name_off));
            if (name.empty()) continue;

            GoFunction fn;
            fn.name = name;
            fn.entry_va = func_va;
            fn.package_name = extract_package(name);

            if (!fn.package_name.empty()) {
                unique_pkgs.insert(fn.package_name);
            }

            if (fn.package_name.starts_with("runtime") || fn.package_name.starts_with("internal/") ||
                fn.name.starts_with("type..") || fn.name.starts_with("go.")) {
                report.runtime_functions++;
            } else {
                report.user_functions++;
            }

            report.functions.push_back(std::move(fn));
        }
    } else if (report.version == GoPclnVersion::go116) {
        if (max_len < 8 + 7 * ptr_sz) return report;
        const std::uint64_t nfunc_raw = read_uintptr(p + 8, ptr_sz);
        const std::size_t nfunc = static_cast<std::size_t>(std::min<std::uint64_t>(nfunc_raw, 250000));
        report.function_count = nfunc;

        const std::size_t funcnametab_off = static_cast<std::size_t>(read_uintptr(p + 8 + 2 * ptr_sz, ptr_sz));
        const std::size_t functab_off = static_cast<std::size_t>(read_uintptr(p + 8 + 6 * ptr_sz, ptr_sz));
        const std::size_t entry_size = 2 * ptr_sz;

        for (std::size_t i = 0; i < nfunc; ++i) {
            const std::size_t cur_entry = functab_off + i * entry_size;
            if (cur_entry + entry_size > max_len) break;

            const std::uint64_t func_va = read_uintptr(p + cur_entry, ptr_sz);
            const std::uint64_t func_data_off = read_uintptr(p + cur_entry + ptr_sz, ptr_sz);

            if (functab_off + func_data_off + ptr_sz + 4 > max_len) continue;

            const std::int32_t name_off = read_i32(p + functab_off + func_data_off + ptr_sz);
            if (name_off < 0) continue;

            std::string name = read_pcln_string(funcnametab_off + static_cast<std::size_t>(name_off));
            if (name.empty()) continue;

            GoFunction fn;
            fn.name = name;
            fn.entry_va = func_va;
            fn.package_name = extract_package(name);

            if (!fn.package_name.empty()) {
                unique_pkgs.insert(fn.package_name);
            }

            if (fn.package_name.starts_with("runtime") || fn.package_name.starts_with("internal/") ||
                fn.name.starts_with("type..") || fn.name.starts_with("go.")) {
                report.runtime_functions++;
            } else {
                report.user_functions++;
            }

            report.functions.push_back(std::move(fn));
        }
    } else { // Go 1.18+
        if (max_len < 8 + 8 * ptr_sz) return report;
        const std::uint64_t nfunc_raw = read_uintptr(p + 8, ptr_sz);
        const std::size_t nfunc = static_cast<std::size_t>(std::min<std::uint64_t>(nfunc_raw, 250000));
        report.function_count = nfunc;

        const std::uint64_t text_start = read_uintptr(p + 8 + 2 * ptr_sz, ptr_sz);
        const std::size_t funcnametab_off = static_cast<std::size_t>(read_uintptr(p + 8 + 3 * ptr_sz, ptr_sz));
        const std::size_t functab_off = static_cast<std::size_t>(read_uintptr(p + 8 + 7 * ptr_sz, ptr_sz));
        const std::size_t entry_size = 2 * 4; // In Go 1.18+ functab entries are uint32 offsets

        for (std::size_t i = 0; i < nfunc; ++i) {
            const std::size_t cur_entry = functab_off + i * entry_size;
            if (cur_entry + entry_size > max_len) break;

            const std::uint32_t func_entry_delta = read_u32(p + cur_entry);
            const std::uint32_t func_data_off = read_u32(p + cur_entry + 4);

            const std::uint64_t func_va = text_start + func_entry_delta;

            if (functab_off + func_data_off + 8 > max_len) continue;

            const std::int32_t name_off = read_i32(p + functab_off + func_data_off + 4);
            if (name_off < 0) continue;

            std::string name = read_pcln_string(funcnametab_off + static_cast<std::size_t>(name_off));
            if (name.empty()) continue;

            GoFunction fn;
            fn.name = name;
            fn.entry_va = func_va;
            fn.package_name = extract_package(name);

            if (!fn.package_name.empty()) {
                unique_pkgs.insert(fn.package_name);
            }

            if (fn.package_name.starts_with("runtime") || fn.package_name.starts_with("internal/") ||
                fn.name.starts_with("type..") || fn.name.starts_with("go.")) {
                report.runtime_functions++;
            } else {
                report.user_functions++;
            }

            report.functions.push_back(std::move(fn));
        }
    }

    report.packages.assign(unique_pkgs.begin(), unique_pkgs.end());
    return report;
}

GoAnalysisReport GoAnalyzer::analyze(const core::ExecutableImage& image) const {
    const auto view = image.view();
    const auto bytes = view.bytes();

    // 1. Look for .gopclntab section
    const auto* gopcln_sec = image.find_section(".gopclntab");
    if (gopcln_sec != nullptr && gopcln_sec->file_size >= 16) {
        const std::size_t off = static_cast<std::size_t>(gopcln_sec->file_offset);
        const std::size_t len = static_cast<std::size_t>(gopcln_sec->file_size);
        if (off + len <= bytes.size()) {
            auto rep = parse_pclntab(image, bytes.data(), off, len, gopcln_sec->virtual_address);
            if (rep.detected) return rep;
        }
    }

    // 2. Scan read-only and code sections for magic header
    for (const auto& sec : image.sections()) {
        if (sec.writable() || sec.file_size < 32) continue;
        const std::size_t s_off = static_cast<std::size_t>(sec.file_offset);
        const std::size_t s_len = static_cast<std::size_t>(sec.file_size);
        if (s_off + s_len > bytes.size()) continue;

        for (std::size_t i = s_off; i + 32 <= s_off + s_len; i += 4) {
            const std::uint32_t magic = read_u32(bytes.data() + i);
            if (magic == 0xFFFFFFFB || magic == 0xFFFFFFFA || magic == 0xFFFFFFF0 || magic == 0xFFFFFFF1) {
                const std::uint8_t q = bytes[i + 6];
                const std::uint8_t ps = bytes[i + 7];
                if ((q == 1 || q == 4) && (ps == 4 || ps == 8)) {
                    const std::uint64_t va = sec.virtual_address + (i - sec.file_offset);
                    auto rep = parse_pclntab(image, bytes.data(), i, s_len - (i - s_off), va);
                    if (rep.detected && !rep.functions.empty()) {
                        return rep;
                    }
                }
            }
        }
    }

    return analyze_view(view);
}

GoAnalysisReport GoAnalyzer::analyze_view(const core::BinaryView& view) const {
    const auto bytes = view.bytes();
    GoAnalysisReport report;
    if (bytes.size() < 32) return report;

    for (std::size_t i = 0; i + 32 <= bytes.size(); i += 4) {
        const std::uint32_t magic = read_u32(bytes.data() + i);
        if (magic == 0xFFFFFFFB || magic == 0xFFFFFFFA || magic == 0xFFFFFFF0 || magic == 0xFFFFFFF1) {
            const std::uint8_t q = bytes[i + 6];
            const std::uint8_t ps = bytes[i + 7];
            if ((q == 1 || q == 4) && (ps == 4 || ps == 8)) {
                core::ExecutableImage dummy;
                auto rep = parse_pclntab(dummy, bytes.data(), i, bytes.size() - i, i);
                if (rep.detected && !rep.functions.empty()) {
                    return rep;
                }
            }
        }
    }
    return report;
}

}  // namespace typemorph::golang

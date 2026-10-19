// TypeMorph - Golang pclntab & Symbol Metadata Reconstructor.
#include "typemorph/go/go_analyzer.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

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

namespace {

constexpr std::uint8_t kKindBool = 1;
constexpr std::uint8_t kKindInt = 2;
constexpr std::uint8_t kKindInt8 = 3;
constexpr std::uint8_t kKindInt16 = 4;
constexpr std::uint8_t kKindInt32 = 5;
constexpr std::uint8_t kKindInt64 = 6;
constexpr std::uint8_t kKindUint = 7;
constexpr std::uint8_t kKindUint8 = 8;
constexpr std::uint8_t kKindUint16 = 9;
constexpr std::uint8_t kKindUint32 = 10;
constexpr std::uint8_t kKindUint64 = 11;
constexpr std::uint8_t kKindUintptr = 12;
constexpr std::uint8_t kKindFloat32 = 13;
constexpr std::uint8_t kKindFloat64 = 14;
constexpr std::uint8_t kKindComplex64 = 15;
constexpr std::uint8_t kKindComplex128 = 16;
constexpr std::uint8_t kKindArray = 17;
constexpr std::uint8_t kKindChan = 18;
constexpr std::uint8_t kKindFunc = 19;
constexpr std::uint8_t kKindInterface = 20;
constexpr std::uint8_t kKindMap = 21;
constexpr std::uint8_t kKindPtr = 22;
constexpr std::uint8_t kKindSlice = 23;
constexpr std::uint8_t kKindString = 24;
constexpr std::uint8_t kKindStruct = 25;
constexpr std::uint8_t kKindUnsafePointer = 26;
constexpr std::uint8_t kKindMask = 0x1F;

std::string kind_to_name(std::uint8_t kind) {
    switch (kind & kKindMask) {
    case kKindBool: return "bool";
    case kKindInt: return "int";
    case kKindInt8: return "int8";
    case kKindInt16: return "int16";
    case kKindInt32: return "int32";
    case kKindInt64: return "int64";
    case kKindUint: return "uint";
    case kKindUint8: return "uint8";
    case kKindUint16: return "uint16";
    case kKindUint32: return "uint32";
    case kKindUint64: return "uint64";
    case kKindUintptr: return "uintptr";
    case kKindFloat32: return "float32";
    case kKindFloat64: return "float64";
    case kKindComplex64: return "complex64";
    case kKindComplex128: return "complex128";
    case kKindArray: return "[]any";
    case kKindChan: return "chan any";
    case kKindFunc: return "func()";
    case kKindInterface: return "interface{}";
    case kKindMap: return "map[any]any";
    case kKindPtr: return "*any";
    case kKindSlice: return "[]byte";
    case kKindString: return "string";
    case kKindStruct: return "struct";
    case kKindUnsafePointer: return "unsafe.Pointer";
    default: return "any";
    }
}

std::string read_go_name(const std::uint8_t* base, std::size_t offset, std::size_t max_size) {
    if (offset >= max_size) return {};
    const std::uint8_t* p = base + offset;
    std::size_t cur = 1;
    if (offset + cur >= max_size) return {};
    std::size_t name_len = 0;
    if ((p[cur] & 0x80) != 0) {
        if (offset + cur + 1 >= max_size) return {};
        name_len = ((static_cast<std::size_t>(p[cur] & 0x7F) << 8U) | p[cur + 1]);
        cur += 2;
    } else {
        name_len = p[cur];
        cur += 1;
    }
    if (name_len == 0 || offset + cur + name_len > max_size) return {};
    return std::string(reinterpret_cast<const char*>(p + cur), name_len);
}

}  // namespace

std::string GoAnalyzer::to_golang_source(const GoAnalysisReport& report) {
    if (!report.detected && report.structs.empty() && report.interfaces.empty() && report.functions.empty()) {
        return "// No Golang runtime metadata detected\n";
    }

    std::ostringstream ss;
    ss << "// Reconstructed with TypeMorph v0.7.0\n"
       << "// Target: Golang runtime (" << to_string(report.version) << ")\n"
       << "// Functions: " << report.function_count
       << ", Structs: " << report.structs.size()
       << ", Interfaces: " << report.interfaces.size()
       << ", itabs: " << report.itabs.size() << "\n\n"
       << "package main\n\n"
       << "import (\n"
       << "    \"unsafe\"\n"
       << ")\n\n"
       << "var _ = unsafe.Sizeof(0)\n\n";

    // 1. Interfaces
    if (!report.interfaces.empty()) {
        ss << "// ============================================================================\n"
           << "// Reconstructed Interfaces (" << report.interfaces.size() << ")\n"
           << "// ============================================================================\n\n";

        for (const auto& iface : report.interfaces) {
            ss << "// Interface VA: 0x" << std::hex << iface.type_va << std::dec << "\n"
               << "type " << iface.name << " interface {\n";
            for (const auto& m : iface.methods) {
                ss << "    " << m.name << "()\n";
            }
            ss << "}\n\n";
        }
    }

    // 2. Structs
    if (!report.structs.empty()) {
        ss << "// ============================================================================\n"
           << "// Reconstructed Struct Types (" << report.structs.size() << ")\n"
           << "// ============================================================================\n\n";

        for (const auto& s : report.structs) {
            ss << "// Struct VA: 0x" << std::hex << s.type_va << std::dec
               << " (Size: " << s.size << " bytes)\n"
               << "type " << s.name << " struct {\n";
            for (const auto& f : s.fields) {
                ss << "    " << f.name << " " << f.type_name;
                if (!f.tag.empty()) {
                    ss << " `" << f.tag << "`";
                }
                ss << " // +0x" << std::hex << f.offset << std::dec << "\n";
            }
            ss << "}\n\n";
        }
    }

    // 3. itabs / Interface implementations
    if (!report.itabs.empty()) {
        ss << "// ============================================================================\n"
           << "// Interface Implementations (itabs) (" << report.itabs.size() << ")\n"
           << "// ============================================================================\n\n";

        for (const auto& itab : report.itabs) {
            ss << "// itab: " << itab.concrete_type_name << " implements " << itab.interface_name
               << " (itab VA: 0x" << std::hex << itab.itab_va << std::dec << ")\n";
            for (const auto& m : itab.methods) {
                ss << "func (recv *" << itab.concrete_type_name << ") " << m.name << "() {\n"
                   << "    // Method VA: 0x" << std::hex << m.fn_va << std::dec << "\n"
                   << "}\n\n";
            }
        }
    }

    // 4. User Functions
    if (!report.functions.empty()) {
        ss << "// ============================================================================\n"
           << "// Recovered Functions (" << report.functions.size() << ")\n"
           << "// ============================================================================\n\n";

        std::size_t emitted = 0;
        for (const auto& fn : report.functions) {
            if (fn.name.starts_with("runtime.") || fn.name.starts_with("type..")) continue;
            ss << "// VA: 0x" << std::hex << fn.entry_va << std::dec
               << " (Frame: " << fn.frame_size << "B, Args: " << fn.args_size << "B)\n"
               << "// Package: " << fn.package_name << "\n"
               << "func " << fn.name << "() {\n"
               << "    // Body stub\n"
               << "}\n\n";
            if (++emitted >= 50) {
                ss << "// ... and " << (report.functions.size() - emitted) << " more functions.\n";
                break;
            }
        }
    }

    return ss.str();
}

void GoAnalyzer::recover_types(const core::ExecutableImage& image, GoAnalysisReport& report) const {
    const auto view = image.view();
    const auto bytes = view.bytes();
    const std::size_t total_size = bytes.size();
    const std::size_t ptr_sz = report.ptr_size != 0 ? report.ptr_size : 8;

    std::uint64_t types_base_va = 0;
    std::size_t types_base_offset = 0;

    // 1. Check if we can locate runtime.firstmoduledata by finding report.pclntab_va in data sections
    if (report.pclntab_va != 0) {
        for (const auto& sec : image.sections()) {
            if (sec.file_size < ptr_sz * 10) continue;
            const std::size_t s_off = static_cast<std::size_t>(sec.file_offset);
            const std::size_t s_len = static_cast<std::size_t>(sec.file_size);
            if (s_off + s_len > total_size) continue;

            for (std::size_t i = s_off; i + ptr_sz * 15 <= s_off + s_len; i += ptr_sz) {
                const std::uint64_t w = read_uintptr(bytes.data() + i, ptr_sz);
                if (w == report.pclntab_va) {
                    for (std::size_t m = i; m < i + ptr_sz * 35 && m + ptr_sz <= s_off + s_len; m += ptr_sz) {
                        const std::uint64_t candidate_types = read_uintptr(bytes.data() + m, ptr_sz);
                        auto off_res = image.va_to_offset(candidate_types, 64);
                        if (off_res && off_res.value() < total_size) {
                            const auto* target_sec = image.section_for_address(candidate_types);
                            if (target_sec && !target_sec->executable() && !target_sec->writable()) {
                                types_base_va = candidate_types;
                                types_base_offset = off_res.value();
                                break;
                            }
                        }
                    }
                    if (types_base_va != 0) break;
                }
            }
            if (types_base_va != 0) break;
        }
    }

    if (types_base_va == 0) {
        const auto* rosec = image.find_section(".rodata");
        if (rosec != nullptr) {
            types_base_va = rosec->virtual_address;
            types_base_offset = static_cast<std::size_t>(rosec->file_offset);
        }
    }

    // 2. Scan for itab records
    for (const auto& sec : image.sections()) {
        if (sec.executable() || sec.file_size < ptr_sz * 4) continue;
        const std::size_t s_off = static_cast<std::size_t>(sec.file_offset);
        const std::size_t s_len = static_cast<std::size_t>(sec.file_size);
        if (s_off + s_len > total_size) continue;

        for (std::size_t i = s_off; i + ptr_sz * 4 <= s_off + s_len; i += ptr_sz) {
            const std::uint64_t inter_va = read_uintptr(bytes.data() + i, ptr_sz);
            const std::uint64_t type_va = read_uintptr(bytes.data() + i + ptr_sz, ptr_sz);
            if (inter_va == 0 || type_va == 0 || inter_va == type_va) continue;

            auto inter_off_res = image.va_to_offset(inter_va, 32);
            auto type_off_res = image.va_to_offset(type_va, 32);
            if (!inter_off_res || !type_off_res) continue;

            const std::size_t inter_off = inter_off_res.value();
            const std::size_t type_off = type_off_res.value();
            if (inter_off + 48 > total_size || type_off + 48 > total_size) continue;

            const std::size_t kind_off = (ptr_sz == 8) ? 23 : 15;
            const std::uint8_t inter_kind = bytes[inter_off + kind_off] & kKindMask;
            const std::uint8_t type_kind = bytes[type_off + kind_off] & kKindMask;

            if (inter_kind == kKindInterface && type_kind != 0) {
                const std::uint64_t fn0_va = read_uintptr(bytes.data() + i + ptr_sz * 3, ptr_sz);
                const auto* fn_sec = image.section_for_address(fn0_va);
                if (fn_sec && fn_sec->executable()) {
                    GoITab itab;
                    itab.itab_va = sec.virtual_address + (i - s_off);

                    const std::size_t str_off_in_type = (ptr_sz == 8) ? 40 : 28;
                    const std::int32_t inter_name_off = read_i32(bytes.data() + inter_off + str_off_in_type);
                    const std::int32_t type_name_off = read_i32(bytes.data() + type_off + str_off_in_type);

                    std::string iname;
                    std::string tname;
                    if (types_base_offset != 0) {
                        iname = read_go_name(bytes.data(), types_base_offset + static_cast<std::size_t>(inter_name_off), total_size);
                        tname = read_go_name(bytes.data(), types_base_offset + static_cast<std::size_t>(type_name_off), total_size);
                    }
                    if (iname.empty()) iname = "Interface_" + std::to_string(report.itabs.size());
                    if (tname.empty()) tname = "Type_" + std::to_string(report.itabs.size());

                    itab.interface_name = iname;
                    itab.concrete_type_name = tname;

                    for (std::size_t m = 0; m < 32; ++m) {
                        const std::size_t f_off = i + ptr_sz * 3 + m * ptr_sz;
                        if (f_off + ptr_sz > s_off + s_len) break;
                        const std::uint64_t cur_fn_va = read_uintptr(bytes.data() + f_off, ptr_sz);
                        const auto* cur_sec = image.section_for_address(cur_fn_va);
                        if (!cur_sec || !cur_sec->executable()) break;

                        GoMethod meth;
                        meth.fn_va = cur_fn_va;
                        for (const auto& sym : image.symbols()) {
                            if (sym.address == cur_fn_va) {
                                meth.name = sym.name;
                                break;
                            }
                        }
                        if (meth.name.empty()) {
                            meth.name = "Method" + std::to_string(m);
                        }
                        itab.methods.push_back(std::move(meth));
                    }

                    report.itabs.push_back(std::move(itab));
                }
            }
        }
    }

    // 3. Scan for structtype records in read-only data
    for (const auto& sec : image.sections()) {
        if (sec.executable() || sec.writable() || sec.file_size < 64) continue;
        const std::size_t s_off = static_cast<std::size_t>(sec.file_offset);
        const std::size_t s_len = static_cast<std::size_t>(sec.file_size);
        if (s_off + s_len > total_size) continue;

        for (std::size_t i = s_off; i + 64 <= s_off + s_len; i += ptr_sz) {
            const std::size_t kind_off = (ptr_sz == 8) ? 23 : 15;
            if (i + kind_off >= total_size) break;
            const std::uint8_t kind = bytes[i + kind_off] & kKindMask;
            if (kind != kKindStruct) continue;

            const std::uint64_t struct_size = read_uintptr(bytes.data() + i, ptr_sz);
            if (struct_size == 0 || struct_size > 1000000) continue;

            const std::uint8_t align = bytes[i + ((ptr_sz == 8) ? 21 : 13)];
            if (align != 1 && align != 2 && align != 4 && align != 8 && align != 16) continue;

            const std::size_t fields_slice_off = (ptr_sz == 8) ? (i + 56) : (i + 36);
            if (fields_slice_off + ptr_sz * 3 > s_off + s_len) continue;

            const std::uint64_t fields_ptr = read_uintptr(bytes.data() + fields_slice_off, ptr_sz);
            const std::uint64_t fields_len = read_uintptr(bytes.data() + fields_slice_off + ptr_sz, ptr_sz);

            if (fields_len > 0 && fields_len <= 100) {
                auto farr_off_res = image.va_to_offset(fields_ptr, fields_len * 16);
                if (farr_off_res && farr_off_res.value() < total_size) {
                    GoStructType st;
                    st.type_va = sec.virtual_address + (i - s_off);
                    st.size = struct_size;

                    const std::size_t str_off_in_type = (ptr_sz == 8) ? 40 : 28;
                    const std::int32_t name_off = read_i32(bytes.data() + i + str_off_in_type);
                    if (types_base_offset != 0) {
                        st.name = read_go_name(bytes.data(), types_base_offset + static_cast<std::size_t>(name_off), total_size);
                    }
                    if (st.name.empty()) {
                        st.name = "Struct_" + std::to_string(report.structs.size());
                    }

                    const std::size_t f_size = (ptr_sz == 8) ? 24 : 12;
                    const std::size_t f_base = farr_off_res.value();

                    for (std::size_t f = 0; f < fields_len; ++f) {
                        if (f_base + (f + 1) * f_size > total_size) break;
                        const std::size_t cf_off = f_base + f * f_size;
                        const std::int32_t fn_name_off = read_i32(bytes.data() + cf_off);
                        const std::uint64_t field_offset = read_uintptr(bytes.data() + cf_off + f_size - ptr_sz, ptr_sz);

                        GoField fld;
                        fld.offset = field_offset;
                        if (types_base_offset != 0) {
                            fld.name = read_go_name(bytes.data(), types_base_offset + static_cast<std::size_t>(fn_name_off), total_size);
                        }
                        if (fld.name.empty()) {
                            fld.name = "Field_" + std::to_string(f);
                        }
                        fld.type_name = "uintptr";
                        st.fields.push_back(std::move(fld));
                    }

                    report.structs.push_back(std::move(st));
                }
            }
        }
    }
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
            if (rep.detected) {
                recover_types(image, rep);
                rep.golang_source = to_golang_source(rep);
                return rep;
            }
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
                        recover_types(image, rep);
                        rep.golang_source = to_golang_source(rep);
                        return rep;
                    }
                }
            }
        }
    }

    auto rep = analyze_view(view);
    if (rep.detected) {
        recover_types(image, rep);
        rep.golang_source = to_golang_source(rep);
    }
    return rep;
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
                    rep.golang_source = to_golang_source(rep);
                    return rep;
                }
            }
        }
    }
    return report;
}

}  // namespace typemorph::golang

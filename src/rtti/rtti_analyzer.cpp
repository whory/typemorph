// TypeMorph - C++ RTTI & Class Hierarchy Analyzer implementation.
#include "typemorph/rtti/rtti_analyzer.hpp"
#include "typemorph/derust/demangle.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>

namespace typemorph::rtti {
namespace {

inline std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::int32_t read_i32(const std::uint8_t* p) noexcept {
    return static_cast<std::int32_t>(read_u32(p));
}

inline std::uint64_t read_u64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(read_u32(p)) |
           (static_cast<std::uint64_t>(read_u32(p + 4)) << 32);
}

}  // namespace

std::string RttiAnalyzer::demangle_msvc_typename(std::string_view mangled) {
    if (mangled.empty()) return {};

    std::string_view s = mangled;
    if (s.starts_with(".?AV") || s.starts_with(".?AU")) {
        s.remove_prefix(4);
    } else if (s.starts_with("?AV") || s.starts_with("?AU")) {
        s.remove_prefix(3);
    }

    auto pos = s.find("@@");
    if (pos != std::string_view::npos) {
        s = s.substr(0, pos);
    }

    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start < s.size()) {
        auto at = s.find('@', start);
        if (at == std::string_view::npos) {
            parts.emplace_back(s.substr(start));
            break;
        }
        parts.emplace_back(s.substr(start, at - start));
        start = at + 1;
    }

    if (parts.empty()) return std::string(mangled);

    std::reverse(parts.begin(), parts.end());

    std::string result;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (parts[i].empty()) continue;
        if (!result.empty()) result += "::";
        result += parts[i];
    }

    return result.empty() ? std::string(mangled) : result;
}

std::vector<RttiClass> RttiAnalyzer::analyze_msvc(const core::ExecutableImage& image) const {
    std::vector<RttiClass> results;
    const auto view = image.view();
    const auto bytes = view.bytes();
    const bool is_64 = (image.bits() == 64);
    const std::uint64_t image_base = image.image_base();

    // Helper to read null-terminated string at VA
    auto read_string_at_va = [&](std::uint64_t va, std::size_t max_len = 128) -> std::string {
        auto off_res = image.va_to_offset(va);
        if (!off_res) return {};
        std::size_t off = static_cast<std::size_t>(off_res.value());
        if (off >= bytes.size()) return {};
        std::size_t end = std::min(bytes.size(), off + max_len);
        std::string s;
        for (std::size_t i = off; i < end; ++i) {
            if (bytes[i] == '\0') break;
            s.push_back(static_cast<char>(bytes[i]));
        }
        return s;
    };

    // Helper to read bytes at VA
    auto read_bytes_at_va = [&](std::uint64_t va, std::size_t len) -> const std::uint8_t* {
        auto off_res = image.va_to_offset(va);
        if (!off_res) return nullptr;
        std::size_t off = static_cast<std::size_t>(off_res.value());
        if (off + len > bytes.size()) return nullptr;
        return bytes.data() + off;
    };

    // Scan for RTTICompleteObjectLocator structures in read-only / data sections
    std::set<std::uint64_t> seen_locators;

    for (const auto& sec : image.sections()) {
        if (sec.executable() || sec.file_size < 24) continue;
        const std::size_t start = static_cast<std::size_t>(sec.file_offset);
        const std::size_t len = static_cast<std::size_t>(sec.file_size);
        if (start + len > bytes.size()) continue;

        for (std::size_t i = start; i + (is_64 ? 24 : 20) <= start + len; i += 4) {
            const std::uint32_t sig = read_u32(bytes.data() + i);
            if (is_64 && sig != 1) continue; // 64-bit MSVC locator signature is 1
            if (!is_64 && sig != 0) continue; // 32-bit MSVC locator signature is 0

            const std::uint32_t offset = read_u32(bytes.data() + i + 4);
            if (offset != 0) continue; // Primary vtable offset is 0

            std::uint64_t type_desc_va = 0;
            std::uint64_t class_desc_va = 0;

            if (is_64) {
                const std::int32_t type_desc_rva = read_i32(bytes.data() + i + 12);
                const std::int32_t class_desc_rva = read_i32(bytes.data() + i + 16);
                if (type_desc_rva <= 0) continue;
                type_desc_va = image_base + static_cast<std::uint32_t>(type_desc_rva);
                if (class_desc_rva > 0) {
                    class_desc_va = image_base + static_cast<std::uint32_t>(class_desc_rva);
                }
            } else {
                type_desc_va = read_u32(bytes.data() + i + 12);
                class_desc_va = read_u32(bytes.data() + i + 16);
                if (type_desc_va < image_base) continue;
            }

            // Verify TypeDescriptor at type_desc_va
            // In 64-bit: pVFTable (8 bytes), spare (8 bytes), name string (.?A...)
            // In 32-bit: pVFTable (4 bytes), spare (4 bytes), name string (.?A...)
            const std::size_t name_offset = is_64 ? 16 : 8;
            auto raw_name = read_string_at_va(type_desc_va + name_offset);
            if (!raw_name.starts_with(".?A") && !raw_name.starts_with("?A")) continue;

            const std::uint64_t locator_va = sec.virtual_address + (i - sec.file_offset);
            if (!seen_locators.insert(locator_va).second) continue;

            RttiClass cls;
            cls.mangled_name = raw_name;
            cls.name = demangle_msvc_typename(raw_name);
            cls.locator_va = locator_va;

            // Read base classes from ClassHierarchyDescriptor
            if (class_desc_va >= image_base) {
                const auto* ch_bytes = read_bytes_at_va(class_desc_va, 16);
                if (ch_bytes) {
                const std::uint32_t num_bases = read_u32(ch_bytes + 8);
                if (num_bases > 1 && num_bases <= 64) {
                    std::uint64_t base_array_va = 0;
                    if (is_64) {
                        const std::int32_t base_array_rva = read_i32(ch_bytes + 12);
                        if (base_array_rva > 0) base_array_va = image_base + static_cast<std::uint32_t>(base_array_rva);
                    } else {
                        base_array_va = read_u32(ch_bytes + 12);
                    }

                    if (base_array_va >= image_base) {
                        for (std::uint32_t b = 1; b < num_bases; ++b) {
                            const auto* ba_entry = read_bytes_at_va(base_array_va + b * 4, 4);
                            if (!ba_entry) break;

                            std::uint64_t bcd_va = 0;
                            if (is_64) {
                                const std::int32_t bcd_rva = read_i32(ba_entry);
                                if (bcd_rva > 0) bcd_va = image_base + static_cast<std::uint32_t>(bcd_rva);
                            } else {
                                bcd_va = read_u32(ba_entry);
                            }

                            const auto* bcd_bytes = read_bytes_at_va(bcd_va, 24);
                            if (!bcd_bytes) continue;

                            std::uint64_t base_td_va = 0;
                            if (is_64) {
                                const std::int32_t base_td_rva = read_i32(bcd_bytes);
                                if (base_td_rva > 0) base_td_va = image_base + static_cast<std::uint32_t>(base_td_rva);
                            } else {
                                base_td_va = read_u32(bcd_bytes);
                            }

                            const std::int32_t mdisp = read_i32(bcd_bytes + 8);
                            auto base_raw_name = read_string_at_va(base_td_va + name_offset);
                            if (base_raw_name.starts_with(".?A") || base_raw_name.starts_with("?A")) {
                                RttiBaseClass base_entry;
                                base_entry.mangled_name = base_raw_name;
                                base_entry.name = demangle_msvc_typename(base_raw_name);
                                base_entry.offset = mdisp;
                                cls.base_classes.push_back(std::move(base_entry));
                            }
                        }
                    }
                }
            }
            }

            // Find vftable: Search for pointer containing locator_va
            const std::size_t ptr_size = is_64 ? 8 : 4;
            for (const auto& data_sec : image.sections()) {
                if (data_sec.executable()) continue;
                const std::size_t d_start = static_cast<std::size_t>(data_sec.file_offset);
                const std::size_t d_len = static_cast<std::size_t>(data_sec.file_size);
                if (d_start + d_len > bytes.size()) continue;

                for (std::size_t p = d_start; p + ptr_size <= d_start + d_len; p += ptr_size) {
                    const std::uint64_t val = is_64 ? read_u64(bytes.data() + p) : read_u32(bytes.data() + p);
                    if (val == locator_va) {
                        cls.vftable_va = data_sec.virtual_address + ((p + ptr_size) - data_sec.file_offset);

                        // Read virtual methods
                        for (std::size_t slot = 0; slot < 64; ++slot) {
                            const std::uint64_t method_slot_va = cls.vftable_va + slot * ptr_size;
                            const auto* m_bytes = read_bytes_at_va(method_slot_va, ptr_size);
                            if (!m_bytes) break;

                            const std::uint64_t m_va = is_64 ? read_u64(m_bytes) : read_u32(m_bytes);
                            const auto* m_sec = image.section_for_address(m_va);
                            if (!m_sec || !m_sec->executable()) break;

                            char name_buf[64];
                            std::snprintf(name_buf, sizeof(name_buf), "sub_%llX", static_cast<unsigned long long>(m_va));
                            cls.methods.push_back({slot, m_va, name_buf});
                        }
                        break;
                    }
                }
                if (cls.vftable_va != 0) break;
            }

            results.push_back(std::move(cls));
        }
    }

    return results;
}

std::vector<RttiClass> RttiAnalyzer::analyze_itanium(const core::ExecutableImage& image) const {
    std::vector<RttiClass> results;

    // Scan for _ZTV symbols in symbol table
    for (const auto& sym : image.symbols()) {
        if (sym.name.starts_with("_ZTV")) {
            // vtable for Class
            std::string demangled = derust::demangle_or_original(sym.name);
            RttiClass cls;
            cls.mangled_name = sym.name;
            cls.name = demangled.starts_with("vtable for ") ? demangled.substr(11) : demangled;
            cls.vftable_va = sym.address;
            results.push_back(std::move(cls));
        }
    }

    return results;
}

std::vector<RttiClass> RttiAnalyzer::analyze(const core::ExecutableImage& image) const {
    if (image.format() == core::ImageFormat::pe) {
        return analyze_msvc(image);
    }
    return analyze_itanium(image);
}

std::vector<RttiClass> RttiAnalyzer::analyze_view(const core::BinaryView& view) const {
    auto img_res = core::ExecutableImage::parse(view);
    if (!img_res) return {};
    return analyze(img_res.value());
}

std::string RttiAnalyzer::to_cpp_header(const std::vector<RttiClass>& classes) {
    std::string out;
    out += "// Automatically reconstructed C++ class hierarchy from RTTI\n";
    out += "#pragma once\n\n";
    out += "#include <cstdint>\n\n";

    for (const auto& cls : classes) {
        out += "class " + cls.name;
        if (!cls.base_classes.empty()) {
            out += " : ";
            for (std::size_t i = 0; i < cls.base_classes.size(); ++i) {
                if (i > 0) out += ", ";
                out += "public " + cls.base_classes[i].name;
            }
        }
        out += " {\npublic:\n";
        out += "    virtual ~" + cls.name + "() = default;\n";
        for (const auto& m : cls.methods) {
            char va_buf[32];
            std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(m.virtual_address));
            out += "    virtual void " + m.name + "(); // slot " + std::to_string(m.slot) + " (" + va_buf + ")\n";
        }
        out += "};\n\n";
    }
    return out;
}

}  // namespace typemorph::rtti

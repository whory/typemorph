// TypeMorph - .NET / C# Metadata & Code Reconstructor.
#include "typemorph/dotnet/dotnet_analyzer.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>

namespace typemorph::dotnet {

namespace {

inline std::uint16_t load16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8U);
}

inline std::uint32_t load32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) |
           (static_cast<std::uint32_t>(p[3]) << 24U);
}

inline std::uint64_t load64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(load32(p)) |
           (static_cast<std::uint64_t>(load32(p + 4)) << 32U);
}

std::string get_string_from_heap(const std::uint8_t* heap, std::size_t heap_size, std::size_t offset) {
    if (offset >= heap_size) return {};
    const char* str = reinterpret_cast<const char*>(heap + offset);
    std::size_t max_len = heap_size - offset;
    std::size_t len = 0;
    while (len < max_len && str[len] != '\0') ++len;
    return std::string(str, len);
}

}  // namespace

std::string DotNetAnalyzer::to_csharp(const DotNetReport& report) {
    if (!report.is_dotnet || report.types.empty()) {
        return "// No .NET metadata detected\n";
    }

    std::ostringstream ss;
    ss << "// Decompiled with TypeMorph v0.6.0\n"
       << "// Target Runtime: " << report.runtime_version << "\n"
       << "// Types: " << report.types.size() << ", Methods: " << report.method_count
       << ", Fields: " << report.field_count << "\n\n"
       << "using System;\n"
       << "using System.Collections.Generic;\n"
       << "using System.Runtime.InteropServices;\n\n";

    // Group types by namespace
    std::map<std::string, std::vector<const DotNetType*>> by_ns;
    for (const auto& t : report.types) {
        by_ns[t.namespace_name].push_back(&t);
    }

    for (const auto& [ns, types] : by_ns) {
        const bool has_ns = !ns.empty();
        if (has_ns) {
            ss << "namespace " << ns << " {\n";
        }

        const std::string indent = has_ns ? "    " : "";
        for (const auto* t : types) {
            ss << indent;
            if (t->is_public) ss << "public ";
            else ss << "internal ";

            if (t->is_interface) ss << "interface ";
            else if (t->is_enum) ss << "enum ";
            else {
                if (t->is_abstract && t->is_sealed) ss << "static ";
                else if (t->is_abstract) ss << "abstract ";
                else if (t->is_sealed) ss << "sealed ";

                if (t->is_value_type) ss << "struct ";
                else ss << "class ";
            }

            ss << t->name;
            if (!t->base_type.empty() && t->base_type != "Object" && t->base_type != "ValueType") {
                ss << " : " << t->base_type;
            }
            ss << " {\n";

            // Fields
            for (const auto& f : t->fields) {
                ss << indent << "    ";
                if (f.is_public) ss << "public ";
                else if (f.is_private) ss << "private ";
                else ss << "internal ";

                if (f.is_static) ss << "static ";
                if (f.is_readonly) ss << "readonly ";

                ss << f.type_name << " " << f.name << ";\n";
            }

            if (!t->fields.empty() && !t->methods.empty()) {
                ss << "\n";
            }

            // Methods
            for (const auto& m : t->methods) {
                ss << indent << "    ";
                if (!t->is_interface) {
                    if (m.is_public) ss << "public ";
                    else if (m.is_private) ss << "private ";
                    else ss << "internal ";

                    if (m.is_static) ss << "static ";
                    else if (m.is_virtual) ss << "virtual ";
                }

                if (m.is_constructor) {
                    ss << t->name << "(";
                } else {
                    ss << m.return_type << " " << m.name << "(";
                }

                for (std::size_t pi = 0; pi < m.parameters.size(); ++pi) {
                    if (pi > 0) ss << ", ";
                    ss << m.parameters[pi].type_name << " " << m.parameters[pi].name;
                }

                if (t->is_interface) {
                    ss << ");\n";
                } else {
                    ss << ") { /* IL RVA: 0x" << std::hex << m.rva << std::dec << " */ }\n";
                }
            }

            ss << indent << "}\n\n";
        }

        if (has_ns) {
            ss << "}\n\n";
        }
    }

    return ss.str();
}

DotNetReport DotNetAnalyzer::analyze_view(const core::BinaryView& view) const {
    auto image_res = core::ExecutableImage::parse(view);
    if (!image_res) {
        return {};
    }
    return analyze(image_res.value());
}

DotNetReport DotNetAnalyzer::analyze(const core::ExecutableImage& image) const {
    DotNetReport report;
    if (image.format() != core::ImageFormat::pe) {
        return report;
    }

    const auto& view = image.view();
    const std::uint64_t file_size = view.size();
    const std::uint8_t* data = view.data();

    if (file_size < 0x40 || data[0] != 'M' || data[1] != 'Z') return report;
    const std::uint32_t pe_offset = load32(data + 0x3C);
    if (pe_offset + 24 >= file_size || data[pe_offset] != 'P' || data[pe_offset + 1] != 'E') return report;

    const std::uint16_t opt_size = load16(data + pe_offset + 20);
    const std::uint64_t opt_offset = static_cast<std::uint64_t>(pe_offset) + 24U;
    if (opt_offset + opt_size > file_size || opt_size < 96) return report;

    const std::uint16_t opt_magic = load16(data + opt_offset);
    const bool is_pe32plus = (opt_magic == 0x20B);
    const std::uint64_t data_dir_offset = opt_offset + (is_pe32plus ? 112U : 96U);

    // Entry 14 is IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (.NET CLI Header)
    constexpr std::size_t kComDescriptorIndex = 14;
    const std::uint64_t clr_dir_entry = data_dir_offset + kComDescriptorIndex * 8U;
    if (clr_dir_entry + 8 > file_size) return report;

    const std::uint32_t clr_rva = load32(data + clr_dir_entry);
    const std::uint32_t clr_size = load32(data + clr_dir_entry + 4);
    if (clr_rva == 0 || clr_size < 72) {
        return report; // Not a .NET executable
    }

    auto clr_offset_res = image.va_to_offset(image.image_base() + clr_rva, clr_size);
    if (!clr_offset_res) return report;
    const std::uint64_t clr_offset = clr_offset_res.value();
    if (clr_offset + 72 > file_size) return report;

    const std::uint8_t* cor20 = data + clr_offset;
    const std::uint32_t meta_rva = load32(cor20 + 8);
    const std::uint32_t meta_size = load32(cor20 + 12);
    const std::uint32_t ep_token = load32(cor20 + 20);

    if (meta_rva == 0 || meta_size < 16) return report;
    auto meta_offset_res = image.va_to_offset(image.image_base() + meta_rva, meta_size);
    if (!meta_offset_res) return report;
    const std::uint64_t meta_offset = meta_offset_res.value();
    if (meta_offset + meta_size > file_size) return report;

    return parse_metadata(data, file_size, meta_offset, meta_size, "", clr_rva, meta_rva, ep_token);
}

DotNetReport DotNetAnalyzer::parse_metadata(
    const std::uint8_t* data,
    std::size_t file_size,
    std::uint64_t meta_offset,
    std::uint64_t meta_size,
    const std::string& runtime_ver,
    std::uint32_t cli_rva,
    std::uint32_t meta_rva,
    std::uint32_t ep_token) const {

    (void)runtime_ver;
    DotNetReport report;
    report.is_dotnet = true;
    report.cli_header_rva = cli_rva;
    report.metadata_rva = meta_rva;
    report.entry_point_token = ep_token;

    if (meta_offset + 16 > file_size || meta_size < 16) return report;
    const std::uint8_t* bsjb = data + meta_offset;

    // Check BSJB magic (0x424A5342)
    if (load32(bsjb) != 0x424A5342) {
        return report;
    }

    const std::uint32_t v_len = load32(bsjb + 12);
    if (16 + v_len > meta_size) return report;

    report.runtime_version = std::string(reinterpret_cast<const char*>(bsjb + 16),
                                         std::min<std::size_t>(v_len, std::strlen(reinterpret_cast<const char*>(bsjb + 16))));

    // Stream count offset is after version string aligned to 4 bytes
    const std::size_t v_len_aligned = (v_len + 3U) & ~3U;
    const std::size_t streams_header_offset = 16 + v_len_aligned;
    if (streams_header_offset + 4 > meta_size) return report;

    const std::uint16_t stream_count = load16(bsjb + streams_header_offset + 2);

    std::size_t stream_scan = streams_header_offset + 4;
    std::uint64_t tbl_stream_offset = 0;
    std::uint64_t tbl_stream_size = 0;
    std::uint64_t str_heap_offset = 0;
    std::uint64_t str_heap_size = 0;
    std::uint64_t blob_heap_offset = 0;
    std::uint64_t blob_heap_size = 0;

    for (std::uint16_t s = 0; s < stream_count; ++s) {
        if (stream_scan + 8 > meta_size) break;
        const std::uint32_t s_off = load32(bsjb + stream_scan);
        const std::uint32_t s_sz = load32(bsjb + stream_scan + 4);
        stream_scan += 8;

        std::string s_name;
        while (stream_scan < meta_size && bsjb[stream_scan] != '\0') {
            s_name.push_back(static_cast<char>(bsjb[stream_scan]));
            stream_scan++;
        }
        stream_scan++; // skip null
        // Stream name is 4-byte aligned
        stream_scan = (stream_scan + 3U) & ~3U;

        if (s_name == "#~" || s_name == "#-") {
            tbl_stream_offset = meta_offset + s_off;
            tbl_stream_size = s_sz;
        } else if (s_name == "#Strings") {
            str_heap_offset = meta_offset + s_off;
            str_heap_size = s_sz;
        } else if (s_name == "#Blob") {
            blob_heap_offset = meta_offset + s_off;
            blob_heap_size = s_sz;
        }
    }

    if (tbl_stream_offset == 0 || tbl_stream_offset + 24 > file_size || str_heap_offset == 0) {
        return report;
    }

    const std::uint8_t* tbl_data = data + tbl_stream_offset;
    const std::uint8_t* str_heap = data + str_heap_offset;

    const std::uint8_t heap_sizes = tbl_data[6];
    const std::size_t str_idx_sz = (heap_sizes & 0x01) ? 4 : 2;
    const std::size_t blob_idx_sz = (heap_sizes & 0x04) ? 4 : 2;

    const std::uint64_t valid_mask = load64(tbl_data + 8);

    // Read row counts for each present table
    std::uint32_t row_counts[64] = {0};
    std::size_t rc_ptr = 24;
    for (int tid = 0; tid < 64; ++tid) {
        if ((valid_mask & (1ULL << tid)) != 0) {
            if (rc_ptr + 4 > tbl_stream_size) break;
            row_counts[tid] = load32(tbl_data + rc_ptr);
            rc_ptr += 4;
        }
    }

    auto read_idx = [](const std::uint8_t* p, std::size_t sz) -> std::uint32_t {
        return sz == 4 ? load32(p) : static_cast<std::uint32_t>(load16(p));
    };

    // Table indices
    constexpr int kTypeDef = 0x02;
    constexpr int kField = 0x04;
    constexpr int kMethodDef = 0x06;
    constexpr int kParam = 0x08;

    const std::size_t field_idx_sz = (row_counts[kField] >= 65536) ? 4 : 2;
    const std::size_t method_idx_sz = (row_counts[kMethodDef] >= 65536) ? 4 : 2;
    const std::size_t param_idx_sz = (row_counts[kParam] >= 65536) ? 4 : 2;

    // TypeDefOrRef coded index (2 tag bits)
    const std::uint32_t max_tdor = std::max({row_counts[kTypeDef], row_counts[0x01], row_counts[0x1B]});
    const std::size_t tdor_sz = (max_tdor >= (1U << 14U)) ? 4 : 2;

    // Table row sizes
    const std::size_t typedef_row_sz = 4 + str_idx_sz + str_idx_sz + tdor_sz + field_idx_sz + method_idx_sz;
    const std::size_t field_row_sz = 2 + str_idx_sz + blob_idx_sz;
    const std::size_t method_row_sz = 4 + 2 + 2 + str_idx_sz + blob_idx_sz + param_idx_sz;

    // Locate tables in stream
    std::size_t cur_table_offset = rc_ptr;
    std::size_t table_offsets[64] = {0};
    for (int tid = 0; tid < 64; ++tid) {
        if ((valid_mask & (1ULL << tid)) != 0) {
            table_offsets[tid] = cur_table_offset;
            std::size_t row_sz = 0;
            switch (tid) {
            case 0x00: row_sz = 2 + str_idx_sz + (heap_sizes & 0x02 ? 4 : 2) * 3; break; // Module
            case 0x01: row_sz = (row_counts[0x00] >= (1U << 14U) ? 4 : 2) + str_idx_sz + str_idx_sz; break; // TypeRef
            case kTypeDef: row_sz = typedef_row_sz; break;
            case kField: row_sz = field_row_sz; break;
            case kMethodDef: row_sz = method_row_sz; break;
            case kParam: row_sz = 2 + 2 + str_idx_sz; break;
            default: row_sz = 4; break; // Fallback estimate
            }
            cur_table_offset += row_counts[tid] * row_sz;
        }
    }

    const std::size_t n_typedefs = row_counts[kTypeDef];
    const std::size_t n_fields = row_counts[kField];
    const std::size_t n_methods = row_counts[kMethodDef];

    report.type_count = n_typedefs;
    report.field_count = n_fields;
    report.method_count = n_methods;

    const std::uint8_t* typedef_base = tbl_data + table_offsets[kTypeDef];
    const std::uint8_t* field_base = tbl_data + table_offsets[kField];
    const std::uint8_t* method_base = tbl_data + table_offsets[kMethodDef];

    for (std::size_t i = 0; i < n_typedefs; ++i) {
        const std::uint8_t* row = typedef_base + i * typedef_row_sz;
        if (row + typedef_row_sz > tbl_data + tbl_stream_size) break;

        const std::uint32_t flags = load32(row);
        const std::uint32_t name_idx = read_idx(row + 4, str_idx_sz);
        const std::uint32_t ns_idx = read_idx(row + 4 + str_idx_sz, str_idx_sz);

        std::string type_name = get_string_from_heap(str_heap, str_heap_size, name_idx);
        std::string ns_name = get_string_from_heap(str_heap, str_heap_size, ns_idx);

        if (type_name == "<Module>" || type_name.empty()) {
            continue; // Skip module pseudo-type
        }

        DotNetType dt;
        dt.name = type_name;
        dt.namespace_name = ns_name;
        dt.full_name = ns_name.empty() ? type_name : (ns_name + "." + type_name);
        dt.flags = flags;
        dt.is_public = (flags & 0x07) == 0x01 || (flags & 0x07) == 0x02; // Public / NestedPublic
        dt.is_interface = (flags & 0x00000020U) != 0;
        dt.is_abstract = (flags & 0x00000080U) != 0;
        dt.is_sealed = (flags & 0x00000100U) != 0;

        const std::size_t f_list_off = 4 + str_idx_sz + str_idx_sz + tdor_sz;
        const std::uint32_t f_start = read_idx(row + f_list_off, field_idx_sz);
        std::uint32_t f_end = static_cast<std::uint32_t>(n_fields + 1);
        if (i + 1 < n_typedefs) {
            f_end = read_idx(typedef_base + (i + 1) * typedef_row_sz + f_list_off, field_idx_sz);
        }

        // Read fields (1-based index in CLI)
        if (table_offsets[kField] != 0 && f_start <= f_end && f_start <= n_fields + 1) {
            for (std::uint32_t f_idx = f_start; f_idx < f_end && f_idx <= n_fields; ++f_idx) {
                const std::uint8_t* f_row = field_base + (f_idx - 1) * field_row_sz;
                if (f_row + field_row_sz > tbl_data + tbl_stream_size) break;

                const std::uint16_t f_flags = load16(f_row);
                const std::uint32_t f_name_idx = read_idx(f_row + 2, str_idx_sz);
                std::string f_name = get_string_from_heap(str_heap, str_heap_size, f_name_idx);

                DotNetField df;
                df.name = f_name.empty() ? ("field_" + std::to_string(f_idx)) : f_name;
                df.flags = f_flags;
                df.is_public = (f_flags & 0x07) == 0x06;
                df.is_private = (f_flags & 0x07) == 0x01;
                df.is_static = (f_flags & 0x0010) != 0;
                df.is_readonly = (f_flags & 0x0020) != 0;
                dt.fields.push_back(std::move(df));
            }
        }

        const std::size_t m_list_off = f_list_off + field_idx_sz;
        const std::uint32_t m_start = read_idx(row + m_list_off, method_idx_sz);
        std::uint32_t m_end = static_cast<std::uint32_t>(n_methods + 1);
        if (i + 1 < n_typedefs) {
            m_end = read_idx(typedef_base + (i + 1) * typedef_row_sz + m_list_off, method_idx_sz);
        }

        // Read methods (1-based index in CLI)
        if (table_offsets[kMethodDef] != 0 && m_start <= m_end && m_start <= n_methods + 1) {
            for (std::uint32_t m_idx = m_start; m_idx < m_end && m_idx <= n_methods; ++m_idx) {
                const std::uint8_t* m_row = method_base + (m_idx - 1) * method_row_sz;
                if (m_row + method_row_sz > tbl_data + tbl_stream_size) break;

                const std::uint32_t m_rva = load32(m_row);
                const std::uint16_t m_flags = load16(m_row + 6);
                const std::uint32_t m_name_idx = read_idx(m_row + 8, str_idx_sz);
                std::string m_name = get_string_from_heap(str_heap, str_heap_size, m_name_idx);

                DotNetMethod dm;
                dm.name = m_name.empty() ? ("Method_" + std::to_string(m_idx)) : m_name;
                dm.rva = m_rva;
                dm.flags = m_flags;
                dm.is_public = (m_flags & 0x07) == 0x06;
                dm.is_private = (m_flags & 0x07) == 0x01;
                dm.is_static = (m_flags & 0x0010) != 0;
                dm.is_virtual = (m_flags & 0x0040) != 0;
                dm.is_constructor = (m_name == ".ctor" || m_name == ".cctor");

                dt.methods.push_back(std::move(dm));
            }
        }

        report.types.push_back(std::move(dt));
    }

    report.csharp_source = to_csharp(report);
    return report;
}

}  // namespace typemorph::dotnet

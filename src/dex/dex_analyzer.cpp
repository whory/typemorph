// TypeMorph - Android Dalvik Executable (DEX) & Java Decompiler Engine Implementation (JADX style)
#include "typemorph/dex/dex_analyzer.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>

namespace typemorph::dex {

namespace {

inline std::uint16_t read_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}

inline std::uint32_t read_u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0] | (static_cast<std::uint32_t>(p[1]) << 8) |
                                      (static_cast<std::uint32_t>(p[2]) << 16) |
                                      (static_cast<std::uint32_t>(p[3]) << 24));
}

// Read unsigned LEB128
std::uint32_t read_uleb128(const std::uint8_t* data, std::size_t size, std::size_t& offset) {
    std::uint32_t result = 0;
    int shift = 0;
    while (offset < size) {
        std::uint8_t byte = data[offset++];
        result |= static_cast<std::uint32_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
        if (shift >= 35) break;
    }
    return result;
}

// Convert Dalvik type descriptor to clean Java type name
std::string descriptor_to_java(const std::string& desc) {
    if (desc.empty()) return "void";
    if (desc == "V") return "void";
    if (desc == "Z") return "boolean";
    if (desc == "B") return "byte";
    if (desc == "S") return "short";
    if (desc == "C") return "char";
    if (desc == "I") return "int";
    if (desc == "J") return "long";
    if (desc == "F") return "float";
    if (desc == "D") return "double";

    if (desc.front() == '[') {
        return descriptor_to_java(desc.substr(1)) + "[]";
    }

    if (desc.front() == 'L' && desc.back() == ';') {
        std::string inner = desc.substr(1, desc.size() - 2);
        std::replace(inner.begin(), inner.end(), '/', '.');
        return inner;
    }

    return desc;
}

std::string access_flags_to_modifiers(std::uint32_t flags, bool is_method) {
    std::string s;
    if (flags & 0x0001) s += "public ";
    if (flags & 0x0002) s += "private ";
    if (flags & 0x0004) s += "protected ";
    if (flags & 0x0008) s += "static ";
    if (flags & 0x0010) s += "final ";
    if (flags & 0x0020 && is_method) s += "synchronized ";
    if (flags & 0x0400) s += "abstract ";
    if (flags & 0x0100 && is_method) s += "native ";
    return s;
}

} // namespace

bool DexAnalyzer::is_dex(const BinaryView& view) {
    if (view.size() < 112) return false;
    const auto* d = view.data();
    return d[0] == 'd' && d[1] == 'e' && d[2] == 'x' && d[3] == '\n' &&
           d[7] == '\0';
}

DexReport DexAnalyzer::analyze(const BinaryView& view) {
    DexReport report;
    report.is_dex = is_dex(view);
    if (!report.is_dex) return report;

    const auto* data = view.data();
    std::size_t size = view.size();

    // 1. Header parsing
    report.version = std::string(reinterpret_cast<const char*>(data + 4), 3);
    report.checksum = read_u32(data + 0x08);
    report.file_size = read_u32(data + 0x20);

    std::uint32_t string_ids_size = read_u32(data + 0x38);
    std::uint32_t string_ids_off  = read_u32(data + 0x3C);

    std::uint32_t type_ids_size   = read_u32(data + 0x40);
    std::uint32_t type_ids_off    = read_u32(data + 0x44);

    std::uint32_t proto_ids_size  = read_u32(data + 0x48);
    std::uint32_t proto_ids_off   = read_u32(data + 0x4C);

    std::uint32_t field_ids_size  = read_u32(data + 0x50);
    std::uint32_t field_ids_off   = read_u32(data + 0x54);
    (void)field_ids_size;

    std::uint32_t method_ids_size = read_u32(data + 0x58);
    std::uint32_t method_ids_off  = read_u32(data + 0x5C);

    std::uint32_t class_defs_size = read_u32(data + 0x60);
    std::uint32_t class_defs_off  = read_u32(data + 0x64);

    report.string_count = string_ids_size;
    report.type_count = type_ids_size;
    report.method_count = method_ids_size;

    // 2. Read string pool
    std::vector<std::string> string_pool;
    string_pool.reserve(string_ids_size);
    for (std::uint32_t i = 0; i < string_ids_size; ++i) {
        std::size_t ptr_off = string_ids_off + i * 4;
        if (ptr_off + 4 > size) break;
        std::uint32_t str_data_off = read_u32(data + ptr_off);
        if (str_data_off >= size) {
            string_pool.emplace_back("");
            continue;
        }

        std::size_t cursor = str_data_off;
        std::uint32_t utf16_size = read_uleb128(data, size, cursor);
        (void)utf16_size;

        std::string s;
        while (cursor < size && data[cursor] != '\0') {
            s.push_back(static_cast<char>(data[cursor++]));
        }
        string_pool.push_back(s);
    }
    report.strings = string_pool;

    // Helper to get string safely
    auto get_str = [&](std::uint32_t idx) -> std::string {
        return (idx < string_pool.size()) ? string_pool[idx] : "";
    };

    // 3. Read type IDs
    std::vector<std::string> type_pool;
    type_pool.reserve(type_ids_size);
    for (std::uint32_t i = 0; i < type_ids_size; ++i) {
        std::size_t off = type_ids_off + i * 4;
        if (off + 4 > size) break;
        std::uint32_t desc_idx = read_u32(data + off);
        type_pool.push_back(descriptor_to_java(get_str(desc_idx)));
    }

    auto get_type = [&](std::uint32_t idx) -> std::string {
        return (idx < type_pool.size()) ? type_pool[idx] : "Object";
    };

    // 4. Read proto IDs
    struct ProtoItem {
        std::string return_type;
        std::vector<std::string> param_types;
    };
    std::vector<ProtoItem> proto_pool;
    proto_pool.reserve(proto_ids_size);
    for (std::uint32_t i = 0; i < proto_ids_size; ++i) {
        std::size_t off = proto_ids_off + i * 12;
        if (off + 12 > size) break;
        std::uint32_t return_type_idx = read_u32(data + off + 4);
        std::uint32_t parameters_off  = read_u32(data + off + 8);

        ProtoItem proto;
        proto.return_type = get_type(return_type_idx);

        if (parameters_off != 0 && parameters_off + 4 <= size) {
            std::uint32_t param_count = read_u32(data + parameters_off);
            for (std::uint32_t p = 0; p < param_count; ++p) {
                std::size_t p_off = parameters_off + 4 + p * 2;
                if (p_off + 2 <= size) {
                    std::uint16_t tidx = read_u16(data + p_off);
                    proto.param_types.push_back(get_type(tidx));
                }
            }
        }
        proto_pool.push_back(proto);
    }

    // 5. Read method IDs
    struct MethodItem {
        std::string class_name;
        std::string name;
        ProtoItem proto;
    };
    std::vector<MethodItem> method_pool;
    method_pool.reserve(method_ids_size);
    for (std::uint32_t i = 0; i < method_ids_size; ++i) {
        std::size_t off = method_ids_off + i * 8;
        if (off + 8 > size) break;
        std::uint16_t c_idx = read_u16(data + off);
        std::uint16_t p_idx = read_u16(data + off + 2);
        std::uint32_t n_idx = read_u32(data + off + 4);

        MethodItem m;
        m.class_name = get_type(c_idx);
        m.name = get_str(n_idx);
        if (p_idx < proto_pool.size()) m.proto = proto_pool[p_idx];
        method_pool.push_back(m);
    }

    // 6. Read class definitions
    for (std::uint32_t i = 0; i < class_defs_size; ++i) {
        std::size_t off = class_defs_off + i * 32;
        if (off + 32 > size) break;

        std::uint32_t class_idx       = read_u32(data + off);
        std::uint32_t access_flags    = read_u32(data + off + 4);
        std::uint32_t superclass_idx  = read_u32(data + off + 8);
        std::uint32_t source_file_idx = read_u32(data + off + 16);
        std::uint32_t class_data_off  = read_u32(data + off + 24);

        DexClass cls;
        cls.name = get_type(class_idx);
        cls.access_flags = access_flags;
        if (superclass_idx != 0xFFFFFFFF && superclass_idx < type_pool.size()) {
            cls.super_class = get_type(superclass_idx);
        }
        if (source_file_idx != 0xFFFFFFFF && source_file_idx < string_pool.size()) {
            cls.source_file = get_str(source_file_idx);
        }

        // Parse class_data if present
        if (class_data_off != 0 && class_data_off < size) {
            std::size_t cursor = class_data_off;
            std::uint32_t static_fields_size   = read_uleb128(data, size, cursor);
            std::uint32_t instance_fields_size = read_uleb128(data, size, cursor);
            std::uint32_t direct_methods_size   = read_uleb128(data, size, cursor);
            std::uint32_t virtual_methods_size  = read_uleb128(data, size, cursor);

            // Read static fields
            std::uint32_t prev_field_idx = 0;
            for (std::uint32_t f = 0; f < static_fields_size; ++f) {
                std::uint32_t field_idx_diff = read_uleb128(data, size, cursor);
                std::uint32_t f_access = read_uleb128(data, size, cursor);
                prev_field_idx += field_idx_diff;

                if (field_ids_off + prev_field_idx * 8 + 8 <= size) {
                    std::uint16_t f_tidx = read_u16(data + field_ids_off + prev_field_idx * 8 + 2);
                    std::uint32_t f_nidx = read_u32(data + field_ids_off + prev_field_idx * 8 + 4);
                    cls.fields.push_back({get_str(f_nidx), get_type(f_tidx), f_access | 0x0008});
                }
            }

            // Read instance fields
            prev_field_idx = 0;
            for (std::uint32_t f = 0; f < instance_fields_size; ++f) {
                std::uint32_t field_idx_diff = read_uleb128(data, size, cursor);
                std::uint32_t f_access = read_uleb128(data, size, cursor);
                prev_field_idx += field_idx_diff;

                if (field_ids_off + prev_field_idx * 8 + 8 <= size) {
                    std::uint16_t f_tidx = read_u16(data + field_ids_off + prev_field_idx * 8 + 2);
                    std::uint32_t f_nidx = read_u32(data + field_ids_off + prev_field_idx * 8 + 4);
                    cls.fields.push_back({get_str(f_nidx), get_type(f_tidx), f_access});
                }
            }

            // Read direct & virtual methods
            auto parse_method = [&](bool is_direct) {
                (void)is_direct;
                std::uint32_t method_idx_diff = read_uleb128(data, size, cursor);
                std::uint32_t m_access = read_uleb128(data, size, cursor);
                std::uint32_t code_off = read_uleb128(data, size, cursor);

                static std::uint32_t running_midx = 0;
                running_midx += method_idx_diff;

                DexMethod meth;
                meth.access_flags = m_access;
                if (running_midx < method_pool.size()) {
                    const auto& m_info = method_pool[running_midx];
                    meth.class_name = m_info.class_name;
                    meth.name = m_info.name;
                    meth.return_type = m_info.proto.return_type;
                    meth.param_types = m_info.proto.param_types;
                }

                // If code is present, disassemble instructions
                if (code_off != 0 && code_off + 16 <= size) {
                    meth.registers_size = read_u16(data + code_off);
                    std::uint32_t insns_size = read_u32(data + code_off + 12);
                    std::size_t insns_off = code_off + 16;

                    std::ostringstream java_body;
                    for (std::uint32_t ins = 0; ins < insns_size && insns_off + 2 <= size; ) {
                        std::uint8_t opcode = data[insns_off];
                        std::uint8_t op_a   = data[insns_off + 1];

                        switch (opcode) {
                        case 0x00: // nop
                            meth.instructions.push_back("nop");
                            insns_off += 2; ins += 1;
                            break;
                        case 0x0E: // return-void
                            meth.instructions.push_back("return-void");
                            java_body << "        return;\n";
                            insns_off += 2; ins += 1;
                            break;
                        case 0x0F: // return
                            meth.instructions.push_back("return v" + std::to_string(op_a));
                            java_body << "        return v" << static_cast<int>(op_a) << ";\n";
                            insns_off += 2; ins += 1;
                            break;
                        case 0x1A: { // const-string vAA, string@BBBB
                            if (insns_off + 4 <= size) {
                                std::uint16_t sidx = read_u16(data + insns_off + 2);
                                std::string sval = get_str(sidx);
                                meth.instructions.push_back("const-string v" + std::to_string(op_a) + ", \"" + sval + "\"");
                                java_body << "        String v" << static_cast<int>(op_a) << " = \"" << sval << "\";\n";
                                insns_off += 4; ins += 2;
                            } else {
                                insns_off += 2; ins += 1;
                            }
                            break;
                        }
                        case 0x6E: // invoke-virtual
                        case 0x70: // invoke-direct
                        case 0x71: { // invoke-static
                            if (insns_off + 6 <= size) {
                                std::uint16_t target_midx = read_u16(data + insns_off + 2);
                                std::string target_name = (target_midx < method_pool.size()) ?
                                    (method_pool[target_midx].class_name + "." + method_pool[target_midx].name) : "method_" + std::to_string(target_midx);
                                std::string op_name = (opcode == 0x71) ? "invoke-static" : (opcode == 0x70 ? "invoke-direct" : "invoke-virtual");
                                meth.instructions.push_back(op_name + " {v" + std::to_string(op_a & 0x0F) + "}, " + target_name);
                                java_body << "        " << target_name << "(...);\n";
                                insns_off += 6; ins += 3;
                            } else {
                                insns_off += 2; ins += 1;
                            }
                            break;
                        }
                        default:
                            meth.instructions.push_back("op_" + std::to_string(static_cast<int>(opcode)));
                            insns_off += 2; ins += 1;
                            break;
                        }
                    }
                    meth.decompiled_java = java_body.str();
                }

                cls.methods.push_back(meth);
            };

            for (std::uint32_t m = 0; m < direct_methods_size; ++m) parse_method(true);
            for (std::uint32_t m = 0; m < virtual_methods_size; ++m) parse_method(false);
        }

        report.classes.push_back(cls);
    }

    return report;
}

std::string DexAnalyzer::to_java_source(const DexReport& report) {
    std::ostringstream ss;
    ss << "// ----------------------------------------------------------------------------\n"
       << "// TypeMorph DEX & Dalvik Bytecode Decompiler (JADX style)\n"
       << "// DEX Version: " << report.version << ", Classes: " << report.classes.size() << "\n"
       << "// ----------------------------------------------------------------------------\n\n";

    for (const auto& cls : report.classes) {
        // Extract package name
        std::string pkg;
        std::string simple_name = cls.name;
        auto last_dot = cls.name.rfind('.');
        if (last_dot != std::string::npos) {
            pkg = cls.name.substr(0, last_dot);
            simple_name = cls.name.substr(last_dot + 1);
        }

        if (!pkg.empty()) {
            ss << "package " << pkg << ";\n\n";
        }

        ss << access_flags_to_modifiers(cls.access_flags, false) << "class " << simple_name;
        if (!cls.super_class.empty() && cls.super_class != "java.lang.Object") {
            ss << " extends " << cls.super_class;
        }
        ss << " {\n";

        // Fields
        for (const auto& f : cls.fields) {
            ss << "    " << access_flags_to_modifiers(f.access_flags, false)
               << f.type << " " << f.name << ";\n";
        }
        if (!cls.fields.empty()) ss << "\n";

        // Methods
        for (const auto& m : cls.methods) {
            ss << "    " << access_flags_to_modifiers(m.access_flags, true);
            if (m.name == "<init>") {
                ss << simple_name << "(";
            } else if (m.name == "<clinit>") {
                ss << "static { ... }\n\n";
                continue;
            } else {
                ss << (m.return_type.empty() ? "void" : m.return_type) << " " << m.name << "(";
            }

            for (std::size_t p = 0; p < m.param_types.size(); ++p) {
                if (p > 0) ss << ", ";
                ss << m.param_types[p] << " p" << p;
            }
            ss << ") {\n";

            if (!m.decompiled_java.empty()) {
                ss << m.decompiled_java;
            } else {
                ss << "        // [TypeMorph] Empty or native method stub\n";
            }
            ss << "    }\n\n";
        }

        ss << "}\n\n";
    }

    return ss.str();
}

std::string DexAnalyzer::format_report(const DexReport& report) {
    std::ostringstream ss;
    ss << "=== TypeMorph Android Dalvik Executable (DEX) Analyzer ===\n\n"
       << "DEX Magic Version: dex\\n" << report.version << "\\0\n"
       << "File Size        : " << report.file_size << " bytes\n"
       << "Checksum (Adler) : 0x" << std::hex << std::uppercase << report.checksum << std::dec << "\n"
       << "String Count     : " << report.string_count << "\n"
       << "Type Count       : " << report.type_count << "\n"
       << "Method Count     : " << report.method_count << "\n"
       << "Class Definitions: " << report.classes.size() << "\n\n";

    for (std::size_t i = 0; i < report.classes.size(); ++i) {
        const auto& c = report.classes[i];
        ss << "[" << (i + 1) << "] Class: " << c.name << "\n"
           << "    Superclass  : " << (c.super_class.empty() ? "java.lang.Object" : c.super_class) << "\n"
           << "    Fields      : " << c.fields.size() << "\n"
           << "    Methods     : " << c.methods.size() << "\n";

        for (const auto& m : c.methods) {
            ss << "      " << m.name << "(";
            for (std::size_t p = 0; p < m.param_types.size(); ++p) {
                if (p > 0) ss << ", ";
                ss << m.param_types[p];
            }
            ss << ") : " << (m.return_type.empty() ? "void" : m.return_type)
               << " [" << m.instructions.size() << " insns]\n";
        }
        ss << "\n";
    }

    return ss.str();
}

} // namespace typemorph::dex

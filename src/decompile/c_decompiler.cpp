// TypeMorph - C / C++ High-Level Code & Struct Reconstructor.
#include "typemorph/decompile/c_decompiler.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

namespace typemorph::decompile {

namespace {

std::string format_hex(std::uint64_t val) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(val));
    return std::string(buf);
}

}  // namespace

std::vector<StructField> CDecompiler::infer_struct_layout(
    std::span<const std::uint8_t> code,
    std::string_view base_reg) {

    std::map<std::uint32_t, StructField> field_map;
    const std::size_t n = code.size();

    (void)base_reg;

    for (std::size_t i = 0; i + 3 < n; ++i) {
        std::uint32_t disp = 0;
        std::uint32_t sz = 4;
        std::string type = "uint32_t";
        bool is_ptr = false;
        bool is_flt = false;
        bool matched = false;

        // 1. float/double movss/movsd [reg + disp]
        if (i + 4 < n && (code[i] == 0xF3 || code[i] == 0xF2) && code[i + 1] == 0x0F && code[i + 2] == 0x10) {
            const std::uint8_t modrm = code[i + 3];
            const std::uint8_t mod = (modrm >> 6) & 0x03;
            if (mod == 0x01 && i + 4 < n) { // 8-bit displacement
                disp = code[i + 4];
                sz = (code[i] == 0xF3) ? 4 : 8;
                type = (code[i] == 0xF3) ? "float" : "double";
                is_flt = true;
                matched = true;
                i += 4;
            } else if (mod == 0x02 && i + 7 < n) { // 32-bit displacement
                disp = static_cast<std::uint32_t>(code[i + 4]) |
                       (static_cast<std::uint32_t>(code[i + 5]) << 8U) |
                       (static_cast<std::uint32_t>(code[i + 6]) << 16U) |
                       (static_cast<std::uint32_t>(code[i + 7]) << 24U);
                sz = (code[i] == 0xF3) ? 4 : 8;
                type = (code[i] == 0xF3) ? "float" : "double";
                is_flt = true;
                matched = true;
                i += 7;
            }
        }

        // 2. 64-bit mov/add/cmp: REX.W (0x48) + opcode + ModR/M
        if (!matched && code[i] == 0x48 && (code[i + 1] == 0x8B || code[i + 1] == 0x89 ||
                                            code[i + 1] == 0x03 || code[i + 1] == 0x3B)) {
            const std::uint8_t modrm = code[i + 2];
            const std::uint8_t mod = (modrm >> 6) & 0x03;
            if (mod == 0x01 && i + 3 < n) {
                disp = code[i + 3];
                sz = 8;
                type = "uint64_t";
                is_ptr = (disp == 0 || disp % 8 == 0);
                matched = true;
                i += 3;
            } else if (mod == 0x02 && i + 6 < n) {
                disp = static_cast<std::uint32_t>(code[i + 3]) |
                       (static_cast<std::uint32_t>(code[i + 4]) << 8U) |
                       (static_cast<std::uint32_t>(code[i + 5]) << 16U) |
                       (static_cast<std::uint32_t>(code[i + 6]) << 24U);
                sz = 8;
                type = "uint64_t";
                matched = true;
                i += 6;
            }
        }

        // 3. 32-bit mov/add/cmp (0x8B, 0x89, 0x03, 0x3B)
        if (!matched && (code[i] == 0x8B || code[i] == 0x89 || code[i] == 0x03 || code[i] == 0x3B)) {
            const std::uint8_t modrm = code[i + 1];
            const std::uint8_t mod = (modrm >> 6) & 0x03;
            if (mod == 0x01 && i + 2 < n) {
                disp = code[i + 2];
                sz = 4;
                type = "uint32_t";
                matched = true;
                i += 2;
            } else if (mod == 0x02 && i + 5 < n) {
                disp = static_cast<std::uint32_t>(code[i + 2]) |
                       (static_cast<std::uint32_t>(code[i + 3]) << 8U) |
                       (static_cast<std::uint32_t>(code[i + 4]) << 16U) |
                       (static_cast<std::uint32_t>(code[i + 5]) << 24U);
                sz = 4;
                type = "uint32_t";
                matched = true;
                i += 5;
            }
        }

        // 4. 16-bit operand size override (0x66)
        if (!matched && code[i] == 0x66 && (code[i + 1] == 0x8B || code[i + 1] == 0x89)) {
            const std::uint8_t modrm = code[i + 2];
            const std::uint8_t mod = (modrm >> 6) & 0x03;
            if (mod == 0x01 && i + 3 < n) {
                disp = code[i + 3];
                sz = 2;
                type = "uint16_t";
                matched = true;
                i += 3;
            }
        }

        // 5. 8-bit mov (0x8A, 0x88)
        if (!matched && (code[i] == 0x8A || code[i] == 0x88)) {
            const std::uint8_t modrm = code[i + 1];
            const std::uint8_t mod = (modrm >> 6) & 0x03;
            if (mod == 0x01 && i + 2 < n) {
                disp = code[i + 2];
                sz = 1;
                type = "uint8_t";
                matched = true;
                i += 2;
            }
        }

        if (matched && disp < 4096) {
            StructField f;
            f.offset = disp;
            f.size = sz;
            f.type_name = type;
            f.name = "field_" + std::to_string(disp);
            f.is_pointer = is_ptr;
            f.is_float = is_flt;

            auto it = field_map.find(disp);
            if (it == field_map.end() || it->second.size < sz) {
                field_map[disp] = std::move(f);
            }
        }
    }

    std::vector<StructField> fields;
    fields.reserve(field_map.size());
    for (auto& [_, f] : field_map) {
        fields.push_back(std::move(f));
    }

    std::sort(fields.begin(), fields.end(), [](const StructField& a, const StructField& b) {
        return a.offset < b.offset;
    });

    return fields;
}

std::string CDecompiler::emit_struct_c(
    std::string_view struct_name,
    const std::vector<StructField>& fields) {

    if (fields.empty()) {
        return "typedef struct " + std::string(struct_name) + " {\n    /* Empty struct */\n} " +
               std::string(struct_name) + "_t;\n\n";
    }

    std::ostringstream ss;
    ss << "typedef struct " << struct_name << " {\n";

    std::uint32_t cur_offset = 0;
    std::size_t pad_idx = 0;

    for (const auto& f : fields) {
        if (f.offset > cur_offset) {
            const std::uint32_t pad_size = f.offset - cur_offset;
            ss << "    uint8_t _pad_" << pad_idx++ << "[" << pad_size << "]; // +0x"
               << std::hex << cur_offset << std::dec << "\n";
            cur_offset = f.offset;
        }

        char hex_buf[16];
        std::snprintf(hex_buf, sizeof(hex_buf), "0x%X", f.offset);
        ss << "    " << f.type_name << " " << f.name << "; // +" << hex_buf << "\n";
        cur_offset += f.size;
    }

    ss << "} " << struct_name << "_t;\n\n";
    return ss.str();
}

DecompiledFunction CDecompiler::decompile_bytes(
    std::span<const std::uint8_t> code,
    std::uint64_t entry_va,
    std::uint16_t bits,
    core::ImageFormat format,
    std::string_view name) const {

    abi::AbiClassifier abi_classifier;
    auto sig = abi_classifier.analyze_function_bytes(code, entry_va, bits, format, name);

    DecompiledFunction fn;
    fn.entry_va = entry_va;
    fn.name = sig.name;
    fn.prototype = sig.prototype;

    // 1. Reconstruct struct layout from memory accesses
    auto fields = infer_struct_layout(code);
    if (!fields.empty()) {
        ReconstructedStruct s;
        s.function_va = entry_va;
        s.name = fn.name + "_context";
        s.base_register = (bits == 64) ? "rcx" : "this";
        s.fields = fields;
        s.total_size = fields.back().offset + fields.back().size;
        s.c_declaration = emit_struct_c(s.name, s.fields);
        fn.structs.push_back(std::move(s));
    }

    // 2. Synthesize structured C pseudocode from machine code
    std::ostringstream ss;
    ss << "// Address: " << format_hex(entry_va) << " (" << bits << "-bit)\n"
       << "// Convention: " << to_string(sig.convention) << ", Frame size: "
       << sig.stack_frame_size << " bytes\n";

    if (!fn.structs.empty()) {
        ss << "// Inferred struct context: " << fn.structs[0].name << "_t ("
           << fn.structs[0].fields.size() << " fields)\n";
    }

    ss << sig.prototype << " {\n";

    // Local variable declarations
    ss << "    int32_t eax = 0;\n";
    if (bits == 64) {
        ss << "    int64_t rax = 0;\n";
    }

    const std::size_t len = code.size();
    std::size_t pc = 0;

    // Skip prologue
    if (pc + 4 <= len && code[pc] == 0xF3 && code[pc + 1] == 0x0F &&
        code[pc + 2] == 0x1E && code[pc + 3] == 0xFA) {
        pc += 4; // endbr64
    }
    if (pc < len && code[pc] == 0x55) pc++; // push rbp/ebp
    if (pc + 2 <= len && code[pc] == 0x89 && code[pc + 1] == 0xE5) pc += 2;
    if (pc + 2 <= len && code[pc] == 0x8B && code[pc + 1] == 0xEC) pc += 2;
    if (pc + 3 <= len && code[pc] == 0x48 && code[pc + 1] == 0x89 && code[pc + 2] == 0xE5) pc += 3;
    if (pc + 4 <= len && code[pc] == 0x48 && code[pc + 1] == 0x83 && code[pc + 2] == 0xEC) pc += 4;
    else if (pc + 3 <= len && code[pc] == 0x83 && code[pc + 1] == 0xEC) pc += 3;

    int branch_id = 0;
    while (pc < len) {
        const std::uint8_t op = code[pc];

        // ret / ret N
        if (op == 0xC3 || op == 0xC2) {
            if (sig.return_type_hint == "void") {
                ss << "    return;\n";
            } else if (bits == 64) {
                ss << "    return rax != 0 ? rax : eax;\n";
            } else {
                ss << "    return eax;\n";
            }
            break;
        }

        // test rcx, rcx / test ecx, ecx (85 C9 / 48 85 C9)
        if (pc + 2 <= len && code[pc] == 0x85 && code[pc + 1] == 0xC9) {
            ss << "    bool is_zero = (arg0 == 0);\n";
            pc += 2;
            continue;
        }
        if (pc + 3 <= len && code[pc] == 0x48 && code[pc + 1] == 0x85 && code[pc + 2] == 0xC9) {
            ss << "    bool is_null = (rcx == NULL);\n";
            pc += 3;
            continue;
        }

        // xor eax, eax (31 C0 / 33 C0)
        if (pc + 2 <= len && ((code[pc] == 0x31 && code[pc + 1] == 0xC0) ||
                              (code[pc] == 0x33 && code[pc + 1] == 0xC0))) {
            ss << "    eax = 0;\n";
            pc += 2;
            continue;
        }

        // xor rax, rax (48 31 C0 / 48 33 C0)
        if (pc + 3 <= len && code[pc] == 0x48 &&
            ((code[pc + 1] == 0x31 && code[pc + 2] == 0xC0) ||
             (code[pc + 1] == 0x33 && code[pc + 2] == 0xC0))) {
            ss << "    rax = 0;\n";
            pc += 3;
            continue;
        }

        // mov eax, imm32 (B8 imm32)
        if (op == 0xB8 && pc + 5 <= len) {
            const std::uint32_t imm = static_cast<std::uint32_t>(code[pc + 1]) |
                                     (static_cast<std::uint32_t>(code[pc + 2]) << 8U) |
                                     (static_cast<std::uint32_t>(code[pc + 3]) << 16U) |
                                     (static_cast<std::uint32_t>(code[pc + 4]) << 24U);
            ss << "    eax = " << format_hex(imm) << ";\n";
            pc += 5;
            continue;
        }

        // Conditional branch (je / jne: 74 xx / 75 xx)
        if (op == 0x74 && pc + 2 <= len) {
            const std::int8_t rel = static_cast<std::int8_t>(code[pc + 1]);
            ss << "    if (is_zero) {\n        goto loc_" << ++branch_id << "; // rel +" << static_cast<int>(rel) << "\n    }\n";
            pc += 2;
            continue;
        }
        if (op == 0x75 && pc + 2 <= len) {
            const std::int8_t rel = static_cast<std::int8_t>(code[pc + 1]);
            ss << "    if (!is_zero) {\n        goto loc_" << ++branch_id << "; // rel +" << static_cast<int>(rel) << "\n    }\n";
            pc += 2;
            continue;
        }

        // call rel32 (E8 rel32)
        if (op == 0xE8 && pc + 5 <= len) {
            const std::int32_t rel = static_cast<std::int32_t>(
                static_cast<std::uint32_t>(code[pc + 1]) |
                (static_cast<std::uint32_t>(code[pc + 2]) << 8U) |
                (static_cast<std::uint32_t>(code[pc + 3]) << 16U) |
                (static_cast<std::uint32_t>(code[pc + 4]) << 24U));
            const std::uint64_t target = entry_va + pc + 5 + rel;
            ss << "    sub_" << std::hex << target << std::dec << "();\n";
            pc += 5;
            continue;
        }

        // Memory load: mov eax, [rcx + disp] (8B 41 disp8)
        if (pc + 3 <= len && code[pc] == 0x8B && code[pc + 1] == 0x41) {
            const std::uint8_t d = code[pc + 2];
            ss << "    eax = ctx->field_" << std::to_string(d) << "; // [rcx + 0x" << std::hex << (int)d << std::dec << "]\n";
            pc += 3;
            continue;
        }

        // Memory store: mov [rcx + disp], eax (89 41 disp8)
        if (pc + 3 <= len && code[pc] == 0x89 && code[pc + 1] == 0x41) {
            const std::uint8_t d = code[pc + 2];
            ss << "    ctx->field_" << std::to_string(d) << " = eax;\n";
            pc += 3;
            continue;
        }

        // add eax, ecx / edx (01 C8 / 03 C2)
        if (pc + 2 <= len && code[pc] == 0x01 && code[pc + 1] == 0xC8) {
            ss << "    eax += ecx;\n";
            pc += 2;
            continue;
        }
        if (pc + 2 <= len && code[pc] == 0x03 && code[pc + 1] == 0xC2) {
            ss << "    eax += edx;\n";
            pc += 2;
            continue;
        }

        // sete al / setne al (0F 94 C0 / 0F 95 C0)
        if (pc + 3 <= len && code[pc] == 0x0F && code[pc + 1] == 0x94 && code[pc + 2] == 0xC0) {
            ss << "    eax = (cond == 0);\n";
            pc += 3;
            continue;
        }
        if (pc + 3 <= len && code[pc] == 0x0F && code[pc + 1] == 0x95 && code[pc + 2] == 0xC0) {
            ss << "    eax = (cond != 0);\n";
            pc += 3;
            continue;
        }

        pc++;
    }

    ss << "}\n\n";
    fn.pseudocode = ss.str();
    return fn;
}

DecompiledFunction CDecompiler::decompile_function(
    const core::ExecutableImage& image,
    std::uint64_t entry_va,
    std::string_view name) const {

    const auto* sec = image.section_for_address(entry_va);
    if (!sec || !sec->executable()) {
        DecompiledFunction fn;
        fn.entry_va = entry_va;
        fn.name = name.empty() ? ("sub_" + format_hex(entry_va)) : std::string(name);
        fn.pseudocode = "// Address not in executable section\n";
        return fn;
    }

    const std::uint64_t max_len = std::min<std::uint64_t>(1024, sec->end() - entry_va);
    auto bytes_res = image.span_at_va(entry_va, max_len);
    if (!bytes_res) {
        DecompiledFunction fn;
        fn.entry_va = entry_va;
        fn.name = name.empty() ? ("sub_" + format_hex(entry_va)) : std::string(name);
        fn.pseudocode = "// Failed to read bytes\n";
        return fn;
    }

    return decompile_bytes(bytes_res.value(), entry_va, image.bits(), image.format(), name);
}

DecompileReport CDecompiler::decompile(
    const core::ExecutableImage& image,
    std::optional<std::uint64_t> target_va) const {

    DecompileReport report;
    std::set<std::uint64_t> visited;

    std::ostringstream ss;
    ss << "// Decompiled with TypeMorph v0.6.0\n"
       << "// Target Architecture: " << image.bits() << "-bit " << image.format_name() << "\n\n"
       << "#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n\n";

    if (target_va) {
        auto fn = decompile_function(image, *target_va);
        for (const auto& s : fn.structs) {
            ss << s.c_declaration;
            report.global_structs.push_back(s);
        }
        ss << fn.pseudocode;
        report.functions.push_back(std::move(fn));
        report.total_functions = 1;
        report.combined_source = ss.str();
        return report;
    }

    // Decompile symbols / entry points
    for (const auto& sym : image.symbols()) {
        if (sym.kind == core::SymbolKind::function && sym.address != 0 &&
            image.is_executable_address(sym.address) && !visited.contains(sym.address)) {
            visited.insert(sym.address);
            auto fn = decompile_function(image, sym.address, sym.name);
            for (const auto& s : fn.structs) {
                ss << s.c_declaration;
                report.global_structs.push_back(s);
            }
            ss << fn.pseudocode;
            report.functions.push_back(std::move(fn));
            if (report.functions.size() >= 50) break; // Limit default CLI batch
        }
    }

    if (image.entry_point() != 0 && !visited.contains(image.entry_point()) &&
        image.is_executable_address(image.entry_point())) {
        visited.insert(image.entry_point());
        auto fn = decompile_function(image, image.entry_point(), "entry");
        for (const auto& s : fn.structs) {
            ss << s.c_declaration;
            report.global_structs.push_back(s);
        }
        ss << fn.pseudocode;
        report.functions.push_back(std::move(fn));
    }

    report.total_functions = report.functions.size();
    report.combined_source = ss.str();
    return report;
}

}  // namespace typemorph::decompile

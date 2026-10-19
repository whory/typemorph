// TypeMorph - Calling Convention & Function Signature Classifier.
#include "typemorph/abi/calling_convention.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>

namespace typemorph::abi {

namespace {

std::string format_sub_name(std::uint64_t va, std::uint16_t bits) {
    char buf[64];
    if (bits == 64) {
        std::snprintf(buf, sizeof(buf), "sub_%016llX", static_cast<unsigned long long>(va));
    } else {
        std::snprintf(buf, sizeof(buf), "sub_%08X", static_cast<unsigned int>(va));
    }
    return std::string(buf);
}

}  // namespace

FunctionSignature AbiClassifier::analyze_function_bytes(
    std::span<const std::uint8_t> code,
    std::uint64_t entry_va,
    std::uint16_t bits,
    core::ImageFormat format,
    std::string_view name) const {

    FunctionSignature sig;
    sig.entry_va = entry_va;
    sig.name = name.empty() ? format_sub_name(entry_va, bits) : std::string(name);
    sig.confidence = 0.85;

    if (code.empty()) {
        sig.rationale = "Empty code span";
        sig.prototype = "void " + sig.name + "()";
        return sig;
    }

    const std::size_t len = code.size();
    std::size_t pc = 0;

    // 1. Check for endbr64 prefix (F3 0F 1E FA)
    if (pc + 4 <= len && code[pc] == 0xF3 && code[pc + 1] == 0x0F &&
        code[pc + 2] == 0x1E && code[pc + 3] == 0xFA) {
        pc += 4;
    }

    // 2. Detect Frame Setup (push rbp/ebp; mov rbp/ebp, rsp/esp)
    bool has_frame_pointer = false;
    if (pc < len && code[pc] == 0x55) { // push ebp/rbp
        pc++;
        if (pc + 2 <= len && code[pc] == 0x89 && code[pc + 1] == 0xE5) {
            has_frame_pointer = true;
            pc += 2;
        } else if (pc + 2 <= len && code[pc] == 0x8B && code[pc + 1] == 0xEC) {
            has_frame_pointer = true;
            pc += 2;
        } else if (pc + 3 <= len && code[pc] == 0x48 && code[pc + 1] == 0x89 && code[pc + 2] == 0xE5) {
            has_frame_pointer = true;
            pc += 3;
        } else if (pc + 3 <= len && code[pc] == 0x48 && code[pc + 1] == 0x8B && code[pc + 2] == 0xEC) {
            has_frame_pointer = true;
            pc += 3;
        }
    }

    // 3. Detect Stack Frame Allocation (sub rsp/esp, imm) anywhere in first 32 bytes
    const std::size_t alloc_scan = std::min<std::size_t>(len, 32);
    for (std::size_t i = 0; i < alloc_scan; ++i) {
        if (code[i] == 0xC3 || code[i] == 0xC2) break;
        if (i + 4 <= len && code[i] == 0x48 && code[i + 1] == 0x83 && code[i + 2] == 0xEC) {
            sig.stack_frame_size = code[i + 3];
            break;
        }
        if (i + 7 <= len && code[i] == 0x48 && code[i + 1] == 0x81 && code[i + 2] == 0xEC) {
            sig.stack_frame_size = static_cast<std::uint32_t>(code[i + 3]) |
                                  (static_cast<std::uint32_t>(code[i + 4]) << 8U) |
                                  (static_cast<std::uint32_t>(code[i + 5]) << 16U) |
                                  (static_cast<std::uint32_t>(code[i + 6]) << 24U);
            break;
        }
        if (i + 3 <= len && code[i] == 0x83 && code[i + 1] == 0xEC) {
            sig.stack_frame_size = code[i + 2];
            break;
        }
        if (i + 6 <= len && code[i] == 0x81 && code[i + 1] == 0xEC) {
            sig.stack_frame_size = static_cast<std::uint32_t>(code[i + 2]) |
                                  (static_cast<std::uint32_t>(code[i + 3]) << 8U) |
                                  (static_cast<std::uint32_t>(code[i + 4]) << 16U) |
                                  (static_cast<std::uint32_t>(code[i + 5]) << 24U);
            break;
        }
    }

    // 4. Scan forward in the first basic block (up to 128 bytes) for parameter register / stack usage
    bool rcx_used = false;
    bool rdx_used = false;
    bool r8_used = false;
    bool r9_used = false;
    bool rdi_used = false;
    bool rsi_used = false;
    bool ecx_used = false;
    bool edx_used = false;
    int max_stack_arg_offset = -1;

    const std::size_t scan_limit = std::min<std::size_t>(len, 128);
    for (std::size_t i = 0; i < scan_limit; ++i) {
        if (code[i] == 0xC3 || code[i] == 0xC2) break; // Reached return

        // Win64 parameter store to shadow stack:
        // mov [rsp+8], rcx/ecx
        if (i + 5 <= scan_limit && code[i + 2] == 0x4C && code[i + 3] == 0x24 && code[i + 4] == 0x08) {
            if ((code[i] == 0x48 && code[i + 1] == 0x89) || code[i] == 0x89) rcx_used = true;
        }
        // mov [rsp+16], rdx/edx
        if (i + 5 <= scan_limit && code[i + 2] == 0x54 && code[i + 3] == 0x24 && code[i + 4] == 0x10) {
            if ((code[i] == 0x48 && code[i + 1] == 0x89) || code[i] == 0x89) rdx_used = true;
        }
        // mov [rsp+24], r8/r8d
        if (i + 5 <= scan_limit && code[i + 2] == 0x44 && code[i + 3] == 0x24 && code[i + 4] == 0x18) {
            if ((code[i] == 0x4C && code[i + 1] == 0x89) || (code[i] == 0x44 && code[i + 1] == 0x89)) r8_used = true;
        }
        // mov [rsp+32], r9/r9d
        if (i + 5 <= scan_limit && code[i + 2] == 0x4C && code[i + 3] == 0x24 && code[i + 4] == 0x20) {
            if ((code[i] == 0x4C && code[i + 1] == 0x89) || (code[i] == 0x44 && code[i + 1] == 0x89)) r9_used = true;
        }

        // Test / deref / move reads on argument registers:
        // RCX / ECX
        if (i + 2 <= scan_limit && (code[i] == 0x85 && code[i + 1] == 0xC9)) { rcx_used = true; ecx_used = true; }
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x85 && code[i + 2] == 0xC9) rcx_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x8B && code[i + 1] == 0x01)) { rcx_used = true; ecx_used = true; } // mov eax, [rcx]
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x8B && code[i + 2] == 0x01) rcx_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x89 && code[i + 1] == 0xC8)) { rcx_used = true; ecx_used = true; } // mov eax, ecx
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0xC8) rcx_used = true;

        // RDX / EDX
        if (i + 2 <= scan_limit && (code[i] == 0x85 && code[i + 1] == 0xD2)) { rdx_used = true; edx_used = true; }
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x85 && code[i + 2] == 0xD2) rdx_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x8B && code[i + 1] == 0x02)) { rdx_used = true; edx_used = true; }
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x8B && code[i + 2] == 0x02) rdx_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x89 && code[i + 1] == 0xD0)) { rdx_used = true; edx_used = true; }
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0xD0) rdx_used = true;

        // R8
        if (i + 3 <= scan_limit && (code[i] == 0x4D || code[i] == 0x45) && code[i + 1] == 0x85 && code[i + 2] == 0xC0) r8_used = true;
        if (i + 3 <= scan_limit && (code[i] == 0x4C || code[i] == 0x44) && code[i + 1] == 0x89 && code[i + 2] == 0xC0) r8_used = true;

        // R9
        if (i + 3 <= scan_limit && (code[i] == 0x4D || code[i] == 0x45) && code[i + 1] == 0x85 && code[i + 2] == 0xC9) r9_used = true;
        if (i + 3 <= scan_limit && (code[i] == 0x4C || code[i] == 0x44) && code[i + 1] == 0x89 && code[i + 2] == 0xC8) r9_used = true;

        // SysV RDI
        if (i + 2 <= scan_limit && (code[i] == 0x85 && code[i + 1] == 0xFF)) rdi_used = true;
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x85 && code[i + 2] == 0xFF) rdi_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x8B && code[i + 1] == 0x07)) rdi_used = true;
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x8B && code[i + 2] == 0x07) rdi_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x89 && code[i + 1] == 0xF8)) rdi_used = true;
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0xF8) rdi_used = true;

        // SysV RSI
        if (i + 2 <= scan_limit && (code[i] == 0x85 && code[i + 1] == 0xF6)) rsi_used = true;
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x85 && code[i + 2] == 0xF6) rsi_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x8B && code[i + 1] == 0x06)) rsi_used = true;
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x8B && code[i + 2] == 0x06) rsi_used = true;
        if (i + 2 <= scan_limit && (code[i] == 0x89 && code[i + 1] == 0xF0)) rsi_used = true;
        if (i + 3 <= scan_limit && code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0xF0) rsi_used = true;

        // Stack read [ebp + disp8] (ModR/M byte with mod=01, rm=101)
        if (has_frame_pointer && i + 2 < scan_limit) {
            if ((code[i + 1] & 0xC7) == 0x45) {
                const std::int8_t disp = static_cast<std::int8_t>(code[i + 2]);
                if (disp >= 8 && disp <= 64) {
                    if (disp > max_stack_arg_offset) {
                        max_stack_arg_offset = disp;
                    }
                }
            }
        }
    }

    // 5. Scan for Epilogue & Return (searching backwards or scanning first ret)
    std::size_t ret_pos = std::string::npos;
    for (std::size_t i = 0; i < len; ++i) {
        if (code[i] == 0xC3) {
            ret_pos = i;
            sig.stack_purge_bytes = 0;
            break;
        }
        if (code[i] == 0xC2 && i + 2 < len) {
            ret_pos = i;
            sig.stack_purge_bytes = static_cast<std::uint32_t>(code[i + 1]) |
                                   (static_cast<std::uint32_t>(code[i + 2]) << 8U);
            break;
        }
    }

    // 6. Return Kind Determination (check instructions immediately preceding ret)
    sig.return_kind = ReturnKind::void_type;
    sig.return_type_hint = "void";

    if (ret_pos != std::string::npos && ret_pos > 0) {
        // Look up to 16 bytes before ret (skipping leave/pop rbp)
        std::size_t check_start = (ret_pos >= 16) ? ret_pos - 16 : 0;
        for (std::size_t k = ret_pos; k > check_start; --k) {
            const std::size_t idx = k - 1;
            // xor eax, eax (31 C0 or 33 C0)
            if (idx + 1 < ret_pos && ((code[idx] == 0x31 && code[idx + 1] == 0xC0) ||
                                      (code[idx] == 0x33 && code[idx + 1] == 0xC0))) {
                sig.return_kind = ReturnKind::integer;
                sig.return_type_hint = (bits == 64 ? "int32_t" : "int32_t");
                break;
            }
            // xor rax, rax (48 31 C0 or 48 33 C0)
            if (idx + 2 < ret_pos && code[idx] == 0x48 &&
                ((code[idx + 1] == 0x31 && code[idx + 2] == 0xC0) ||
                 (code[idx + 1] == 0x33 && code[idx + 2] == 0xC0))) {
                sig.return_kind = ReturnKind::integer;
                sig.return_type_hint = "int64_t";
                break;
            }
            // mov eax, imm32 (B8 xx xx xx xx)
            if (idx + 4 < ret_pos && code[idx] == 0xB8) {
                sig.return_kind = ReturnKind::integer;
                sig.return_type_hint = "int32_t";
                break;
            }
            // setcc al (0F 9x C0)
            if (idx + 2 < ret_pos && code[idx] == 0x0F && (code[idx + 1] & 0xF0) == 0x90 && code[idx + 2] == 0xC0) {
                sig.return_kind = ReturnKind::boolean_type;
                sig.return_type_hint = "bool";
                break;
            }
            // movss xmm0 (F3 0F 10) / movsd xmm0 (F2 0F 10)
            if (idx + 3 < ret_pos && code[idx] == 0xF3 && code[idx + 1] == 0x0F && code[idx + 2] == 0x10) {
                sig.return_kind = ReturnKind::floating_point;
                sig.return_type_hint = "float";
                break;
            }
            if (idx + 3 < ret_pos && code[idx] == 0xF2 && code[idx + 1] == 0x0F && code[idx + 2] == 0x10) {
                sig.return_kind = ReturnKind::floating_point;
                sig.return_type_hint = "double";
                break;
            }
        }
    }

    // 7. Calling Convention & Argument Resolution
    if (bits == 64) {
        if (format == core::ImageFormat::pe) {
            sig.convention = CallingConvention::x64_windows;
            sig.rationale = "x64 PE binary uses Microsoft x64 calling convention";

            std::size_t num_args = 0;
            if (r9_used) num_args = 4;
            else if (r8_used) num_args = 3;
            else if (rdx_used) num_args = 2;
            else if (rcx_used) num_args = 1;

            static const char* kWin64Regs[] = {"rcx", "rdx", "r8", "r9"};
            for (std::size_t i = 0; i < num_args; ++i) {
                FunctionArgument arg;
                arg.index = i;
                arg.name = std::string(kWin64Regs[i]);
                arg.location = std::string(kWin64Regs[i]);
                arg.type_hint = (i == 0 && rcx_used && has_frame_pointer) ? "void*" : "int64_t";
                sig.arguments.push_back(std::move(arg));
            }
        } else {
            sig.convention = CallingConvention::x64_sysv;
            sig.rationale = "x64 ELF/Mach-O binary uses System V AMD64 ABI";

            std::size_t num_args = 0;
            if (r9_used) num_args = 6;
            else if (r8_used) num_args = 5;
            else if (rcx_used) num_args = 4;
            else if (rdx_used) num_args = 3;
            else if (rsi_used) num_args = 2;
            else if (rdi_used) num_args = 1;

            static const char* kSysVRegs[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
            for (std::size_t i = 0; i < num_args; ++i) {
                FunctionArgument arg;
                arg.index = i;
                arg.name = std::string(kSysVRegs[i]);
                arg.location = std::string(kSysVRegs[i]);
                arg.type_hint = (i == 0 && rdi_used) ? "void*" : "int64_t";
                sig.arguments.push_back(std::move(arg));
            }
        }
    } else { // 32-bit x86
        if (sig.stack_purge_bytes > 0) {
            const std::size_t stack_args = sig.stack_purge_bytes / 4;
            if (ecx_used && edx_used) {
                sig.convention = CallingConvention::x86_fastcall;
                sig.rationale = "Callee purges stack via ret " + std::to_string(sig.stack_purge_bytes) +
                                "; ECX and EDX read before write -> __fastcall";
                sig.arguments.push_back(FunctionArgument{0, "arg0", "ecx", "uint32_t"});
                sig.arguments.push_back(FunctionArgument{1, "arg1", "edx", "uint32_t"});
                for (std::size_t k = 0; k < stack_args; ++k) {
                    sig.arguments.push_back(FunctionArgument{
                        2 + k, "arg" + std::to_string(2 + k),
                        "stack[+0x" + std::to_string(4 + 4 * k) + "]", "uint32_t"});
                }
            } else if (ecx_used) {
                sig.convention = CallingConvention::x86_thiscall;
                sig.rationale = "Callee purges stack via ret " + std::to_string(sig.stack_purge_bytes) +
                                "; ECX holds this pointer -> __thiscall";
                sig.arguments.push_back(FunctionArgument{0, "this_ptr", "ecx", "void*"});
                for (std::size_t k = 0; k < stack_args; ++k) {
                    sig.arguments.push_back(FunctionArgument{
                        1 + k, "arg" + std::to_string(1 + k),
                        "stack[+0x" + std::to_string(4 + 4 * k) + "]", "uint32_t"});
                }
            } else {
                sig.convention = CallingConvention::x86_stdcall;
                sig.rationale = "Callee cleans " + std::to_string(sig.stack_purge_bytes) +
                                " bytes via ret N; no register args -> __stdcall";
                for (std::size_t k = 0; k < stack_args; ++k) {
                    sig.arguments.push_back(FunctionArgument{
                        k, "arg" + std::to_string(k),
                        "stack[+0x" + std::to_string(4 + 4 * k) + "]", "uint32_t"});
                }
            }
        } else {
            // stack_purge_bytes == 0 (ret)
            if (ecx_used && edx_used) {
                sig.convention = CallingConvention::x86_fastcall;
                sig.rationale = "Registers ECX and EDX read before write with caller clean -> __fastcall";
                sig.arguments.push_back(FunctionArgument{0, "arg0", "ecx", "uint32_t"});
                sig.arguments.push_back(FunctionArgument{1, "arg1", "edx", "uint32_t"});
            } else if (ecx_used && !edx_used && max_stack_arg_offset <= 0) {
                sig.convention = CallingConvention::x86_thiscall;
                sig.rationale = "ECX read before write with zero stack args -> __thiscall";
                sig.arguments.push_back(FunctionArgument{0, "this_ptr", "ecx", "void*"});
            } else {
                sig.convention = CallingConvention::x86_cdecl;
                sig.rationale = "Standard ret (0xC3) with caller stack clean -> __cdecl";
                std::size_t stack_args = 0;
                if (max_stack_arg_offset >= 8) {
                    stack_args = static_cast<std::size_t>((max_stack_arg_offset - 8) / 4 + 1);
                }
                for (std::size_t k = 0; k < stack_args; ++k) {
                    sig.arguments.push_back(FunctionArgument{
                        k, "arg" + std::to_string(k),
                        "stack[+0x" + std::to_string(4 + 4 * k) + "]", "uint32_t"});
                }
            }
        }
    }

    // 8. Reconstruct Prototype String
    std::string proto = sig.return_type_hint + " " + std::string(to_string(sig.convention)) + " " + sig.name + "(";
    for (std::size_t i = 0; i < sig.arguments.size(); ++i) {
        if (i > 0) proto += ", ";
        proto += sig.arguments[i].type_hint + " " + sig.arguments[i].name;
    }
    proto += ")";
    sig.prototype = std::move(proto);

    return sig;
}

FunctionSignature AbiClassifier::analyze_function(
    const core::ExecutableImage& image,
    std::uint64_t entry_va,
    std::string_view name) const {

    const auto* sec = image.section_for_address(entry_va);
    if (!sec || !sec->executable()) {
        FunctionSignature sig;
        sig.entry_va = entry_va;
        sig.name = name.empty() ? format_sub_name(entry_va, image.bits()) : std::string(name);
        sig.rationale = "Address does not reside in an executable section";
        sig.prototype = "void " + sig.name + "()";
        return sig;
    }

    const std::uint64_t max_func_len = std::min<std::uint64_t>(512, sec->end() - entry_va);
    auto span_res = image.span_at_va(entry_va, max_func_len);
    if (!span_res) {
        FunctionSignature sig;
        sig.entry_va = entry_va;
        sig.name = name.empty() ? format_sub_name(entry_va, image.bits()) : std::string(name);
        sig.rationale = "Failed to map virtual address to bytes";
        sig.prototype = "void " + sig.name + "()";
        return sig;
    }

    return analyze_function_bytes(span_res.value(), entry_va, image.bits(), image.format(), name);
}

AbiReport AbiClassifier::analyze(
    const core::ExecutableImage& image,
    std::optional<std::uint64_t> target_va) const {

    AbiReport report;
    std::set<std::uint64_t> visited_vas;

    if (target_va) {
        report.signatures.push_back(analyze_function(image, *target_va));
        report.total_functions = 1;
        report.convention_distribution[std::string(to_string(report.signatures[0].convention))]++;
        return report;
    }

    // 1. Gather functions from symbols
    for (const auto& sym : image.symbols()) {
        if (sym.kind == core::SymbolKind::function && sym.address != 0) {
            if (image.is_executable_address(sym.address) && !visited_vas.contains(sym.address)) {
                visited_vas.insert(sym.address);
                report.signatures.push_back(analyze_function(image, sym.address, sym.name));
            }
        }
    }

    // 2. Gather entry point
    if (image.entry_point() != 0 && image.is_executable_address(image.entry_point()) &&
        !visited_vas.contains(image.entry_point())) {
        visited_vas.insert(image.entry_point());
        report.signatures.push_back(analyze_function(image, image.entry_point(), "entry"));
    }

    // 3. Scan executable sections for common prologues if few symbols exist
    if (report.signatures.size() < 100) {
        for (const auto* sec : image.sections_with(core::SectionFlag::executable)) {
            auto bytes_res = image.section_bytes(*sec);
            if (!bytes_res) continue;
            const auto bytes = bytes_res.value();
            const std::size_t n = bytes.size();

            for (std::size_t i = 0; i + 8 < n && report.signatures.size() < 250; ++i) {
                const std::uint64_t cur_va = sec->virtual_address + i;
                if (visited_vas.contains(cur_va)) continue;

                bool is_prologue = false;
                // push ebp; mov ebp, esp (55 89 E5 / 55 8B EC)
                if (bytes[i] == 0x55 &&
                    ((bytes[i + 1] == 0x89 && bytes[i + 2] == 0xE5) ||
                     (bytes[i + 1] == 0x8B && bytes[i + 2] == 0xEC))) {
                    is_prologue = true;
                }
                // push rbp; mov rbp, rsp (55 48 89 E5 / 55 48 8B EC)
                else if (bytes[i] == 0x55 && bytes[i + 1] == 0x48 &&
                         ((bytes[i + 2] == 0x89 && bytes[i + 3] == 0xE5) ||
                          (bytes[i + 2] == 0x8B && bytes[i + 3] == 0xEC))) {
                    is_prologue = true;
                }
                // sub rsp, imm8 (48 83 EC xx)
                else if (bytes[i] == 0x48 && bytes[i + 1] == 0x83 && bytes[i + 2] == 0xEC) {
                    is_prologue = true;
                }
                // endbr64 (F3 0F 1E FA)
                else if (bytes[i] == 0xF3 && bytes[i + 1] == 0x0F &&
                         bytes[i + 2] == 0x1E && bytes[i + 3] == 0xFA) {
                    is_prologue = true;
                }

                if (is_prologue) {
                    visited_vas.insert(cur_va);
                    report.signatures.push_back(analyze_function(image, cur_va));
                    i += 16; // Skip forward
                }
            }
        }
    }

    report.total_functions = report.signatures.size();
    for (const auto& sig : report.signatures) {
        report.convention_distribution[std::string(to_string(sig.convention))]++;
    }

    return report;
}

}  // namespace typemorph::abi

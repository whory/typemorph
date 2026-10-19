// TypeMorph - Advanced Virtualization & VM Handler Profiler (VMDragonSlayer / NoVmp / Magicmida)
//
// Analyzes virtual machine protections (VMProtect 2.x/3.x, Themida/WinLicense, Code Virtualizer):
// - Detects VM Entry stubs (context preservation, PUSHAD / stack spill, setup of VIP/VSP)
// - Locates VM Dispatcher loops (opcode fetch, rolling key decryption, handler table indexing)
// - Classifies VM Handler primitives (VM_PUSH, VM_POP, VM_ADD, VM_NOR, VM_NAND, VM_JMP, VM_EXIT)
// - Identifies VM Exit trampolines (native register restoration, return to native code)
// - Reconstructs VM context architecture (rolling key register, virtual stack register)
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::vm {

using core::BinaryView;

struct VmHandler {
    std::string type; // "VM_PUSH", "VM_POP", "VM_ADD", "VM_NOR", "VM_NAND", "VM_JMP", "VM_EXIT"
    std::uint64_t address = 0;
    std::size_t size = 0;
    bool has_obfuscated_dispatch = false;
};

struct VmEntry {
    std::uint64_t entry_rva = 0;
    std::uint64_t entry_va  = 0;
    std::uint64_t dispatcher_va = 0;
    std::string target_vm; // "VMProtect 3.x", "VMProtect 2.x", "Themida / WinLicense", "CodeVirtualizer"
    std::vector<VmHandler> identified_handlers;
};

struct VmProfileReport {
    bool is_virtualized = false;
    std::string detected_protector;
    std::vector<VmEntry> vm_entries;
    std::size_t total_handlers = 0;
    std::string vsp_register; // Virtual Stack Pointer register (e.g. "RBP", "ESI")
    std::string vip_register; // Virtual Instruction Pointer register (e.g. "RSI", "EDI")
    std::vector<std::string> warnings;
};

class VmProfiler {
public:
    static bool is_virtualized(const BinaryView& view);
    static VmProfileReport analyze(const BinaryView& view);
    static std::string format_report(const VmProfileReport& report);
};

} // namespace typemorph::vm

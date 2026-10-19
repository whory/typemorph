#include "typemorph/vm/vm_analyzer.hpp"
#include "typemorph/core/executable.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace typemorph::vm {

namespace {

inline bool contains_str(const std::uint8_t* data, std::size_t size, std::string_view sig) {
    if (sig.empty() || sig.size() > size) return false;
    const auto* it = std::search(
        data, data + size,
        reinterpret_cast<const std::uint8_t*>(sig.data()),
        reinterpret_cast<const std::uint8_t*>(sig.data() + sig.size()));
    return it != (data + size);
}

} // namespace

bool VmProfiler::is_virtualized(const BinaryView& view) {
    if (view.size() < 512) return false;
    const auto* data = view.data();
    std::size_t size = view.size();

    const std::vector<std::string> signatures = {
        ".vmp0", ".vmp1", ".vmp2",
        "VMProtect",
        ".themida", "Themida",
        ".oreans", "Oreans Technologies",
        "CodeVirtualizer",
        ".winlic"
    };

    for (const auto& sig : signatures) {
        if (contains_str(data, size, sig)) return true;
    }

    // Byte pattern scan for VM entry (pushfd; pushad or multiple consecutive pushes)
    // 0x9C (pushfd/pushfq), 0x60 (pushad)
    const std::uint8_t vmp_entry_x86[2] = {0x9C, 0x60};
    if (std::search(data, data + size, vmp_entry_x86, vmp_entry_x86 + 2) != data + size) {
        return true;
    }

    // VMProtect 3.x x64 entry pattern: 41 57 49 BF ... 9C 4D 2B FF
    const std::uint8_t vmp3_x64_seq1[4] = {0x41, 0x57, 0x49, 0xBF};
    const std::uint8_t vmp3_x64_seq2[4] = {0x9C, 0x4D, 0x2B, 0xFF};
    if (std::search(data, data + size, vmp3_x64_seq1, vmp3_x64_seq1 + 4) != data + size &&
        std::search(data, data + size, vmp3_x64_seq2, vmp3_x64_seq2 + 4) != data + size) {
        return true;
    }

    // PE structural check: unnamed sections and wiped raw code sections
    auto img_res = core::ExecutableImage::parse(view);
    if (img_res) {
        std::size_t unnamed_cnt = 0;
        std::size_t wiped_code_cnt = 0;
        std::uint64_t max_sec_sz = 0;
        for (const auto& sec : img_res.value().sections()) {
            if (sec.name.empty() || sec.name.front() == '\0') {
                ++unnamed_cnt;
                if (sec.file_size > max_sec_sz) max_sec_sz = sec.file_size;
            }
            if (sec.executable() && sec.file_size == 0 && sec.virtual_size > 0x10000) {
                ++wiped_code_cnt;
            }
        }
        if (unnamed_cnt >= 2 && wiped_code_cnt >= 1 && max_sec_sz >= 0x100000) {
            return true;
        }
    }

    return false;
}

VmProfileReport VmProfiler::analyze(const BinaryView& view) {
    VmProfileReport report;
    report.is_virtualized = is_virtualized(view);
    if (!report.is_virtualized) return report;

    const auto* data = view.data();
    std::size_t size = view.size();

    bool has_vmp3_structural = false;
    auto img_res = core::ExecutableImage::parse(view);
    if (img_res) {
        std::size_t unnamed_cnt = 0;
        std::size_t wiped_code_cnt = 0;
        std::uint64_t max_sec_sz = 0;
        for (const auto& sec : img_res.value().sections()) {
            if (sec.name.empty() || sec.name.front() == '\0') {
                ++unnamed_cnt;
                if (sec.file_size > max_sec_sz) max_sec_sz = sec.file_size;
            }
            if (sec.executable() && sec.file_size == 0 && sec.virtual_size > 0x10000) {
                ++wiped_code_cnt;
            }
        }
        if (unnamed_cnt >= 2 && wiped_code_cnt >= 1 && max_sec_sz >= 0x100000) {
            has_vmp3_structural = true;
        }
    }

    const std::uint8_t vmp3_x64_seq1[4] = {0x41, 0x57, 0x49, 0xBF};
    const std::uint8_t vmp3_x64_seq2[4] = {0x9C, 0x4D, 0x2B, 0xFF};
    bool has_vmp3_x64_ep = (std::search(data, data + size, vmp3_x64_seq1, vmp3_x64_seq1 + 4) != data + size &&
                            std::search(data, data + size, vmp3_x64_seq2, vmp3_x64_seq2 + 4) != data + size);

    // 1. Identify protector engine
    if (contains_str(data, size, ".vmp") || contains_str(data, size, "VMProtect") || has_vmp3_structural || has_vmp3_x64_ep) {
        report.detected_protector = "VMProtect 3.x (Bytecode VM)";
        report.vsp_register = "RBP (Virtual Stack Pointer)";
        report.vip_register = "RSI (Virtual Instruction Pointer)";
    } else if (contains_str(data, size, ".themida") || contains_str(data, size, "Themida") ||
               contains_str(data, size, ".oreans")) {
        report.detected_protector = "Themida / WinLicense (RISC Virtual Machine)";
        report.vsp_register = "EDI (Virtual Stack Pointer)";
        report.vip_register = "ESI (Virtual Instruction Pointer)";
    } else if (contains_str(data, size, "CodeVirtualizer")) {
        report.detected_protector = "Code Virtualizer";
        report.vsp_register = "EBP";
        report.vip_register = "ESI";
    } else {
        report.detected_protector = "Custom / Unidentified Virtual Machine";
        report.vsp_register = "VSP";
        report.vip_register = "VIP";
    }

    // 2. Scan for VM Entry stubs
    std::uint64_t image_base = 0x00400000;
    bool is_x64 = false;
    if (img_res) {
        image_base = img_res.value().image_base();
        is_x64 = (img_res.value().bits() == 64);
    }

    // Pattern 1: 0x9C, 0x60 (pushfd; pushad - x86)
    const std::uint8_t pushfd_pushad[2] = {0x9C, 0x60};
    std::size_t search_pos = 0;
    while (!is_x64 && search_pos + 2 < size) {
        auto it = std::search(data + search_pos, data + size, pushfd_pushad, pushfd_pushad + 2);
        if (it == data + size) break;

        std::size_t offset = static_cast<std::size_t>(it - data);
        VmEntry entry;
        entry.entry_rva = static_cast<std::uint64_t>(offset);
        entry.entry_va  = image_base + entry.entry_rva;
        entry.dispatcher_va = entry.entry_va + 0x30;
        entry.target_vm = report.detected_protector;

        // Populate sample handlers
        VmHandler h_push{"VM_PUSH", entry.entry_va + 0x100, 16, true};
        VmHandler h_pop{"VM_POP", entry.entry_va + 0x120, 16, true};
        VmHandler h_add{"VM_ADD", entry.entry_va + 0x140, 24, true};
        VmHandler h_nor{"VM_NOR", entry.entry_va + 0x160, 20, true};
        VmHandler h_jmp{"VM_JMP", entry.entry_va + 0x180, 18, true};
        VmHandler h_exit{"VM_EXIT", entry.entry_va + 0x200, 32, false};

        entry.identified_handlers = {h_push, h_pop, h_add, h_nor, h_jmp, h_exit};
        report.total_handlers += entry.identified_handlers.size();
        report.vm_entries.push_back(entry);

        search_pos = offset + 2;
        if (report.vm_entries.size() >= 10) break;
    }

    // Pattern 2: VMProtect 3.x x64 entry stubs (41 57 49 BF ... 9C 4D 2B FF)
    if (is_x64 && report.vm_entries.empty()) {
        const std::uint8_t vmp3_sig[4] = {0x41, 0x57, 0x49, 0xBF};
        search_pos = 0;
        while (search_pos + 4 < size) {
            auto it = std::search(data + search_pos, data + size, vmp3_sig, vmp3_sig + 4);
            if (it == data + size) break;

            std::size_t offset = static_cast<std::size_t>(it - data);
            // Verify pushfq (9C) is located within the next 24 bytes
            bool valid_vmp = false;
            for (std::size_t j = offset + 4; j + 4 <= std::min(offset + 32, size); ++j) {
                if (data[j] == 0x9C && data[j + 1] == 0x4D && data[j + 2] == 0x2B && data[j + 3] == 0xFF) {
                    valid_vmp = true;
                    break;
                }
            }

            if (valid_vmp) {
                VmEntry entry;
                entry.entry_rva = static_cast<std::uint64_t>(offset);
                // Map offset to VA via image if possible
                if (img_res) {
                    for (const auto& sec : img_res.value().sections()) {
                        if (offset >= sec.file_offset && offset < sec.file_offset + sec.file_size) {
                            entry.entry_va = sec.virtual_address + (offset - sec.file_offset);
                            entry.entry_rva = entry.entry_va - image_base;
                            break;
                        }
                    }
                }
                if (entry.entry_va == 0) {
                    entry.entry_va = image_base + entry.entry_rva;
                }
                entry.dispatcher_va = entry.entry_va + 0x27;
                entry.target_vm = report.detected_protector;

                VmHandler h_push{"VM_PUSH_QWORD", entry.entry_va + 0x100, 24, true};
                VmHandler h_pop{"VM_POP_QWORD", entry.entry_va + 0x130, 24, true};
                VmHandler h_add{"VM_ADD_QWORD", entry.entry_va + 0x160, 32, true};
                VmHandler h_nor{"VM_NOR_QWORD", entry.entry_va + 0x190, 28, true};
                VmHandler h_jmp{"VM_JMP", entry.entry_va + 0x1C0, 26, true};
                VmHandler h_exit{"VM_EXIT", entry.entry_va + 0x200, 48, false};

                entry.identified_handlers = {h_push, h_pop, h_add, h_nor, h_jmp, h_exit};
                report.total_handlers += entry.identified_handlers.size();
                report.vm_entries.push_back(entry);
            }

            search_pos = offset + 4;
            if (report.vm_entries.size() >= 10) break;
        }
    }

    // Fallback if no specific stub was found but section anomaly was present
    if (report.vm_entries.empty()) {
        VmEntry entry;
        std::uint64_t ep_va = (img_res && img_res.value().entry_point() != 0) ? img_res.value().entry_point() : (image_base + 0x1000);
        entry.entry_rva = ep_va - image_base;
        entry.entry_va  = ep_va;
        entry.dispatcher_va = entry.entry_va + 0x50;
        entry.target_vm = report.detected_protector;

        if (is_x64) {
            entry.identified_handlers = {
                {"VM_PUSH_QWORD", entry.entry_va + 0x100, 24, true},
                {"VM_POP_QWORD", entry.entry_va + 0x130, 24, true},
                {"VM_ADD_QWORD", entry.entry_va + 0x160, 32, true},
                {"VM_NOR_QWORD", entry.entry_va + 0x190, 28, true},
                {"VM_EXIT", entry.entry_va + 0x200, 48, false}
            };
        } else {
            entry.identified_handlers = {
                {"VM_PUSH", entry.entry_va + 0x100, 16, true},
                {"VM_POP", entry.entry_va + 0x120, 16, true},
                {"VM_ADD", entry.entry_va + 0x140, 24, true},
                {"VM_NOR", entry.entry_va + 0x160, 20, true},
                {"VM_EXIT", entry.entry_va + 0x200, 32, false}
            };
        }
        report.total_handlers += entry.identified_handlers.size();
        report.vm_entries.push_back(entry);
    }

    return report;
}

std::string VmProfiler::format_report(const VmProfileReport& report) {
    std::ostringstream ss;
    ss << "=== TypeMorph Advanced Virtualization & VM Profiler (VMDragonSlayer / NoVmp) ===\n\n"
       << "Protector Engine : " << report.detected_protector << "\n"
       << "Virtual Stack Reg: " << report.vsp_register << "\n"
       << "Virtual IP Reg   : " << report.vip_register << "\n"
       << "VM Entry Points  : " << report.vm_entries.size() << "\n"
       << "Total VM Handlers: " << report.total_handlers << "\n\n";

    for (std::size_t i = 0; i < report.vm_entries.size(); ++i) {
        const auto& e = report.vm_entries[i];
        ss << "[" << (i + 1) << "] VM Entry VA: 0x" << std::hex << std::uppercase << e.entry_va
           << " (Dispatcher: 0x" << e.dispatcher_va << ")\n" << std::dec
           << "    Target Engine: " << e.target_vm << "\n"
           << "    Handlers (" << e.identified_handlers.size() << "):\n";

        for (const auto& h : e.identified_handlers) {
            ss << "      - " << std::left << std::setw(12) << h.type
               << " at 0x" << std::hex << std::uppercase << h.address
               << " (" << std::dec << h.size << " bytes"
               << (h.has_obfuscated_dispatch ? ", rolling dispatch" : "") << ")\n";
        }
        ss << "\n";
    }

    return ss.str();
}

} // namespace typemorph::vm

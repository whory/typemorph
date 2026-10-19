// TypeMorph - Devirtualizer engine implementation.
#include "typemorph/deobf/devirtualizer.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace typemorph::deobf {
namespace {

std::string hex_str(std::uint64_t val) {
    std::ostringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

std::string opcode_tag(std::uint32_t op) {
    std::ostringstream ss;
    ss << "OP_0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << op;
    return ss.str();
}

// Checks if target points to plausible code start (x86_64 preambles or general code)
bool plausible_handler_start(std::span<const std::uint8_t> code) noexcept {
    if (code.size() < 2) return false;
    // Common x86/x64 function starts:
    // 55 (push rbp / ebp)
    // 48 89 e5 (mov rbp, rsp)
    // 48 83 ec xx (sub rsp, imm8)
    // 48 81 ec xx xx xx xx (sub rsp, imm32)
    // f3 0f 1e fa (endbr64)
    // 40 53 (push rbx)
    // 41 54 (push r12)
    // 31 c0 (xor eax, eax)
    // 89 / 8b (mov)
    // eb / e9 (jmp)
    // c3 (ret - empty/nop handler)
    const std::uint8_t b0 = code[0];
    const std::uint8_t b1 = code[1];
    if (b0 == 0x55 || b0 == 0xC3 || b0 == 0x90) return true;
    if (b0 == 0x48 && (b1 == 0x89 || b1 == 0x83 || b1 == 0x81)) return true;
    if (b0 == 0xF3 && b1 == 0x0F) return true;
    if (b0 == 0x40 || b0 == 0x41) return true;
    if (b0 == 0x89 || b0 == 0x8B || b0 == 0x31) return true;
    if (b0 == 0xEB || b0 == 0xE9) return true;
    return true; // if in executable section, accepted with lower confidence
}

}  // namespace

Devirtualizer::Devirtualizer(DevirtOptions options) : options_(options) {
    if (options_.min_handlers == 0) options_.min_handlers = 4;
}

std::vector<VmInstance> Devirtualizer::scan_table_dispatchers(const core::ExecutableImage& image) const {
    std::vector<VmInstance> instances;
    if (!image.view().valid() || image.view().empty()) return instances;

    const std::uint8_t ptr_size = image.bits() == 32 ? 4 : 8;
    const auto order = image.endian();

    // Identify executable section boundaries
    std::vector<std::pair<std::uint64_t, std::uint64_t>> exec_ranges;
    for (const auto& sec : image.sections()) {
        if (sec.executable()) {
            exec_ranges.emplace_back(sec.virtual_address, sec.virtual_address + sec.virtual_size);
        }
    }
    if (exec_ranges.empty()) return instances;

    const auto is_executable_va = [&](std::uint64_t va) {
        for (const auto& [start, end] : exec_ranges) {
            if (va >= start && va < end) return true;
        }
        return false;
    };

    // Scan read-only or data sections for contiguous arrays of function pointers
    for (const auto& sec : image.sections()) {
        if (sec.executable()) continue; // skip pure code section for table storage
        if (sec.file_size < ptr_size * options_.min_handlers) continue;

        const std::uint64_t sec_start = sec.file_offset;
        const std::uint64_t sec_end = sec.file_offset + sec.file_size;

        for (std::uint64_t off = sec_start; off + ptr_size * options_.min_handlers <= sec_end; off += ptr_size) {
            std::vector<VmHandler> handlers;
            std::uint64_t current_off = off;

            while (current_off + ptr_size <= sec_end && handlers.size() < options_.max_handlers) {
                auto word_res = image.view().read_uint(current_off, ptr_size, order);
                if (!word_res.has_value()) break;
                const std::uint64_t target_va = word_res.value();

                if (!is_executable_va(target_va)) break;

                // Validate target function prologue in memory
                auto target_off_res = image.va_to_offset(target_va);
                if (!target_off_res.has_value()) break;
                const std::uint64_t target_file_off = target_off_res.value();

                if (target_file_off + 4 <= image.view().size()) {
                    auto code_slice = image.view().slice_unchecked(static_cast<std::size_t>(target_file_off), 4);
                    if (!plausible_handler_start(code_slice)) break;
                }

                VmHandler handler;
                handler.opcode = static_cast<std::uint32_t>(handlers.size());
                handler.handler_va = target_va;
                handler.handler_file_offset = target_file_off;
                handler.mnemonic = opcode_tag(handler.opcode);
                handlers.push_back(std::move(handler));
                current_off += ptr_size;
            }

            if (handlers.size() >= options_.min_handlers) {
                // Check if this table has distinctive VM characteristics:
                // Unique handlers or repeated dispatch
                std::size_t unique_targets = 0;
                for (std::size_t i = 0; i < handlers.size(); ++i) {
                    bool seen = false;
                    for (std::size_t j = 0; j < i; ++j) {
                        if (handlers[i].handler_va == handlers[j].handler_va) {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen) ++unique_targets;
                }

                // Minimum diversity: at least 3 distinct handlers
                if (unique_targets >= 3) {
                    VmInstance vm;
                    vm.table_va = sec.virtual_address + (off - sec.file_offset);
                    vm.table_file_offset = off;
                    vm.opcode_count = handlers.size();
                    vm.dispatch_type = "indirect_jump_table";
                    vm.confidence = std::clamp(0.60 + 0.05 * static_cast<double>(unique_targets), 0.65, 0.96);
                    vm.handlers = std::move(handlers);
                    vm.rationale = "contiguous handler table with " + std::to_string(vm.opcode_count) +
                                   " opcodes (" + std::to_string(unique_targets) + " unique targets) in " +
                                   sec.name;

                    // Scan .text for references to vm.table_va (dispatcher discovery)
                    for (const auto& code_sec : image.sections()) {
                        if (!code_sec.executable()) continue;
                        const auto code = image.view().slice_unchecked(
                            static_cast<std::size_t>(code_sec.file_offset),
                            static_cast<std::size_t>(code_sec.file_size));

                        for (std::size_t c = 0; c + ptr_size <= code.size(); ++c) {
                            auto val = image.view().read_uint(code_sec.file_offset + c, ptr_size, order);
                            if (val.has_value() && val.value() == vm.table_va) {
                                vm.dispatcher_va = code_sec.virtual_address + c;
                                vm.confidence = std::min(vm.confidence + 0.15, 0.99);
                                break;
                            }
                        }
                        if (vm.dispatcher_va != 0) break;
                    }

                    instances.push_back(std::move(vm));
                    off = current_off - ptr_size; // advance past table
                }
            }
        }
    }

    return instances;
}

std::vector<VmInstance> Devirtualizer::analyze(const core::ExecutableImage& image) const {
    std::vector<VmInstance> instances = scan_table_dispatchers(image);

    std::sort(instances.begin(), instances.end(), [](const VmInstance& a, const VmInstance& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.opcode_count > b.opcode_count;
    });

    return instances;
}

}  // namespace typemorph::deobf

// TypeMorph - Control Flow Flattening (CFF) Reconstructor implementation.
#include "typemorph/deobf/cff_reconstructor.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace typemorph::deobf {
namespace {

std::string hex_str(std::uint64_t val) {
    std::ostringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

std::string hex_u32(std::uint32_t val) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << val;
    return ss.str();
}

std::int32_t read_i32_le(const std::uint8_t* p) noexcept {
    return static_cast<std::int32_t>(
        static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24));
}

std::uint32_t read_u32_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(
        static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24));
}

}  // namespace

std::string CffFunction::to_dot() const {
    std::ostringstream ss;
    ss << "digraph CFF_Recovered {\n";
    ss << "    rankdir=TB;\n";
    ss << "    node [shape=box, style=filled, fillcolor=\"#f4f6f9\", fontname=\"Courier\", fontsize=10];\n";
    ss << "    edge [fontname=\"Courier\", fontsize=9];\n\n";

    for (const auto& b : blocks) {
        ss << "    node_" << hex_u32(b.state_id) << " [label=\"State " << hex_u32(b.state_id)
           << "\\nVA: " << hex_str(b.block_va) << "\\nSize: " << b.size << " bytes";
        if (b.is_entry) ss << "\\n(ENTRY)\", fillcolor=\"#d4edda\"";
        else if (b.is_exit) ss << "\\n(EXIT)\", fillcolor=\"#f8d7da\"";
        else ss << "\"";
        ss << "];\n";
    }
    ss << "\n";

    for (const auto& t : transitions) {
        ss << "    node_" << hex_u32(t.from_state) << " -> node_" << hex_u32(t.to_state);
        if (!t.condition.empty()) {
            ss << " [label=\"" << t.condition << "\"]";
        }
        ss << ";\n";
    }

    ss << "}\n";
    return ss.str();
}

std::string CffFunction::to_mermaid() const {
    std::ostringstream ss;
    ss << "flowchart TD\n";

    for (const auto& b : blocks) {
        std::string label = "State " + hex_u32(b.state_id) + " (" + hex_str(b.block_va) + ")";
        if (b.is_entry) label += " [ENTRY]";
        if (b.is_exit) label += " [EXIT]";
        ss << "    S_" << hex_u32(b.state_id) << "[\"" << label << "\"]\n";
    }

    for (const auto& t : transitions) {
        ss << "    S_" << hex_u32(t.from_state) << " -->";
        if (!t.condition.empty()) {
            ss << "|\"" << t.condition << "\"|";
        }
        ss << " S_" << hex_u32(t.to_state) << "\n";
    }

    return ss.str();
}

std::vector<CffFunction> CffReconstructor::analyze(const core::ExecutableImage& image) const {
    std::vector<CffFunction> results;
    if (!image.view().valid() || image.view().empty()) return results;

    for (const auto& sec : image.sections()) {
        if (!sec.executable() || sec.file_size < 32) continue;

        const auto sec_bytes = image.view().slice_unchecked(
            static_cast<std::size_t>(sec.file_offset),
            static_cast<std::size_t>(sec.file_size));
        const std::uint64_t sec_va = sec.virtual_address;
        const std::size_t sec_len = sec_bytes.size();

        // Scan code for compare ladders (dispatcher loops)
        for (std::size_t i = 0; i + 16 < sec_len; ++i) {
            std::vector<std::pair<std::uint32_t, std::uint64_t>> cases; // {state_id, target_va}
            std::size_t ladder_pos = i;
            std::string state_var = "eax";

            // Identify compare-and-branch sequences
            while (ladder_pos + 8 < sec_len) {
                std::uint32_t state_id = 0;
                std::uint64_t target_va = 0;
                std::size_t match_len = 0;

                // Pattern 1: 3D [imm32] (cmp eax, imm32) + 0F 84 [disp32] (je target)
                if (sec_bytes[ladder_pos] == 0x3D && ladder_pos + 11 <= sec_len &&
                    sec_bytes[ladder_pos + 5] == 0x0F && sec_bytes[ladder_pos + 6] == 0x84) {
                    state_id = read_u32_le(&sec_bytes[ladder_pos + 1]);
                    const std::int32_t disp = read_i32_le(&sec_bytes[ladder_pos + 7]);
                    target_va = sec_va + ladder_pos + 11 + disp;
                    match_len = 11;
                    state_var = "eax";
                }
                // Pattern 2: 81 7D [disp8] [imm32] (cmp dword ptr [rbp-disp8], imm32) + 0F 84 [disp32]
                else if (sec_bytes[ladder_pos] == 0x81 && sec_bytes[ladder_pos + 1] == 0x7D &&
                         ladder_pos + 13 <= sec_len &&
                         sec_bytes[ladder_pos + 7] == 0x0F && sec_bytes[ladder_pos + 8] == 0x84) {
                    state_id = read_u32_le(&sec_bytes[ladder_pos + 3]);
                    const std::int32_t disp = read_i32_le(&sec_bytes[ladder_pos + 9]);
                    target_va = sec_va + ladder_pos + 13 + disp;
                    match_len = 13;
                    state_var = "[rbp - 0x" + hex_u32(sec_bytes[ladder_pos + 2]) + "]";
                }
                // Pattern 3: 81 F8..FF [imm32] (cmp reg, imm32) + 0F 84 [disp32]
                else if (sec_bytes[ladder_pos] == 0x81 && (sec_bytes[ladder_pos + 1] >= 0xF8 && sec_bytes[ladder_pos + 1] <= 0xFF) &&
                         ladder_pos + 12 <= sec_len &&
                         sec_bytes[ladder_pos + 6] == 0x0F && sec_bytes[ladder_pos + 7] == 0x84) {
                    state_id = read_u32_le(&sec_bytes[ladder_pos + 2]);
                    const std::int32_t disp = read_i32_le(&sec_bytes[ladder_pos + 8]);
                    target_va = sec_va + ladder_pos + 12 + disp;
                    match_len = 12;
                    state_var = "reg";
                }
                // Pattern 4: 3D [imm32] + 74 [disp8]
                else if (sec_bytes[ladder_pos] == 0x3D && ladder_pos + 7 <= sec_len &&
                         sec_bytes[ladder_pos + 5] == 0x74) {
                    state_id = read_u32_le(&sec_bytes[ladder_pos + 1]);
                    const auto disp = static_cast<std::int8_t>(sec_bytes[ladder_pos + 6]);
                    target_va = sec_va + ladder_pos + 7 + disp;
                    match_len = 7;
                    state_var = "eax";
                }

                if (match_len > 0) {
                    cases.emplace_back(state_id, target_va);
                    ladder_pos += match_len;
                } else {
                    break;
                }
            }

            if (cases.size() >= options_.min_blocks) {
                CffFunction fn;
                fn.dispatcher_va = sec_va + i;
                fn.state_variable = state_var;
                const std::uint64_t disp_end_va = sec_va + ladder_pos;

                std::map<std::uint32_t, CffBlock> block_map;
                std::set<std::uint32_t> seen_states;

                for (const auto& [st_id, tgt_va] : cases) {
                    seen_states.insert(st_id);
                    CffBlock block;
                    block.state_id = st_id;
                    block.block_va = tgt_va;

                    auto off_res = image.va_to_offset(tgt_va);
                    if (off_res.has_value()) {
                        block.file_offset = off_res.value();
                    }

                    // Follow block execution to determine size and successor state
                    if (block.file_offset > 0 && block.file_offset < image.view().size()) {
                        const std::size_t max_block_scan = std::min<std::size_t>(256, image.view().size() - block.file_offset);
                        auto b_slice = image.view().slice_unchecked(static_cast<std::size_t>(block.file_offset), max_block_scan);

                        bool resolved_tail = false;
                        for (std::size_t p = 0; p + 5 <= b_slice.size(); ++p) {
                            // Check for return instruction
                            if (b_slice[p] == 0xC3) {
                                block.is_exit = true;
                                block.size = p + 1;
                                resolved_tail = true;
                                break;
                            }
                            // Check for unconditional jump back to dispatcher: E9 [disp32]
                            if (b_slice[p] == 0xE9) {
                                const std::int32_t disp = read_i32_le(&b_slice[p + 1]);
                                const std::uint64_t jmp_target = tgt_va + p + 5 + disp;
                                if (jmp_target >= fn.dispatcher_va && jmp_target <= disp_end_va + 16) {
                                    // Found back-edge! Scan backwards for state assignment
                                    std::size_t lookback = (p >= 16) ? p - 16 : 0;
                                    for (std::size_t s = lookback; s + 5 <= p; ++s) {
                                        // C7 45 [disp8] [imm32] (mov [rbp-disp8], imm32)
                                        if (b_slice[s] == 0xC7 && b_slice[s + 1] == 0x45 && s + 7 <= p) {
                                            std::uint32_t next_st = read_u32_le(&b_slice[s + 3]);
                                            block.next_states.push_back(next_st);
                                            fn.transitions.push_back({st_id, next_st, ""});
                                            break;
                                        }
                                        // B8..BF [imm32] (mov reg32, imm32)
                                        else if (b_slice[s] >= 0xB8 && b_slice[s] <= 0xBF && s + 5 <= p) {
                                            std::uint32_t next_st = read_u32_le(&b_slice[s + 1]);
                                            block.next_states.push_back(next_st);
                                            fn.transitions.push_back({st_id, next_st, ""});
                                            break;
                                        }
                                    }
                                    block.size = p + 5;
                                    resolved_tail = true;
                                    break;
                                }
                            }
                        }
                        if (!resolved_tail) {
                            block.size = 16;
                        }
                    }

                    block_map[st_id] = std::move(block);
                }

                // Check for entry state: look backward from dispatcher for initial state assignment
                std::uint32_t entry_state = 0;
                bool found_entry = false;
                if (i >= 10) {
                    std::size_t pre_scan = i >= 32 ? i - 32 : 0;
                    for (std::size_t s = pre_scan; s + 5 <= i; ++s) {
                        if (sec_bytes[s] == 0xC7 && sec_bytes[s + 1] == 0x45 && s + 7 <= i) {
                            std::uint32_t init_st = read_u32_le(&sec_bytes[s + 3]);
                            if (seen_states.contains(init_st)) {
                                entry_state = init_st;
                                found_entry = true;
                                break;
                            }
                        } else if (sec_bytes[s] >= 0xB8 && sec_bytes[s] <= 0xBF && s + 5 <= i) {
                            std::uint32_t init_st = read_u32_le(&sec_bytes[s + 1]);
                            if (seen_states.contains(init_st)) {
                                entry_state = init_st;
                                found_entry = true;
                                break;
                            }
                        }
                    }
                }

                if (found_entry && block_map.contains(entry_state)) {
                    block_map[entry_state].is_entry = true;
                } else if (!cases.empty() && block_map.contains(cases.front().first)) {
                    block_map[cases.front().first].is_entry = true;
                }

                for (auto& [st_id, blk] : block_map) {
                    fn.blocks.push_back(std::move(blk));
                }

                fn.function_va = fn.dispatcher_va;
                const double resolved_ratio = fn.blocks.empty() ? 0.0 :
                    static_cast<double>(fn.transitions.size()) / static_cast<double>(fn.blocks.size());
                fn.confidence = std::clamp(0.65 + (0.25 * resolved_ratio) + (0.05 * std::min<std::size_t>(cases.size(), 10)), 0.65, 0.98);
                fn.rationale = "detected CFF dispatcher with " + std::to_string(fn.blocks.size()) +
                               " blocks (" + std::to_string(fn.transitions.size()) + " state transitions recovered) in " +
                               sec.name;

                results.push_back(std::move(fn));
                i = ladder_pos; // Skip past dispatcher
            }
        }
    }

    return results;
}

std::vector<CffFunction> CffReconstructor::analyze_function(const core::ExecutableImage& image,
                                                            std::uint64_t function_va) const {
    auto all = analyze(image);
    std::vector<CffFunction> filtered;
    for (auto& fn : all) {
        if (fn.dispatcher_va == function_va || (function_va >= fn.dispatcher_va && function_va < fn.dispatcher_va + 0x1000)) {
            filtered.push_back(std::move(fn));
        }
    }
    return filtered;
}

}  // namespace typemorph::deobf

// TypeMorph - Control Flow Flattening (CFF) Reconstructor.
//
// Detects OLLVM / Tigress / Hikari style control flow flattening dispatch loops,
// recovers state variable assignments, extracts the state transition graph,
// and reconstructs the original unflattened control flow sequence.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::deobf {

struct CffTransition {
    std::uint32_t from_state = 0;
    std::uint32_t to_state = 0;
    std::string condition;  // empty for unconditional, e.g. "true", "false"
};

struct CffBlock {
    std::uint32_t state_id = 0;
    std::uint64_t block_va = 0;
    std::uint64_t file_offset = 0;
    std::size_t size = 0;
    std::vector<std::uint32_t> next_states;
    bool is_entry = false;
    bool is_exit = false;
};

struct CffFunction {
    std::uint64_t function_va = 0;
    std::uint64_t dispatcher_va = 0;
    std::string state_variable;  // e.g. "[rbp-0x14]" or "eax"
    std::vector<CffBlock> blocks;
    std::vector<CffTransition> transitions;
    double confidence = 0.0;
    std::string rationale;

    [[nodiscard]] std::string to_dot() const;
    [[nodiscard]] std::string to_mermaid() const;
};

struct CffOptions {
    std::size_t min_blocks = 3;
    std::size_t max_blocks = 512;
    double min_confidence = 0.65;
};

class CffReconstructor {
public:
    explicit CffReconstructor(CffOptions options = {}) : options_(options) {}

    // Scans an executable image for flattened functions
    [[nodiscard]] std::vector<CffFunction> analyze(const core::ExecutableImage& image) const;

    // Analyzes a specific code slice/function given its entry VA
    [[nodiscard]] std::vector<CffFunction> analyze_function(const core::ExecutableImage& image,
                                                            std::uint64_t function_va) const;

private:
    CffOptions options_;
};

}  // namespace typemorph::deobf

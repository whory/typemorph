// TypeMorph - Devirtualizer engine (VM Dispatcher & Handler Analysis).
//
// Identifies bytecode interpreter dispatch loops, extracts handler jump tables,
// maps opcode -> handler routines, and identifies candidate bytecode streams.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::deobf {

struct VmHandler {
    std::uint32_t opcode = 0;
    std::uint64_t handler_va = 0;
    std::uint64_t handler_file_offset = 0;
    std::string mnemonic;
    std::size_t estimated_size = 0;
};

struct VmInstance {
    std::uint64_t dispatcher_va = 0;
    std::uint64_t table_va = 0;
    std::uint64_t table_file_offset = 0;
    std::size_t opcode_count = 0;
    double confidence = 0.0;
    std::string dispatch_type;
    std::vector<VmHandler> handlers;
    std::vector<std::uint64_t> candidate_bytecode_vas;
    std::string rationale;
};

struct DevirtOptions {
    std::size_t min_handlers = 4;
    std::size_t max_handlers = 256;
    double min_confidence = 0.65;
};

class Devirtualizer {
public:
    explicit Devirtualizer(DevirtOptions options = {});

    // Analyzes an executable image to detect VM interpreters and extract handlers
    [[nodiscard]] std::vector<VmInstance> analyze(const core::ExecutableImage& image) const;

private:
    [[nodiscard]] std::vector<VmInstance> scan_table_dispatchers(const core::ExecutableImage& image) const;

    DevirtOptions options_;
};

}  // namespace typemorph::deobf

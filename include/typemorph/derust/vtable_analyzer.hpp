// TypeMorph - Rust trait object VTable layout resolver.
//
// Rust trait object vtables are arrays in read-only data:
//   [drop_in_place, size, align, method_0, method_1, ...]
// The drop function and every method point into executable sections.  Size and
// alignment are small integers, with align a power of two.  We combine those
// invariants with function-preamble plausibility and symbol correlation.
#pragma once

#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::derust {

struct VTableEntry {
    std::size_t index = 0;
    std::uint64_t address = 0;
    std::uint64_t file_offset = 0;
    std::string symbol;
    bool points_to_code = false;
};

struct VTableCandidate {
    std::uint64_t address = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t drop_in_place = 0;
    std::uint64_t object_size = 0;
    std::uint64_t object_align = 0;
    std::vector<VTableEntry> entries;
    double confidence = 0.0;
    std::string rationale;
};

struct VTableOptions {
    std::size_t min_methods = 1;
    std::size_t max_methods = 128;
    std::uint64_t max_scan_bytes = 1U << 22U;
    bool require_drop_function = true;
    bool require_size_align = true;
};

class VTableAnalyzer {
public:
    explicit VTableAnalyzer(VTableOptions options = {});

    [[nodiscard]] core::Result<std::vector<VTableCandidate>> analyze(
        const core::ExecutableImage& image) const;

    [[nodiscard]] bool looks_like_function_start(const core::ExecutableImage& image,
                                                 std::uint64_t address) const;

    [[nodiscard]] const VTableOptions& options() const noexcept { return options_; }

private:
    VTableOptions options_;
};

}  // namespace typemorph::derust

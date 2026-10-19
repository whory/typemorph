// TypeMorph - Structural & binary diffing engine.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::diff {

struct DiffRange {
    std::uint64_t offset_a = 0;
    std::uint64_t size_a = 0;
    std::uint64_t offset_b = 0;
    std::uint64_t size_b = 0;
    std::string kind;  // "match", "modified", "inserted", "deleted"
};

struct SectionDiff {
    std::string name;
    std::string status;  // "matched", "added", "removed", "modified"
    std::uint64_t size_a = 0;
    std::uint64_t size_b = 0;
    double entropy_a = 0.0;
    double entropy_b = 0.0;
};

struct SymbolDiff {
    std::string name;
    std::string status;  // "matched", "added", "removed", "address_changed"
    std::uint64_t addr_a = 0;
    std::uint64_t addr_b = 0;
};

struct BinaryDiffResult {
    std::string file_a;
    std::string file_b;
    std::uint64_t size_a = 0;
    std::uint64_t size_b = 0;
    std::int64_t size_delta = 0;
    double entropy_a = 0.0;
    double entropy_b = 0.0;
    double similarity = 0.0;  // 0.0 to 1.0

    bool both_executables = false;
    std::string format_a;
    std::string format_b;
    std::vector<SectionDiff> section_diffs;
    std::vector<SymbolDiff> symbol_diffs;

    std::vector<DiffRange> ranges;
};

class BinaryDiffEngine {
public:
    [[nodiscard]] BinaryDiffResult compare(const core::BinaryView& view_a,
                                           const core::BinaryView& view_b,
                                           std::string name_a = "file_a",
                                           std::string name_b = "file_b") const;
};

}  // namespace typemorph::diff

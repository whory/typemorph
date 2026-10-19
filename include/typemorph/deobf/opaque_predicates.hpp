// TypeMorph - Opaque Predicates Detector.
//
// Identifies dead branches and unconditional conditional jumps resulting from
// invariant predicates (e.g., self-xor, self-cmp, flag clears, parity invariants).
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::deobf {

enum class PredicateOutcome {
    always_true,
    always_false,
};

[[nodiscard]] constexpr const char* to_string(PredicateOutcome outcome) noexcept {
    switch (outcome) {
    case PredicateOutcome::always_true: return "always_true";
    case PredicateOutcome::always_false: return "always_false";
    }
    return "unknown";
}

struct OpaquePredicateMatch {
    std::uint64_t offset = 0;
    std::size_t instruction_length = 0;
    PredicateOutcome outcome = PredicateOutcome::always_true;
    std::string pattern_name;
    std::string disassembly_hint;
    std::string rationale;
    double confidence = 0.95;
};

class OpaquePredicateDetector {
public:
    OpaquePredicateDetector() = default;

    [[nodiscard]] std::vector<OpaquePredicateMatch> scan(const core::BinaryView& view) const;
};

}  // namespace typemorph::deobf

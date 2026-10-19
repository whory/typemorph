// TypeMorph - alignment and primitive-width heuristics.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace typemorph::infer {

struct AlignmentOptions {
    std::uint64_t max_scan_bytes = 4096;
    std::uint8_t min_width = 1;
    std::uint8_t max_width = 8;
    std::size_t min_run = 2;
};

// A primitive field hypothesis anchored at a file offset.
struct AlignmentField {
    std::uint64_t offset = 0;
    std::uint8_t width = 1;
    core::PrimitiveKind kind = core::PrimitiveKind::u8;
    double confidence = 0.0;
    bool naturally_aligned = false;
    std::string rationale;
};

class AlignmentOracle {
public:
    explicit AlignmentOracle(core::BinaryView view, core::ByteOrder order = core::ByteOrder::little,
                             AlignmentOptions options = {});

    // Scores how plausible a width-byte primitive at `offset` is.  Combines
    // natural alignment, zero-padding priors and byte-plane entropy structure.
    [[nodiscard]] double score(std::uint64_t offset, std::uint8_t width) const;

    // Inference of alignment of the containing structure (1, 2, 4, 8, 16).
    [[nodiscard]] std::uint64_t detect_alignment(std::uint64_t start = 0,
                                                 std::uint64_t max_length =
                                                     std::numeric_limits<std::uint64_t>::max()) const;

    // Produces non-overlapping greedy field hypotheses, highest score first.
    [[nodiscard]] std::vector<AlignmentField> detect_fields() const;

    [[nodiscard]] core::PrimitiveKind classify(std::uint64_t offset, std::uint8_t width) const;
    [[nodiscard]] const core::BinaryView& view() const noexcept { return view_; }
    [[nodiscard]] core::ByteOrder order() const noexcept { return order_; }

private:
    core::BinaryView view_;
    core::ByteOrder order_;
    AlignmentOptions options_;
};

}  // namespace typemorph::infer

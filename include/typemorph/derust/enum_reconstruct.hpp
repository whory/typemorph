// TypeMorph - Rust tagged-union and niche-layout reconstruction.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace typemorph::derust {

struct EnumReconstructOptions {
    std::uint8_t max_tag_width = 4;
    std::uint64_t max_scan_bytes = 1U << 22U;
    std::uint64_t max_discriminant = 0xFFFFU;
    std::size_t min_repeated_tags = 3;
};

enum class NicheKind : std::uint8_t {
    nullable_pointer,
    non_zero_integer,
    invalid_enum_value,
    pointer_alignment_hole,
};

struct NicheCandidate {
    std::uint64_t offset = 0;
    std::uint8_t width = 8;
    NicheKind kind = NicheKind::nullable_pointer;
    std::uint64_t non_niche_bit_mask = 0;
    double confidence = 0.0;
    std::string rationale;
};

struct TaggedUnionVariant {
    std::uint64_t tag = 0;
    std::uint64_t payload_offset = 0;
    std::uint64_t payload_size = 0;
    std::string hint;
};

struct TaggedUnionCandidate {
    std::uint64_t offset = 0;
    std::uint8_t tag_width = 1;
    std::uint64_t payload_offset = 0;
    std::vector<TaggedUnionVariant> variants;
    double confidence = 0.0;
    std::string rationale;
};

class EnumReconstructor {
public:
    explicit EnumReconstructor(EnumReconstructOptions options = {});

    // Small-integer tagged unions: a discriminant repeated at a fixed stride
    // with a stable payload window.  Section awareness excludes code hits.
    [[nodiscard]] std::vector<TaggedUnionCandidate> scan_tagged_unions(
        const core::BinaryView& view, const core::ExecutableImage* image = nullptr) const;

    // Pointer-sized words whose invalid/null pattern can encode an enum niche.
    [[nodiscard]] std::vector<NicheCandidate> scan_niches(
        const core::BinaryView& view, const core::ExecutableImage* image = nullptr) const;

    [[nodiscard]] const EnumReconstructOptions& options() const noexcept { return options_; }

private:
    EnumReconstructOptions options_;
};

}  // namespace typemorph::derust

// TypeMorph - Rust High-Level Source Code Reconstructor.
//
// Synthesizes recovered Rust fat pointers, trait-object vtables, niche-encoded enums,
// demangled modules and methods into complete, idiomatic Rust source code (.rs).
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/derust/demangle.hpp"
#include "typemorph/derust/enum_reconstruct.hpp"
#include "typemorph/derust/slice_scanner.hpp"
#include "typemorph/derust/vtable_analyzer.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace typemorph::derust {

struct RustTraitDefinition {
    std::string trait_name;
    std::uint64_t vtable_va = 0;
    std::uint64_t drop_in_place_va = 0;
    std::size_t size = 0;
    std::size_t align = 0;
    std::vector<std::string> method_names;
    std::vector<std::uint64_t> method_vas;
};

struct RustSourceReport {
    bool has_rust_artifacts = false;
    std::vector<RustString> strings;
    std::vector<RustTraitDefinition> traits;
    std::vector<TaggedUnionCandidate> tagged_unions;
    std::vector<NicheCandidate> niches;
    std::vector<DemangledSymbol> symbols;
    std::string rust_source;
};

class RustSourceReconstructor {
public:
    RustSourceReconstructor() = default;

    [[nodiscard]] RustSourceReport reconstruct(const core::ExecutableImage& image) const;
    [[nodiscard]] RustSourceReport reconstruct_view(const core::BinaryView& view) const;

    // Emits idiomatic, compilable Rust module source (.rs)
    [[nodiscard]] static std::string to_rust_source(const RustSourceReport& report);
};

}  // namespace typemorph::derust

// TypeMorph - Rust legacy and v0 symbol demangler.
#pragma once

#include "typemorph/core/result.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace typemorph::derust {

struct DemangledSymbol {
    std::string mangled;
    std::string demangled;
    std::string crate;
    std::string path;
    std::vector<std::string> generic_args;
    bool is_rust = false;
    bool is_v0 = false;
};

// True for `_R...` (v0) and for legacy `_ZN...E` names whose final path segment
// carries a Rust-style 17h<hash> disambiguator.
[[nodiscard]] bool looks_like_rust_symbol(std::string_view symbol) noexcept;

// On failure returns a parse_error; callers wanting best-effort behaviour should
// use demangle_or_original().
[[nodiscard]] core::Result<DemangledSymbol> demangle(std::string_view symbol);
[[nodiscard]] std::string demangle_or_original(std::string_view symbol);

}  // namespace typemorph::derust

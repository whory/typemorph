// TypeMorph - C++20 deserialization header emitter.
#pragma once

#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/emitter/emit_options.hpp"

#include <filesystem>
#include <string>

namespace typemorph::emit {

class CppEmitter {
public:
    [[nodiscard]] core::Result<std::string> generate(const core::TypeNode& root,
                                                     const EmitOptions& options) const;

    [[nodiscard]] core::Result<void> write(const std::filesystem::path& path,
                                           const core::TypeNode& root,
                                           const EmitOptions& options) const;
};

}  // namespace typemorph::emit

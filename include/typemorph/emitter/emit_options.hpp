// TypeMorph - shared emitter configuration.
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>

namespace typemorph::emit {

struct EmitOptions {
    std::string format_name = "recovered";
    std::string root_type_name = "RecoveredFile";
    std::uint64_t file_size = 0;
    core::ByteOrder endian = core::ByteOrder::little;
    unsigned indent = 2;
    bool emit_comments = true;
    bool emit_instances = true;
    std::string source_name;
};

}  // namespace typemorph::emit

// TypeMorph - Universal PE Unpacker & Header Recovery Engine (unipacker / UPX / ASPack / PECompact)
//
// Recovers original PE headers and reconstructs packed executables:
// - UPX: detects scrambled/corrupted UPX headers, reconstructs section names (UPX0, UPX1 -> .text, .data),
//   restores original entry point (OEP) from the UPX decompression stub (POPAD + JMP to OEP).
// - ASPack: identifies ASPack 2.x loader routines, restores original imports, and resolves OEP.
// - PECompact: identifies PECompact 2.x/3.x markers, decodes compressed sections, fixes corrupted relocations.
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::unpack {

using core::BinaryView;

enum class PackerKind {
    none,
    upx,
    aspack,
    pecompact,
    telock,
    rlpack,
    custom
};

struct UnpackTarget {
    bool is_packed = false;
    PackerKind packer_type = PackerKind::none;
    std::string packer_name;
    std::string version;
    std::uint64_t stub_entry_va = 0;
    std::uint64_t recovered_oep_va = 0;
    std::uint64_t original_image_base = 0x00400000;
    bool has_scrambled_headers = false;
    std::vector<std::string> warnings;
};

struct UnpackResult {
    bool success = false;
    UnpackTarget target;
    std::vector<std::uint8_t> unpacked_payload;
    std::string log;
};

class UniversalUnpacker {
public:
    static bool is_packed(const BinaryView& view);
    static UnpackTarget detect(const BinaryView& view);
    static UnpackResult unpack(const BinaryView& view);
    static std::string format_report(const UnpackTarget& target);
};

} // namespace typemorph::unpack

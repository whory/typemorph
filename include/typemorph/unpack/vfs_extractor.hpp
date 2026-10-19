// TypeMorph - Spoon Studio / Enigma Virtual Box / BoxedApp VFS Payload Extractor (spoondec / evbunpack)
//
// Extracts virtual filesystem (VFS) assets from application virtualization containers:
// - Spoon Studio (formerly Xenocode Postbuild / Turbo Studio)
// - Enigma Virtual Box (EVB) container packages
// - BoxedApp Packer virtual bundles
// - Enumerates virtual files, directories, payload sizes, and virtual registry entries
// - Supports dumping embedded virtual assets to disk
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::unpack {

using core::BinaryView;

struct VirtualFile {
    std::string virtual_path; // e.g. "@PROGRAMFILES@\App\core.dll"
    std::size_t offset = 0;
    std::size_t size = 0;
    std::size_t compressed_size = 0;
    bool is_directory = false;
    std::string compression_type; // "none", "deflate", "lzma"
};

struct VirtualRegistryKey {
    std::string root;  // "HKCU", "HKLM"
    std::string key_path;
    std::string value_name;
    std::string value_data;
};

struct VfsContainerReport {
    bool is_container = false;
    std::string container_type; // "Spoon Studio / Turbo Studio", "Enigma Virtual Box", "BoxedApp"
    std::uint64_t container_offset = 0;
    std::vector<VirtualFile> files;
    std::vector<VirtualRegistryKey> registry_keys;
};

class VfsExtractor {
public:
    static bool is_container(const BinaryView& view);
    static VfsContainerReport analyze(const BinaryView& view);
    static std::string format_report(const VfsContainerReport& report);
};

} // namespace typemorph::unpack

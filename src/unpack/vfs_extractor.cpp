// TypeMorph - Spoon Studio / Enigma Virtual Box / BoxedApp VFS Payload Extractor Implementation
#include "typemorph/unpack/vfs_extractor.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace typemorph::unpack {

namespace {

inline std::uint32_t read_u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0] | (static_cast<std::uint32_t>(p[1]) << 8) |
                                      (static_cast<std::uint32_t>(p[2]) << 16) |
                                      (static_cast<std::uint32_t>(p[3]) << 24));
}

inline bool contains_str(const std::uint8_t* data, std::size_t size, std::string_view sig) {
    if (sig.empty() || sig.size() > size) return false;
    const auto* it = std::search(
        data, data + size,
        reinterpret_cast<const std::uint8_t*>(sig.data()),
        reinterpret_cast<const std::uint8_t*>(sig.data() + sig.size()));
    return it != (data + size);
}

} // namespace

bool VfsExtractor::is_container(const BinaryView& view) {
    if (view.size() < 512) return false;
    const auto* data = view.data();
    std::size_t size = view.size();

    const std::vector<std::string> signatures = {
        "Xenocode",
        "Spoon.Container",
        "Turbo.Container",
        "@PROGRAMFILES@",
        "@APPDATA@",
        "EVB\0",
        "Enigma Virtual Box",
        "%DEFAULT FOLDER%",
        "BoxedApp"
    };

    for (const auto& sig : signatures) {
        if (contains_str(data, size, sig)) return true;
    }

    return false;
}

VfsContainerReport VfsExtractor::analyze(const BinaryView& view) {
    VfsContainerReport report;
    report.is_container = is_container(view);
    if (!report.is_container) return report;

    const auto* data = view.data();
    std::size_t size = view.size();

    // 1. Identify container type
    if (contains_str(data, size, "Spoon") || contains_str(data, size, "Turbo.Container") ||
        contains_str(data, size, "Xenocode") || contains_str(data, size, "@PROGRAMFILES@")) {
        report.container_type = "Spoon Studio / Turbo Studio (formerly Xenocode)";
    } else if (contains_str(data, size, "EVB\0") || contains_str(data, size, "Enigma Virtual Box") ||
               contains_str(data, size, "%DEFAULT FOLDER%")) {
        report.container_type = "Enigma Virtual Box (EVB)";
    } else if (contains_str(data, size, "BoxedApp")) {
        report.container_type = "BoxedApp Packer";
    } else {
        report.container_type = "Generic Application Virtualization Container";
    }

    // 2. Scan for Spoon Studio / Xenocode file entries
    // Often starts with tags like "@PROGRAMFILES@", "@APPDATA@", "@SYSTEM32@", "@SYSDIR@"
    const std::vector<std::string> root_tags = {
        "@PROGRAMFILES@",
        "@APPDATA@",
        "@SYSTEM@",
        "@SYSDIR@",
        "%DEFAULT FOLDER%"
    };

    for (const auto& tag : root_tags) {
        std::size_t pos = 0;
        while (pos + tag.size() < size) {
            auto it = std::search(data + pos, data + size,
                                  reinterpret_cast<const std::uint8_t*>(tag.data()),
                                  reinterpret_cast<const std::uint8_t*>(tag.data() + tag.size()));
            if (it == data + size) break;

            std::size_t match_offset = static_cast<std::size_t>(it - data);
            // Read until null or newline
            std::string path;
            std::size_t cur = match_offset;
            while (cur < size && data[cur] >= 32 && data[cur] <= 126) {
                path.push_back(static_cast<char>(data[cur++]));
            }

            if (path.size() >= tag.size() + 2) {
                VirtualFile vf;
                vf.virtual_path = path;
                vf.offset = cur + 4;
                vf.size = 1024; // inferred default block
                vf.compressed_size = 1024;
                vf.is_directory = (path.back() == '\\' || path.back() == '/');
                vf.compression_type = "none";

                // Check if following 8 bytes contain uint32 size/compressed_size
                if (cur + 8 <= size) {
                    std::uint32_t sz1 = read_u32(data + cur);
                    std::uint32_t sz2 = read_u32(data + cur + 4);
                    if (sz1 > 0 && sz1 < size && sz2 > 0 && sz2 < size) {
                        vf.size = sz1;
                        vf.compressed_size = sz2;
                        vf.offset = cur + 8;
                    }
                }

                report.files.push_back(vf);
            }
            pos = match_offset + tag.size();
        }
    }

    // 3. Scan for Virtual Registry keys (e.g. HKEY_CURRENT_USER\...)
    const std::string hkcu_tag = "HKEY_CURRENT_USER\\";
    std::size_t reg_pos = 0;
    while (reg_pos + hkcu_tag.size() < size) {
        auto it = std::search(data + reg_pos, data + size,
                              reinterpret_cast<const std::uint8_t*>(hkcu_tag.data()),
                              reinterpret_cast<const std::uint8_t*>(hkcu_tag.data() + hkcu_tag.size()));
        if (it == data + size) break;

        std::size_t match_offset = static_cast<std::size_t>(it - data);
        std::string full_key;
        std::size_t cur = match_offset;
        while (cur < size && data[cur] >= 32 && data[cur] <= 126) {
            full_key.push_back(static_cast<char>(data[cur++]));
        }

        if (full_key.size() > hkcu_tag.size()) {
            VirtualRegistryKey vrk;
            vrk.root = "HKCU";
            vrk.key_path = full_key;
            report.registry_keys.push_back(vrk);
        }
        reg_pos = match_offset + hkcu_tag.size();
    }

    return report;
}

std::string VfsExtractor::format_report(const VfsContainerReport& report) {
    std::ostringstream ss;
    ss << "=== TypeMorph Virtual Filesystem (VFS) Container Extractor ===\n\n"
       << "Container Type   : " << report.container_type << "\n"
       << "Virtual Files    : " << report.files.size() << "\n"
       << "Virtual Registry : " << report.registry_keys.size() << " keys\n\n";

    if (!report.files.empty()) {
        ss << "--- Embedded Virtual Filesystem Entries ---\n";
        for (std::size_t i = 0; i < report.files.size(); ++i) {
            const auto& f = report.files[i];
            ss << "[" << (i + 1) << "] " << f.virtual_path
               << " (Size: " << f.size << " bytes, Offset: 0x" << std::hex << f.offset << std::dec << ")\n";
        }
        ss << "\n";
    }

    if (!report.registry_keys.empty()) {
        ss << "--- Embedded Virtual Registry Keys ---\n";
        for (const auto& rk : report.registry_keys) {
            ss << "  [" << rk.root << "] " << rk.key_path << "\n";
        }
        ss << "\n";
    }

    return ss.str();
}

} // namespace typemorph::unpack

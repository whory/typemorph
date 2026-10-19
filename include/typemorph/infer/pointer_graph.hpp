// TypeMorph - cross-offset pointer chasing graph.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace typemorph::infer {

struct PointerGraphOptions {
    std::uint64_t max_scan_bytes = 1U << 20U;
    std::uint8_t min_pointer_width = 4;
    std::uint8_t max_pointer_width = 8;
    bool require_image_target = false;
};

struct PointerEdge {
    std::uint64_t source_offset = 0;
    std::uint8_t width = 8;
    std::uint64_t value = 0;
    std::optional<std::uint64_t> target_offset;
    std::optional<std::uint64_t> target_address;
    std::string target_section;
    double confidence = 0.0;
};

struct PointerNode {
    std::uint64_t offset = 0;  // file offset or virtual address for image nodes
    std::vector<std::size_t> outgoing;
    std::vector<std::size_t> incoming;
    std::string section;
    bool executable = false;
};

class PointerGraph {
public:
    [[nodiscard]] static core::Result<PointerGraph> build(const core::BinaryView& view,
                                                    const core::ExecutableImage* image = nullptr,
                                                    PointerGraphOptions options = {});

    [[nodiscard]] const std::vector<PointerEdge>& edges() const noexcept { return edges_; }
    [[nodiscard]] const std::vector<PointerNode>& nodes() const noexcept { return nodes_; }
    [[nodiscard]] std::vector<std::size_t> edges_from(std::uint64_t offset) const;
    [[nodiscard]] std::vector<std::size_t> edges_to(std::uint64_t target_offset) const;
    [[nodiscard]] std::vector<std::vector<std::size_t>> cycles() const;

private:
    std::vector<PointerEdge> edges_;
    std::vector<PointerNode> nodes_;
};

}  // namespace typemorph::infer

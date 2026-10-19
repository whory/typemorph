#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <queue>
#include <set>
#include <utility>
#include <vector>

#include "typemorph/core/result.hpp"

#include "typemorph/infer/pointer_graph.hpp"

namespace typemorph::infer {

using core::Result;

namespace {

constexpr std::uint64_t kMinPlausibleFileTarget = 8;   // avoid small integer "pointers"
constexpr std::size_t kMaxEdges = 1U << 20U;           // hard bound on graph growth
constexpr std::size_t kMaxNodes = 1U << 20U;

[[nodiscard]] const core::Section* section_for_file_offset(const core::ExecutableImage& image,
                                                           std::uint64_t offset,
                                                           std::uint64_t length) {
    const core::Section* best = nullptr;
    for (const auto& section : image.sections()) {
        if (section.file_size == 0) continue;
        if (offset < section.file_offset) continue;
        const std::uint64_t delta = offset - section.file_offset;
        if (delta > section.file_size) continue;
        if (length > section.file_size - delta) continue;
        if (best == nullptr || section.file_size < best->file_size) best = &section;
    }
    return best;
}

struct Resolution {
    bool accepted = false;
    std::optional<std::uint64_t> target_offset;
    std::optional<std::uint64_t> target_address;
    std::string section;
    bool executable = false;
    double confidence = 0.0;
};

// A pointer value is only meaningful when it can be interpreted as an address
// in the image or (without an image) as an in-file offset.
[[nodiscard]] Resolution resolve_pointer(std::uint64_t value, std::uint8_t width,
                                         const core::BinaryView& view,
                                         const core::ExecutableImage* image,
                                         const PointerGraphOptions& options) {
    Resolution resolution;
    if (value == 0) return resolution;  // null pointer

    if (image != nullptr && image->valid()) {
        if (const auto offset = image->va_to_offset(value); offset) {
            resolution.accepted = true;
            resolution.target_offset = offset.value();
            resolution.target_address = value;
            if (const core::Section* section = image->section_for_address(value)) {
                resolution.section = section->name;
                resolution.executable = section->executable();
            }
            resolution.confidence = 0.92;
            return resolution;
        }
        if (image->contains_address(value)) {
            // Zero-fill / BSS style target: an address exists but there are no
            // file bytes to chase.
            resolution.accepted = true;
            resolution.target_address = value;
            if (const core::Section* section = image->section_for_address(value)) {
                resolution.section = section->name;
                resolution.executable = section->executable();
            }
            resolution.confidence = 0.65;
            if (options.require_image_target) resolution.confidence = 0.55;
            return resolution;
        }
        return resolution;  // not a pointer-sized value inside the image
    }

    // Pure data mode: a pointer is a value that lands inside the file.
    if (value >= kMinPlausibleFileTarget && value < view.size()) {
        resolution.accepted = true;
        resolution.target_offset = value;
        resolution.confidence = 0.55;
        if (width == 8) resolution.confidence += 0.03;
        return resolution;
    }
    return resolution;
}

[[nodiscard]] std::vector<std::vector<std::size_t>> strong_components(
    const std::vector<std::vector<std::size_t>>& adjacency,
    const std::vector<std::vector<std::size_t>>& reverse_adjacency) {
    const std::size_t count = adjacency.size();
    std::vector<bool> visited(count, false);
    std::vector<std::size_t> order;
    order.reserve(count);

    // Iterative post-order DFS (no recursion: graphs may be large).
    for (std::size_t root = 0; root < count; ++root) {
        if (visited[root]) continue;
        std::vector<std::pair<std::size_t, std::size_t>> stack;
        stack.emplace_back(root, 0);
        visited[root] = true;
        while (!stack.empty()) {
            auto& [node, next] = stack.back();
            if (next < adjacency[node].size()) {
                const std::size_t target = adjacency[node][next++];
                if (!visited[target]) {
                    visited[target] = true;
                    stack.emplace_back(target, 0);
                }
            } else {
                order.push_back(node);
                stack.pop_back();
            }
        }
    }

    std::vector<std::size_t> component(count, static_cast<std::size_t>(-1));
    std::size_t component_count = 0;
    for (auto it = order.rbegin(); it != order.rend(); ++it) {
        const std::size_t root = *it;
        if (component[root] != static_cast<std::size_t>(-1)) continue;
        std::vector<std::size_t> stack{root};
        component[root] = component_count;
        while (!stack.empty()) {
            const std::size_t node = stack.back();
            stack.pop_back();
            for (const std::size_t target : reverse_adjacency[node]) {
                if (component[target] == static_cast<std::size_t>(-1)) {
                    component[target] = component_count;
                    stack.push_back(target);
                }
            }
        }
        ++component_count;
    }
    (void)component_count;

    // Group nodes by component, preserving ascending node order.
    std::map<std::size_t, std::vector<std::size_t>> groups;
    for (std::size_t node = 0; node < count; ++node) {
        groups[component[node]].push_back(node);
    }
    std::vector<std::vector<std::size_t>> result;
    result.reserve(groups.size());
    for (auto& [id, members] : groups) {
        (void)id;
        result.push_back(std::move(members));
    }
    return result;
}

}  // namespace

core::Result<PointerGraph> PointerGraph::build(const core::BinaryView& view,
                                         const core::ExecutableImage* image,
                                         PointerGraphOptions options) {
    PointerGraph graph;
    if (!view.valid()) {
        return make_error(core::ErrorCode::invalid_argument,
                          "pointer graph requires a valid binary view");
    }

    std::uint8_t min_width = options.min_pointer_width == 0 ? 4 : options.min_pointer_width;
    std::uint8_t max_width = options.max_pointer_width == 0 ? 8 : options.max_pointer_width;
    if (min_width > max_width) std::swap(min_width, max_width);
    if (max_width > 8) max_width = 8;
    if (min_width < 4) min_width = 4;

    bool enable_32 = min_width <= 4 && max_width >= 4;
    bool enable_64 = min_width <= 8 && max_width >= 8;
    if (image != nullptr && image->valid()) {
        if (image->bits() == 32) enable_64 = false;
    }
    if (!enable_32 && !enable_64) {
        return make_error(core::ErrorCode::invalid_argument,
                          "no supported pointer width in requested range",
                          std::to_string(static_cast<unsigned>(min_width)) + ".." +
                              std::to_string(static_cast<unsigned>(max_width)));
    }

    const core::ByteOrder endian =
        (image != nullptr && image->valid()) ? image->endian() : core::ByteOrder::little;
    const std::uint64_t scan_limit =
        std::min<std::uint64_t>(options.max_scan_bytes, view.size());

    std::map<std::uint64_t, std::size_t> node_index;
    const auto ensure_node = [&](std::uint64_t offset, std::string section,
                                 bool executable) -> std::size_t {
        const auto found = node_index.find(offset);
        if (found != node_index.end()) {
            PointerNode& existing = graph.nodes_[found->second];
            if (existing.section.empty() && !section.empty()) existing.section = std::move(section);
            existing.executable = existing.executable || executable;
            return found->second;
        }
        const std::size_t index = graph.nodes_.size();
        PointerNode node;
        node.offset = offset;
        node.section = std::move(section);
        node.executable = executable;
        graph.nodes_.push_back(std::move(node));
        node_index.emplace(offset, index);
        return index;
    };

    std::uint64_t offset = 0;
    while (offset < scan_limit && graph.edges_.size() < kMaxEdges &&
           graph.nodes_.size() < kMaxNodes) {
        bool consumed = false;
        for (const std::uint8_t width : {std::uint8_t{8}, std::uint8_t{4}}) {
            if (width == 8 && !enable_64) continue;
            if (width == 4 && !enable_32) continue;
            if (offset % width != 0) continue;
            if (offset + width > scan_limit) continue;

            const auto raw = view.read_uint(offset, width, endian);
            if (!raw) continue;
            const std::uint64_t value = raw.value();
            if (value == 0) continue;  // null pointer: represented implicitly

            const Resolution resolution =
                resolve_pointer(value, width, view, image, options);
            if (!resolution.accepted) continue;

            // Source-node context.
            std::string source_section;
            bool source_executable = false;
            if (image != nullptr && image->valid()) {
                if (const core::Section* section = section_for_file_offset(*image, offset, width)) {
                    source_section = section->name;
                    source_executable = section->executable();
                }
            }
            const std::size_t source_index =
                ensure_node(offset, std::move(source_section), source_executable);

            std::uint64_t target_key = 0;
            if (resolution.target_offset.has_value()) {
                target_key = resolution.target_offset.value();
            } else if (resolution.target_address.has_value()) {
                target_key = resolution.target_address.value();
            }
            const std::size_t target_index =
                ensure_node(target_key, resolution.section, resolution.executable);

            PointerEdge edge;
            edge.source_offset = offset;
            edge.width = width;
            edge.value = value;
            edge.target_offset = resolution.target_offset;
            edge.target_address = resolution.target_address;
            edge.target_section = resolution.section;
            edge.confidence = resolution.confidence;
            const std::size_t edge_index = graph.edges_.size();
            graph.edges_.push_back(std::move(edge));
            graph.nodes_[source_index].outgoing.push_back(edge_index);
            graph.nodes_[target_index].incoming.push_back(edge_index);

            offset += width;
            consumed = true;
            break;
        }
        if (!consumed) ++offset;
    }

    return graph;
}

std::vector<std::size_t> PointerGraph::edges_from(std::uint64_t offset) const {
    std::vector<std::size_t> result;
    for (std::size_t i = 0; i < edges_.size(); ++i) {
        if (edges_[i].source_offset == offset) result.push_back(i);
    }
    return result;
}

std::vector<std::size_t> PointerGraph::edges_to(std::uint64_t target_offset) const {
    std::vector<std::size_t> result;
    for (std::size_t i = 0; i < edges_.size(); ++i) {
        if (edges_[i].target_offset.has_value() && edges_[i].target_offset.value() == target_offset) {
            result.push_back(i);
        }
    }
    return result;
}

std::vector<std::vector<std::size_t>> PointerGraph::cycles() const {
    std::vector<std::vector<std::size_t>> result;
    if (nodes_.empty() || edges_.empty()) return result;

    std::map<std::uint64_t, std::size_t> index_of_offset;
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        index_of_offset.emplace(nodes_[i].offset, i);
    }

    std::vector<std::pair<std::size_t, std::size_t>> links;
    links.reserve(edges_.size());
    for (const auto& edge : edges_) {
        const auto source = index_of_offset.find(edge.source_offset);
        if (source == index_of_offset.end()) continue;
        const std::uint64_t target_key = edge.target_offset.has_value()
                                             ? edge.target_offset.value()
                                             : (edge.target_address.has_value()
                                                    ? edge.target_address.value()
                                                    : 0);
        const auto target = index_of_offset.find(target_key);
        if (target == index_of_offset.end()) continue;
        links.emplace_back(source->second, target->second);
    }
    if (links.empty()) return result;

    std::vector<std::vector<std::size_t>> adjacency(nodes_.size());
    std::vector<std::vector<std::size_t>> reverse_adjacency(nodes_.size());
    for (const auto& [from, to] : links) {
        adjacency[from].push_back(to);
        reverse_adjacency[to].push_back(from);
    }
    for (auto& list : adjacency) {
        std::sort(list.begin(), list.end());
        list.erase(std::unique(list.begin(), list.end()), list.end());
    }
    for (auto& list : reverse_adjacency) {
        std::sort(list.begin(), list.end());
        list.erase(std::unique(list.begin(), list.end()), list.end());
    }

    const auto components = strong_components(adjacency, reverse_adjacency);
    for (const auto& members : components) {
        bool cyclic = members.size() > 1;
        if (!cyclic) {
            const std::size_t only = members.front();
            cyclic = std::binary_search(adjacency[only].begin(), adjacency[only].end(), only);
        }
        if (!cyclic) continue;

        // Extract a concrete, deterministic cycle through the smallest member.
        std::vector<bool> in_component(nodes_.size(), false);
        for (const std::size_t node : members) in_component[node] = true;
        const std::size_t start = members.front();

        std::vector<std::size_t> parent(nodes_.size(), static_cast<std::size_t>(-1));
        std::vector<std::size_t> distance(nodes_.size(), static_cast<std::size_t>(-1));
        std::queue<std::size_t> frontier;
        parent[start] = start;
        distance[start] = 0;
        frontier.push(start);
        while (!frontier.empty()) {
            const std::size_t node = frontier.front();
            frontier.pop();
            for (const std::size_t target : adjacency[node]) {
                if (!in_component[target] || distance[target] != static_cast<std::size_t>(-1)) {
                    continue;
                }
                distance[target] = distance[node] + 1;
                parent[target] = node;
                frontier.push(target);
            }
        }

        std::size_t best = static_cast<std::size_t>(-1);
        std::size_t best_distance = static_cast<std::size_t>(-1);
        for (const std::size_t member : members) {
            const auto& out = adjacency[member];
            if (!std::binary_search(out.begin(), out.end(), start)) continue;
            const std::size_t candidate_distance = distance[member];
            if (candidate_distance == static_cast<std::size_t>(-1)) continue;
            if (best == static_cast<std::size_t>(-1) || candidate_distance < best_distance ||
                (candidate_distance == best_distance && member < best)) {
                best = member;
                best_distance = candidate_distance;
            }
        }
        if (best == static_cast<std::size_t>(-1)) continue;

        std::vector<std::size_t> cycle;
        std::size_t cursor = best;
        cycle.push_back(cursor);
        while (cursor != start) {
            cursor = parent[cursor];
            if (cursor == static_cast<std::size_t>(-1)) {
                cycle.clear();
                break;
            }
            cycle.push_back(cursor);
        }
        if (cycle.empty()) continue;
        std::reverse(cycle.begin(), cycle.end());
        cycle.push_back(start);  // close the loop
        result.push_back(std::move(cycle));
    }

    std::sort(result.begin(), result.end());
    return result;
}

}  // namespace typemorph::infer

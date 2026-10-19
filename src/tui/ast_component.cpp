// TypeMorph - collapsible recovered-type tree.
//
// The component keeps the root TypePtr alive for its whole lifetime and stores
// the flattened tree as `shared_ptr<const TypeNode>` handles (ConstTypePtr).
// That makes every AstRow snapshot safe even if the caller rebuilds the tree:
// the rows never contain raw pointers, and `selected_node()` only ever hands
// out a pointer into a node that the root (or the previous root, via the
// shared_ptr handles) still owns.
//
// Offsets: core::TypeNode::offset is documented as "relative to the parent
// node (root nodes use absolute file offset)".  AstRow exposes the accumulated
// absolute file offset so the dashboard can correlate tree rows with the hex
// view; the accumulation is guarded against uint64 overflow.
#include "typemorph/tui/ast_component.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace typemorph::tui {
namespace {

constexpr std::size_t kNoEntry = std::numeric_limits<std::size_t>::max();

[[nodiscard]] std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
    return lhs > limit - rhs ? limit : lhs + rhs;
}

[[nodiscard]] std::int64_t saturating_add(std::int64_t lhs, std::int64_t rhs) noexcept {
    const std::int64_t limit = std::numeric_limits<std::int64_t>::max();
    if (rhs > 0 && lhs > limit - rhs) return limit;
    if (rhs < 0 && lhs < std::numeric_limits<std::int64_t>::min() - rhs) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return lhs + rhs;
}

// Human readable type column for the tree.  This deliberately renders the
// interesting shape inline (array count, enum underlying, pointer width, ...)
// because the panel is text-only.
[[nodiscard]] std::string node_type_name(const core::TypeNode& node) {
    if (const auto* primitive = node.get_if<core::PrimitiveNode>()) {
        return std::string(core::to_string(primitive->kind));
    }
    if (const auto* array = node.get_if<core::ArrayNode>()) {
        std::string text = "array[";
        if (array->count.has_value()) {
            text += std::to_string(array->count.value());
        } else if (!array->count_expression.empty()) {
            text += array->count_expression;
        } else {
            text += '?';
        }
        text += ']';
        return text;
    }
    if (node.is<core::StructNode>()) return "struct";
    if (const auto* enumeration = node.get_if<core::EnumNode>()) {
        return std::string("enum<") + std::string(core::to_string(enumeration->underlying)) + ">";
    }
    if (const auto* slice = node.get_if<core::SliceNode>()) {
        return std::string("slice<") + std::string(core::to_string(slice->element_primitive)) +
               ">";
    }
    if (const auto* pointer = node.get_if<core::PointerNode>()) {
        return "ptr" + std::to_string(static_cast<unsigned>(pointer->width) * 8U);
    }
    if (const auto* str = node.get_if<core::StringNode>()) {
        return "string";
    }
    if (node.is<core::UnknownNode>()) return "unknown";
    if (node.is<core::PaddingNode>()) return "padding";
    if (const auto* bitfield = node.get_if<core::BitfieldNode>()) {
        return "bitfield<" + std::string(core::to_string(bitfield->underlying)) + ">";
    }
    return "?";
}

[[nodiscard]] bool has_children_of(const core::TypeNode& node) noexcept {
    if (const auto* structure = node.get_if<core::StructNode>()) return !structure->fields.empty();
    if (const auto* array = node.get_if<core::ArrayNode>()) return static_cast<bool>(array->element);
    if (const auto* slice = node.get_if<core::SliceNode>()) {
        return static_cast<bool>(slice->element_type);
    }
    return false;
}

// Reconstructs the preorder ancestry from (node, depth) pairs.  flatten() and
// select_offset() both need parent links, and Entry cannot carry one (the
// public header is a frozen contract), so it is recomputed cheaply instead.
void compute_ancestry(const std::vector<core::ConstTypePtr>& nodes,
                      const std::vector<int>& depths, std::vector<std::size_t>& parents,
                      std::vector<std::uint64_t>& absolute) {
    parents.assign(nodes.size(), kNoEntry);
    absolute.assign(nodes.size(), 0);
    std::vector<std::size_t> path;
    path.reserve(32);
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        while (!path.empty() && depths[path.back()] >= depths[i]) path.pop_back();
        if (!path.empty()) {
            parents[i] = path.back();
            absolute[i] = saturating_add(absolute[path.back()],
                                        nodes[i] ? nodes[i]->offset : 0);
        } else {
            absolute[i] = nodes[i] ? nodes[i]->offset : 0;
        }
        path.push_back(i);
    }
}

// Places the selection on `entry_index` if that node has a visible row.
[[nodiscard]] bool place_selection_on_entry(const std::vector<AstRow>& rows,
                                            std::size_t entry_index,
                                            std::size_t& selected_row) noexcept {
    for (std::size_t row = 0; row < rows.size(); ++row) {
        if (rows[row].node_index == entry_index) {
            selected_row = row;
            return true;
        }
    }
    return false;
}

void mark_selected(std::vector<AstRow>& rows, std::size_t selected_row) noexcept {
    for (std::size_t row = 0; row < rows.size(); ++row) {
        rows[row].selected = (row == selected_row);
    }
}

}  // namespace

AstComponent::AstComponent(core::TypePtr root) : root_(std::move(root)) { rebuild(); }

void AstComponent::set_root(core::TypePtr root) {
    root_ = std::move(root);
    entries_.clear();
    expanded_.clear();
    rows_.clear();
    selected_row_ = 0;
    rebuild();
}

void AstComponent::rebuild() { flatten(); }

void AstComponent::flatten() {
    // Keep the previously selected node alive and remember it by identity.  A
    // shared_ptr anchor cannot dangle even if the caller replaced the tree.
    core::ConstTypePtr anchor;
    if (!rows_.empty() && selected_row_ < rows_.size()) {
        const std::size_t old_entry = rows_[selected_row_].node_index;
        if (old_entry < entries_.size()) anchor = entries_[old_entry].node;
    }

    entries_.clear();
    if (root_) {
        struct Builder {
            std::vector<Entry>& entries;
            void add(core::ConstTypePtr node, int depth, std::string label) {
                if (!node) return;
                Entry entry;
                entry.node = std::move(node);
                entry.depth = depth;
                entry.has_children = has_children_of(*entry.node);
                entry.label = std::move(label);
                entries.push_back(std::move(entry));

                const core::TypeNode& current = *entries.back().node;
                if (const auto* structure = current.get_if<core::StructNode>()) {
                    for (std::size_t i = 0; i < structure->fields.size(); ++i) {
                        const core::TypeField& field = structure->fields[i];
                        if (!field.type) continue;
                        // Structured children present their recovered type name
                        // (e.g. "Pair"); primitives keep the field name so a
                        // u32 field called "magic" still reads as "magic".
                        std::string child_label = field.name;
                        if (!field.type->is<core::PrimitiveNode>() &&
                            !field.type->name.empty()) {
                            child_label = field.type->name;
                        }
                        if (child_label.empty()) {
                            child_label = field.type->name.empty()
                                              ? "field[" + std::to_string(i) + "]"
                                              : field.type->name;
                        }
                        add(field.type, depth + 1, std::move(child_label));
                    }
                } else if (const auto* array = current.get_if<core::ArrayNode>()) {
                    if (array->element) {
                        std::string child_label =
                            array->element->name.empty() ? "element" : array->element->name;
                        add(array->element, depth + 1, std::move(child_label));
                    }
                } else if (const auto* slice = current.get_if<core::SliceNode>()) {
                    if (slice->element_type) {
                        std::string child_label = slice->element_type->name.empty()
                                                      ? "element"
                                                      : slice->element_type->name;
                        add(slice->element_type, depth + 1, std::move(child_label));
                    }
                }
            }
        };
        Builder builder{entries_};
        const std::string root_label = root_->name.empty() ? "root" : root_->name;
        builder.add(root_, 0, root_label);
    }

    // First build keeps the root expanded; subsequent tree shapes preserve the
    // user's expansion choices as long as the node count is stable.
    if (expanded_.size() != entries_.size()) {
        expanded_.assign(entries_.size(), false);
        if (!entries_.empty()) expanded_[0] = true;
    }

    std::vector<core::ConstTypePtr> nodes(entries_.size());
    std::vector<int> depths(entries_.size());
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        nodes[i] = entries_[i].node;
        depths[i] = entries_[i].depth;
    }
    std::vector<std::size_t> parents;
    std::vector<std::uint64_t> absolute;
    compute_ancestry(nodes, depths, parents, absolute);

    // Preorder walk with an ancestry stack, so a hidden subtree is skipped
    // without needing a parent link on every Entry.
    rows_.clear();
    rows_.reserve(entries_.size());
    std::vector<std::size_t> path;
    std::vector<bool> path_visible;
    path.reserve(32);
    path_visible.reserve(32);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        while (!path.empty() && entries_[path.back()].depth >= entries_[i].depth) {
            path.pop_back();
            path_visible.pop_back();
        }
        const bool parent_visible = path.empty() ? true : path_visible.back();
        const bool parent_expanded =
            path.empty() ? true : expanded_[path.back()];
        const bool visible = parent_visible && parent_expanded;
        if (visible) {
            AstRow row;
            row.node_index = i;
            row.depth = entries_[i].depth;
            row.label = entries_[i].label;
            const core::TypeNode& node = *entries_[i].node;
            row.type_name = node_type_name(node);
            row.offset = absolute[i];
            row.size = node.size;
            row.confidence = node.confidence;
            row.expanded = expanded_[i];
            row.has_children = entries_[i].has_children;
            row.selected = false;
            rows_.push_back(std::move(row));
        }
        path.push_back(i);
        path_visible.push_back(visible);
    }

    // Re-establish the selection by node identity, falling back to the nearest
    // visible ancestor when the previously selected subtree got collapsed.
    std::size_t anchor_entry = kNoEntry;
    if (anchor) {
        for (std::size_t i = 0; i < entries_.size(); ++i) {
            if (entries_[i].node.get() == anchor.get()) {
                anchor_entry = i;
                break;
            }
        }
    }

    selected_row_ = 0;
    if (!rows_.empty()) {
        bool placed = anchor_entry != kNoEntry &&
                      place_selection_on_entry(rows_, anchor_entry, selected_row_);
        if (!placed && anchor_entry != kNoEntry) {
            std::size_t current = parents[anchor_entry];
            while (current != kNoEntry) {
                if (place_selection_on_entry(rows_, current, selected_row_)) {
                    placed = true;
                    break;
                }
                current = parents[current];
            }
        }
        if (!placed) selected_row_ = std::min(selected_row_, rows_.size() - 1);
        mark_selected(rows_, selected_row_);
    }
}

void AstComponent::toggle(std::size_t row) {
    if (row >= rows_.size()) return;
    const std::size_t entry = rows_[row].node_index;
    if (entry >= entries_.size() || entry >= expanded_.size()) return;
    if (!entries_[entry].has_children) return;

    expanded_[entry] = !expanded_[entry];
    flatten();

    // Keep the toggled node selected; collapsing leaves its own row visible.
    if (place_selection_on_entry(rows_, entry, selected_row_)) {
        mark_selected(rows_, selected_row_);
    }
}

void AstComponent::expand_all() {
    if (expanded_.empty()) return;
    std::fill(expanded_.begin(), expanded_.end(), true);
    flatten();
}

void AstComponent::collapse_all() {
    if (expanded_.empty()) return;
    std::fill(expanded_.begin(), expanded_.end(), false);
    flatten();
}

void AstComponent::move_selection(std::int64_t delta) {
    if (rows_.empty()) {
        selected_row_ = 0;
        return;
    }
    const std::int64_t last = static_cast<std::int64_t>(rows_.size() - 1);
    std::int64_t target = saturating_add(static_cast<std::int64_t>(selected_row_), delta);
    target = std::clamp<std::int64_t>(target, 0, last);
    selected_row_ = static_cast<std::size_t>(target);
    mark_selected(rows_, selected_row_);
}

void AstComponent::select_row(std::size_t row) {
    if (rows_.empty()) {
        selected_row_ = 0;
        return;
    }
    selected_row_ = std::min(row, rows_.size() - 1);
    mark_selected(rows_, selected_row_);
}

void AstComponent::select_offset(std::uint64_t offset) {
    if (entries_.empty()) return;

    std::vector<core::ConstTypePtr> nodes(entries_.size());
    std::vector<int> depths(entries_.size());
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        nodes[i] = entries_[i].node;
        depths[i] = entries_[i].depth;
    }
    std::vector<std::size_t> parents;
    std::vector<std::uint64_t> absolute;
    compute_ancestry(nodes, depths, parents, absolute);

    // Most specific node containing the offset: smallest size, then deepest.
    std::size_t best = kNoEntry;
    std::uint64_t best_size = std::numeric_limits<std::uint64_t>::max();
    int best_depth = -1;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const core::TypeNode& node = *entries_[i].node;
        const bool contains = node.size == 0
                                  ? offset == absolute[i]
                                  : (offset >= absolute[i] &&
                                     offset - absolute[i] < node.size);
        if (!contains) continue;
        if (node.size < best_size ||
            (node.size == best_size && entries_[i].depth > best_depth)) {
            best = i;
            best_size = node.size;
            best_depth = entries_[i].depth;
        }
    }
    if (best == kNoEntry) return;

    // Reveal the chosen node by expanding every ancestor (root included).
    for (std::size_t current = parents[best]; current != kNoEntry;
         current = parents[current]) {
        if (current < expanded_.size() && entries_[current].has_children) {
            expanded_[current] = true;
        }
    }
    flatten();

    if (place_selection_on_entry(rows_, best, selected_row_)) {
        mark_selected(rows_, selected_row_);
    } else {
        // Defensive: expanded_ can only fail to reveal the node if the tree was
        // mutated concurrently through a raw TypeNode pointer.
        selected_row_ = 0;
        if (!rows_.empty()) mark_selected(rows_, selected_row_);
    }
}

const core::TypeNode* AstComponent::selected_node() const {
    if (selected_row_ >= rows_.size()) return nullptr;
    const std::size_t entry = rows_[selected_row_].node_index;
    if (entry >= entries_.size()) return nullptr;
    return entries_[entry].node.get();
}

std::uint64_t AstComponent::selected_offset() const {
    if (selected_row_ >= rows_.size()) return 0;
    return rows_[selected_row_].offset;
}

std::uint64_t AstComponent::selected_size() const {
    if (selected_row_ >= rows_.size()) return 0;
    return rows_[selected_row_].size;
}

}  // namespace typemorph::tui

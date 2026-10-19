// TypeMorph - collapsible recovered-type tree.
#pragma once

#include "typemorph/core/types.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::tui {

struct AstRow {
    std::size_t node_index = 0;
    int depth = 0;
    std::string label;
    std::string type_name;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    double confidence = 0.0;
    bool expanded = false;
    bool has_children = false;
    bool selected = false;
};

class AstComponent {
public:
    AstComponent() = default;
    explicit AstComponent(core::TypePtr root);

    void set_root(core::TypePtr root);
    [[nodiscard]] const core::TypePtr& root() const noexcept { return root_; }

    [[nodiscard]] const std::vector<AstRow>& rows() const noexcept { return rows_; }
    void rebuild();

    void toggle(std::size_t row);
    void expand_all();
    void collapse_all();
    void move_selection(std::int64_t delta);
    void select_row(std::size_t row);
    void select_offset(std::uint64_t offset);
    [[nodiscard]] std::size_t selected_row() const noexcept { return selected_row_; }
    [[nodiscard]] const core::TypeNode* selected_node() const;
    [[nodiscard]] std::uint64_t selected_offset() const;
    [[nodiscard]] std::uint64_t selected_size() const;

private:
    struct Entry {
        core::ConstTypePtr node;
        int depth = 0;
        bool has_children = false;
        std::string label;
    };
    void flatten();

    core::TypePtr root_;
    std::vector<Entry> entries_;
    std::vector<bool> expanded_;
    std::vector<AstRow> rows_;
    std::size_t selected_row_ = 0;
};

}  // namespace typemorph::tui

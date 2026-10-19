// TypeMorph - virtualized hex viewer with structural/entropy heat map.
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace typemorph::tui {

struct HexRow {
    std::uint64_t offset = 0;
    std::size_t length = 0;
    std::array<std::uint8_t, 16> bytes{};
    std::array<char, 16> ascii{};
    std::array<std::uint8_t, 16> intensity{};
    std::array<bool, 16> selected{};
    bool row_selected = false;
};

class HexComponent {
public:
    explicit HexComponent(core::BinaryView view, std::size_t bytes_per_row = 16);

    void set_view(core::BinaryView view);
    void set_selection(std::uint64_t offset, std::uint64_t length);
    void clear_selection();
    void set_cursor(std::uint64_t offset);
    void move_cursor(std::int64_t delta);
    void scroll_rows(std::int64_t delta);
    void scroll_to(std::uint64_t offset);
    void page(std::int64_t pages, std::size_t visible_rows);

    [[nodiscard]] std::vector<HexRow> visible_rows(std::size_t height) const;
    [[nodiscard]] std::uint64_t cursor_offset() const noexcept { return cursor_; }
    [[nodiscard]] std::uint64_t top_offset() const noexcept { return top_; }
    [[nodiscard]] std::size_t bytes_per_row() const noexcept { return bytes_per_row_; }
    [[nodiscard]] std::size_t total_rows() const noexcept;
    [[nodiscard]] bool has_selection() const noexcept { return selection_length_ != 0; }
    [[nodiscard]] std::uint64_t selection_offset() const noexcept { return selection_offset_; }
    [[nodiscard]] std::uint64_t selection_length() const noexcept { return selection_length_; }

private:
    void clamp_state();

    core::BinaryView view_;
    std::size_t bytes_per_row_ = 16;
    std::uint64_t top_ = 0;
    std::uint64_t cursor_ = 0;
    std::uint64_t selection_offset_ = 0;
    std::uint64_t selection_length_ = 0;
};

}  // namespace typemorph::tui

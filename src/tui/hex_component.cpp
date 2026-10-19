// TypeMorph - virtualized hex viewer with entropy heat map.
//
// Design notes
// ------------
// * Rendering is strictly bounded by the caller's visible row count.  No code
//   path here ever walks the whole file: `visible_rows` seeks straight to
//   `top_offset()` and materialises at most `height` rows.
// * Entropy is sampled per byte through `core::shannon_entropy` over a small
//   window centred on that byte.  The window is clamped to the view, so the
//   cost is O(visible_rows * bytes_per_row * window) with a tiny constant and
//   no allocation.
// * All public mutators funnel through `clamp_state`, which keeps the cursor,
//   the scroll origin and the selection inside the view.  A selection that
//   starts past EOF degrades to "no selection" instead of reading out of
//   bounds.
#include "typemorph/tui/hex_component.hpp"

#include "typemorph/core/entropy.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

namespace typemorph::tui {
namespace {

// HexRow stores exactly 16 cells, so the caller cannot configure a wider row.
constexpr std::size_t kMaxBytesPerRow = 16;
constexpr std::size_t kMinBytesPerRow = 1;

// Nominal viewport height used to keep the cursor visible when the caller only
// performs cursor navigation (move_cursor / set_cursor).  The dashboard
// re-centres against its real panel height after dispatching a key, so this is
// a safe fallback rather than a hard layout assumption.
constexpr std::size_t kFollowRows = 16;

// Half of the entropy sampling window, in bytes, on each side of a byte.
constexpr std::size_t kEntropyRadius = 16;

[[nodiscard]] std::size_t normalise_bytes_per_row(std::size_t requested) noexcept {
    if (requested < kMinBytesPerRow) return kMinBytesPerRow;
    return std::min(requested, kMaxBytesPerRow);
}

[[nodiscard]] std::size_t total_rows_for(std::size_t size, std::size_t bytes_per_row) noexcept {
    if (size == 0 || bytes_per_row == 0) return 0;
    return size / bytes_per_row + (size % bytes_per_row == 0 ? 0 : 1);
}

[[nodiscard]] std::uint64_t max_cursor_for(std::size_t size) noexcept {
    return size == 0 ? 0 : static_cast<std::uint64_t>(size) - 1;
}

[[nodiscard]] std::uint64_t max_top_for(std::size_t size, std::size_t bytes_per_row) noexcept {
    const std::size_t rows = total_rows_for(size, bytes_per_row);
    if (rows == 0) return 0;
    return static_cast<std::uint64_t>(rows - 1) * static_cast<std::uint64_t>(bytes_per_row);
}

// Saturating arithmetic: a hostile key repeat / huge page size must never wrap
// the scroll or cursor state.
[[nodiscard]] std::uint64_t saturating_add(std::uint64_t base, std::int64_t delta) noexcept {
    if (delta >= 0) {
        const auto magnitude = static_cast<std::uint64_t>(delta);
        const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
        return base > limit - magnitude ? limit : base + magnitude;
    }
    // Negating INT64_MIN is undefined, so build the magnitude carefully.
    const std::uint64_t magnitude =
        static_cast<std::uint64_t>(-(delta + 1)) + std::uint64_t{1};
    return magnitude > base ? 0 : base - magnitude;
}

[[nodiscard]] std::uint64_t clamp_offset(std::uint64_t offset, std::size_t size) noexcept {
    return std::min(offset, static_cast<std::uint64_t>(size));
}

// Moves the scroll origin so that `cursor` sits inside a kFollowRows-tall
// viewport, then clamps the origin to the last possible row.
void follow_cursor(std::uint64_t& top, std::uint64_t cursor, std::size_t bytes_per_row,
                   std::size_t size) noexcept {
    if (bytes_per_row == 0) return;
    const std::uint64_t bpr = static_cast<std::uint64_t>(bytes_per_row);
    const std::uint64_t cursor_row = cursor / bpr;
    const std::uint64_t top_row = top / bpr;
    std::uint64_t proposed = top;
    if (cursor_row < top_row) {
        proposed = cursor_row * bpr;
    } else if (cursor_row >= top_row + kFollowRows) {
        proposed = (cursor_row - (kFollowRows - 1)) * bpr;
    }
    top = std::min(proposed, max_top_for(size, bytes_per_row));
}

[[nodiscard]] bool byte_is_selected(std::uint64_t offset, std::uint64_t selection_offset,
                                    std::uint64_t selection_length) noexcept {
    if (selection_length == 0) return false;
    if (offset < selection_offset) return false;
    return offset - selection_offset < selection_length;
}

// Per-byte entropy intensity.  The window is clamped to the view and only
// visible bytes are ever sampled.
[[nodiscard]] std::uint8_t entropy_intensity_at(std::span<const std::uint8_t> bytes,
                                                std::size_t offset) noexcept {
    if (offset >= bytes.size()) return 0;
    const std::size_t begin = offset > kEntropyRadius ? offset - kEntropyRadius : 0;
    std::size_t end = begin + kEntropyRadius * 2 + 1;
    if (end > bytes.size()) end = bytes.size();
    if (end <= begin) return 0;
    const double value = core::shannon_entropy(bytes.subspan(begin, end - begin));
    return core::entropy_intensity(value);
}

}  // namespace

HexComponent::HexComponent(core::BinaryView view, std::size_t bytes_per_row)
    : view_(std::move(view)), bytes_per_row_(normalise_bytes_per_row(bytes_per_row)) {
    clamp_state();
}

void HexComponent::set_view(core::BinaryView view) {
    view_ = std::move(view);
    // A stale selection must not survive a view swap.
    selection_offset_ = 0;
    selection_length_ = 0;
    cursor_ = 0;
    top_ = 0;
    clamp_state();
}

void HexComponent::set_selection(std::uint64_t offset, std::uint64_t length) {
    selection_offset_ = 0;
    selection_length_ = 0;
    if (length == 0 || view_.empty()) return;

    const std::uint64_t size = static_cast<std::uint64_t>(view_.size());
    if (offset >= size) return;  // entirely past EOF: degrade to no selection
    selection_offset_ = offset;
    selection_length_ = std::min(length, size - offset);
}

void HexComponent::clear_selection() {
    selection_offset_ = 0;
    selection_length_ = 0;
}

void HexComponent::set_cursor(std::uint64_t offset) {
    cursor_ = std::min(offset, max_cursor_for(view_.size()));
    follow_cursor(top_, cursor_, bytes_per_row_, view_.size());
    clamp_state();
}

void HexComponent::move_cursor(std::int64_t delta) {
    const std::uint64_t moved = saturating_add(cursor_, delta);
    cursor_ = std::min(moved, max_cursor_for(view_.size()));
    follow_cursor(top_, cursor_, bytes_per_row_, view_.size());
    clamp_state();
}

void HexComponent::scroll_rows(std::int64_t delta) {
    const std::size_t rows = total_rows_for(view_.size(), bytes_per_row_);
    if (rows == 0) {
        top_ = 0;
        return;
    }
    const std::uint64_t top_row = top_ / static_cast<std::uint64_t>(bytes_per_row_);
    const std::uint64_t last_row = static_cast<std::uint64_t>(rows - 1);
    const std::uint64_t row =
        std::min(saturating_add(top_row, delta), last_row);
    top_ = row * static_cast<std::uint64_t>(bytes_per_row_);
    clamp_state();
}

void HexComponent::scroll_to(std::uint64_t offset) {
    const std::uint64_t clamped = std::min(offset, max_top_for(view_.size(), bytes_per_row_));
    top_ = (clamped / static_cast<std::uint64_t>(bytes_per_row_)) *
           static_cast<std::uint64_t>(bytes_per_row_);
    clamp_state();
}

void HexComponent::page(std::int64_t pages, std::size_t visible_rows) {
    if (pages == 0) return;
    const std::size_t rows = std::max<std::size_t>(visible_rows, 1);
    const int64_t per_page = static_cast<int64_t>(std::min<std::size_t>(
        rows, static_cast<std::size_t>(std::numeric_limits<int64_t>::max() / 2)));

    int64_t delta = 0;
    if (pages > 0) {
        const int64_t limit = std::numeric_limits<int64_t>::max() / 2;
        delta = pages > limit / per_page ? limit : pages * per_page;
    } else {
        const int64_t limit = std::numeric_limits<int64_t>::min() / 2;
        delta = pages < limit / per_page ? limit : pages * per_page;
    }
    scroll_rows(delta);
}

std::vector<HexRow> HexComponent::visible_rows(std::size_t height) const {
    std::vector<HexRow> rows;
    const std::size_t size = view_.size();
    if (height == 0 || size == 0 || bytes_per_row_ == 0) return rows;

    const std::uint64_t bpr = static_cast<std::uint64_t>(bytes_per_row_);
    const std::uint64_t first_row = top_ / bpr;
    const std::size_t total = total_rows_for(size, bytes_per_row_);
    if (first_row >= static_cast<std::uint64_t>(total)) return rows;

    const std::size_t first_index = static_cast<std::size_t>(first_row);
    const std::size_t available = total - first_index;
    const std::size_t count = std::min(height, available);
    const std::span<const std::uint8_t> bytes = view_.bytes();

    rows.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t row_offset =
            (first_row + static_cast<std::uint64_t>(i)) * bpr;
        HexRow row;
        row.offset = row_offset;
        row.length = std::min(bytes_per_row_, size - static_cast<std::size_t>(row_offset));

        for (std::size_t cell = 0; cell < row.length; ++cell) {
            const std::uint64_t absolute = row_offset + static_cast<std::uint64_t>(cell);
            const std::uint8_t value = bytes[static_cast<std::size_t>(absolute)];
            row.bytes[cell] = value;
            row.ascii[cell] = (value >= 0x20U && value <= 0x7EU) ? static_cast<char>(value) : '.';
            row.intensity[cell] = entropy_intensity_at(bytes, static_cast<std::size_t>(absolute));
            row.selected[cell] =
                byte_is_selected(absolute, selection_offset_, selection_length_);
            if (row.selected[cell]) row.row_selected = true;
        }
        rows.push_back(row);
    }
    return rows;
}

std::size_t HexComponent::total_rows() const noexcept {
    return total_rows_for(view_.size(), bytes_per_row_);
}

void HexComponent::clamp_state() {
    bytes_per_row_ = normalise_bytes_per_row(bytes_per_row_);
    const std::size_t size = view_.size();
    if (size == 0) {
        top_ = 0;
        cursor_ = 0;
        selection_offset_ = 0;
        selection_length_ = 0;
        return;
    }

    const std::uint64_t bpr = static_cast<std::uint64_t>(bytes_per_row_);
    top_ = std::min((top_ / bpr) * bpr, max_top_for(size, bytes_per_row_));
    cursor_ = std::min(cursor_, max_cursor_for(size));

    if (selection_length_ == 0) {
        selection_offset_ = 0;
    } else {
        selection_offset_ = clamp_offset(selection_offset_, size);
        if (selection_offset_ >= size) {
            selection_offset_ = 0;
            selection_length_ = 0;
        } else {
            selection_length_ =
                std::min(selection_length_,
                         static_cast<std::uint64_t>(size) - selection_offset_);
        }
    }
}

}  // namespace typemorph::tui

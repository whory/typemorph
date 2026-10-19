// TypeMorph - live emitter preview pane.
//
// The preview keeps the rendered text split into lines once (on set_text) and
// only clips the visible slice per frame.  Clipping is UTF-8 aware: a multi-byte
// sequence is never split, and tabs are expanded to four-column tab stops so the
// preview lines up with the panel border.
#include "typemorph/tui/emitter_component.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace typemorph::tui {
namespace {

constexpr std::size_t kTabWidth = 4;

[[nodiscard]] std::size_t utf8_sequence_length(unsigned char lead) noexcept {
    if (lead < 0x80U) return 1;
    if ((lead & 0xE0U) == 0xC0U) return 2;
    if ((lead & 0xF0U) == 0xE0U) return 3;
    if ((lead & 0xF8U) == 0xF0U) return 4;
    return 1;  // stray continuation byte: render it verbatim
}

// Clips `line` to `width` terminal columns.  Every emitted byte sequence is a
// complete valid UTF-8 code point from the input (or a single stray byte that
// was already in the input), so the result never ends mid-character.
[[nodiscard]] std::string clip_line(std::string_view line, std::size_t width) {
    if (width == 0) return {};
    std::string out;
    out.reserve(std::min(line.size(), width * 4));
    std::size_t columns = 0;
    std::size_t index = 0;
    while (index < line.size() && columns < width) {
        const unsigned char lead = static_cast<unsigned char>(line[index]);
        if (lead == '\t') {
            const std::size_t next = (columns / kTabWidth + 1) * kTabWidth;
            if (next > width) break;
            out.append(next - columns, ' ');
            columns = next;
            ++index;
            continue;
        }
        if (lead == '\r') {
            ++index;
            continue;
        }
        const std::size_t length = std::min(utf8_sequence_length(lead), line.size() - index);
        out.append(line.data() + index, length);
        index += length;
        ++columns;
    }
    return out;
}

[[nodiscard]] std::int64_t max_top_line(std::size_t line_count) noexcept {
    if (line_count == 0) return 0;
    return static_cast<std::int64_t>(line_count - 1);
}

[[nodiscard]] std::int64_t saturating_add(std::int64_t lhs, std::int64_t rhs) noexcept {
    const std::int64_t limit = std::numeric_limits<std::int64_t>::max();
    if (rhs > 0 && lhs > limit - rhs) return limit;
    if (rhs < 0 && lhs < std::numeric_limits<std::int64_t>::min() - rhs) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return lhs + rhs;
}

}  // namespace

void EmitterComponent::set_text(std::string text) {
    text_ = std::move(text);
    lines_.clear();

    std::string current;
    current.reserve(128);
    for (const char character : text_) {
        if (character == '\n') {
            if (!current.empty() && current.back() == '\r') current.pop_back();
            lines_.push_back(std::move(current));
            current.clear();
            current.reserve(128);
        } else {
            current.push_back(character);
        }
    }
    if (!current.empty()) {
        if (current.back() == '\r') current.pop_back();
        lines_.push_back(std::move(current));
    }

    top_line_ = 0;
}

void EmitterComponent::scroll(std::int64_t lines) {
    const std::int64_t target =
        saturating_add(top_line_, lines);
    top_line_ = std::clamp<std::int64_t>(target, 0, max_top_line(lines_.size()));
}

void EmitterComponent::scroll_to(std::int64_t line) {
    top_line_ = std::clamp<std::int64_t>(line, 0, max_top_line(lines_.size()));
}

void EmitterComponent::page(std::int64_t pages, std::size_t visible_lines) {
    if (pages == 0) return;
    const std::size_t page_height = std::max<std::size_t>(visible_lines, 1);
    const std::int64_t per_page = static_cast<std::int64_t>(
        std::min<std::size_t>(page_height,
                              static_cast<std::size_t>(
                                  std::numeric_limits<std::int64_t>::max() / 2)));

    std::int64_t delta = 0;
    if (pages > 0) {
        const std::int64_t limit = std::numeric_limits<std::int64_t>::max() / 2;
        delta = pages > limit / per_page ? limit : pages * per_page;
    } else {
        const std::int64_t limit = std::numeric_limits<std::int64_t>::min() / 2;
        delta = pages < limit / per_page ? limit : pages * per_page;
    }
    scroll(delta);
}

void EmitterComponent::set_active_language(std::string language) {
    language_ = std::move(language);
}

std::vector<std::string> EmitterComponent::visible_lines(std::size_t height,
                                                         std::size_t width) const {
    std::vector<std::string> visible;
    if (height == 0) return visible;
    visible.reserve(height);

    const std::size_t start =
        top_line_ <= 0 ? 0 : static_cast<std::size_t>(top_line_);
    for (std::size_t i = 0; i < height; ++i) {
        const std::size_t index = start + i;
        if (index < lines_.size()) {
            visible.push_back(clip_line(lines_[index], width));
        } else {
            visible.emplace_back();
        }
    }
    return visible;
}

}  // namespace typemorph::tui

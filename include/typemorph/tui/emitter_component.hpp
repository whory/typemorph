// TypeMorph - live emitter preview pane.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::tui {

class EmitterComponent {
public:
    void set_text(std::string text);
    void scroll(std::int64_t lines);
    void scroll_to(std::int64_t line);
    void page(std::int64_t pages, std::size_t visible_lines);
    void set_active_language(std::string language);

    [[nodiscard]] const std::string& text() const noexcept { return text_; }
    [[nodiscard]] const std::string& language() const noexcept { return language_; }
    [[nodiscard]] std::int64_t top_line() const noexcept { return top_line_; }
    [[nodiscard]] std::vector<std::string> visible_lines(std::size_t height,
                                                         std::size_t width) const;

private:
    std::string text_;
    std::string language_ = "kaitai";
    std::vector<std::string> lines_;
    std::int64_t top_line_ = 0;
};

}  // namespace typemorph::tui

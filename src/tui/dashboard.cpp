// TypeMorph - interactive terminal dashboard.
//
// This translation unit implements the complete native ANSI backend declared by
// dashboard.hpp: no FTXUI, ncurses or other package is required.  The same
// renderer is used interactively and by `--render-once` style batch output
// (when stdout is not a terminal `run()` emits exactly one deterministic frame
// and returns).
//
// The header is a frozen public contract and does not carry transient
// presentation state (help overlay, last rendered geometry, terminal size).
// That state lives in an internal, per-Dashboard side table populated by
// render_frame(); it never influences the frame content, so rendering remains
// deterministic and testable without a terminal.
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif

#include "typemorph/tui/dashboard.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <conio.h>
#include <io.h>
#else
#include <cerrno>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace typemorph::tui {

// Logical key codes.  The native backend translates platform specific escape
// sequences (VT100 cursor keys and Windows console extended scancodes) into
// these values.  They carry external linkage so the test suite can drive
// handle_key() without a terminal.
extern const int key_up = 1000;
extern const int key_down = 1001;
extern const int key_left = 1002;
extern const int key_right = 1003;
extern const int key_page_up = 1004;
extern const int key_page_down = 1005;
extern const int key_home = 1006;
extern const int key_end = 1007;
extern const int key_escape = 27;

namespace {

// ---------------------------------------------------------------------------
// Small terminal text helpers
// ---------------------------------------------------------------------------

constexpr const char* kReset = "\x1b[0m";
constexpr const char* kFocusColor = "\x1b[1;36m";   // bold cyan
constexpr const char* kBlurColor = "\x1b[2;37m";    // dim white
constexpr const char* kHeaderColor = "\x1b[1;44;97m";  // bright white on blue
constexpr const char* kFooterColor = "\x1b[2;37m";
constexpr const char* kSelectionColor = "\x1b[1;7m";  // bold reverse
constexpr const char* kNumberColor = "\x1b[2;37m";

[[nodiscard]] std::size_t utf8_length(unsigned char lead) noexcept {
    if (lead < 0x80U) return 1;
    if ((lead & 0xE0U) == 0xC0U) return 2;
    if ((lead & 0xF0U) == 0xE0U) return 3;
    if ((lead & 0xF8U) == 0xF0U) return 4;
    return 1;
}

[[nodiscard]] std::size_t visible_width(std::string_view text) noexcept {
    std::size_t width = 0;
    std::size_t index = 0;
    while (index < text.size()) {
        if (text[index] == '\x1b' && index + 1 < text.size() && text[index + 1] == '[') {
            index += 2;
            while (index < text.size()) {
                const unsigned char code = static_cast<unsigned char>(text[index]);
                ++index;
                if (code >= 0x40U && code <= 0x7EU) break;  // CSI final byte
            }
            continue;
        }
        const auto lead = static_cast<unsigned char>(text[index]);
        index += std::min(utf8_length(lead), text.size() - index);
        ++width;
    }
    return width;
}

// Clips to `width` display columns.  Escape sequences are copied whole, so a
// truncated coloured line keeps a valid (reset-terminated) ANSI stream.
[[nodiscard]] std::string clip_ansi(std::string_view text, std::size_t width) {
    if (width == 0) return {};
    std::string out;
    out.reserve(std::min<std::size_t>(text.size(), width * 2 + 8));
    std::size_t columns = 0;
    std::size_t index = 0;
    bool saw_escape = false;
    while (index < text.size()) {
        if (text[index] == '\x1b' && index + 1 < text.size() && text[index + 1] == '[') {
            const std::size_t start = index;
            index += 2;
            while (index < text.size()) {
                const unsigned char code = static_cast<unsigned char>(text[index]);
                ++index;
                if (code >= 0x40U && code <= 0x7EU) break;
            }
            out.append(text.substr(start, index - start));
            saw_escape = true;
            continue;
        }
        if (columns >= width) break;
        const auto lead = static_cast<unsigned char>(text[index]);
        const std::size_t length = std::min(utf8_length(lead), text.size() - index);
        out.append(text.substr(index, length));
        index += length;
        ++columns;
    }
    if (saw_escape) out += kReset;
    return out;
}

// Clips then right-pads to exactly `width` columns.
[[nodiscard]] std::string fit(std::string_view text, std::size_t width) {
    std::string out = clip_ansi(text, width);
    const std::size_t used = visible_width(out);
    if (used < width) out.append(width - used, ' ');
    return out;
}

[[nodiscard]] std::string paint(std::string text, std::string_view code, bool enabled) {
    if (!enabled || text.empty()) return text;
    std::string out;
    out.reserve(code.size() + text.size() + 8);
    out += code;
    out += text;
    out += kReset;
    return out;
}

[[nodiscard]] std::string hex_u64(std::uint64_t value, std::size_t min_digits = 1) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%0*llx",
                  static_cast<int>(min_digits),
                  static_cast<unsigned long long>(value));
    return std::string(buffer);
}

[[nodiscard]] std::size_t hex_digits(std::uint64_t value) noexcept {
    std::size_t digits = 1;
    while (value > 0xFU) {
        value >>= 4U;
        ++digits;
    }
    return digits;
}

[[nodiscard]] std::size_t decimal_digits(std::uint64_t value) noexcept {
    std::size_t digits = 1;
    while (value > 9U) {
        value /= 10U;
        ++digits;
    }
    return digits;
}

[[nodiscard]] std::size_t offset_column_width(std::size_t size) noexcept {
    const std::uint64_t last =
        size == 0 ? 0 : static_cast<std::uint64_t>(size) - 1;
    return std::max<std::size_t>(6, std::min<std::size_t>(16, hex_digits(last)));
}

[[nodiscard]] std::string percent_text(double confidence) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%.0f%%", confidence * 100.0);
    return std::string(buffer);
}

[[nodiscard]] std::string join_lines(const std::vector<std::string>& lines) {
    std::size_t total = 0;
    for (const auto& line : lines) total += line.size() + 1;
    std::string out;
    out.reserve(total);
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i != 0) out += '\n';
        out += lines[i];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Layout and per-Dashboard presentation state
// ---------------------------------------------------------------------------

struct PanelGeometry {
    std::size_t hex_width = 0;
    std::size_t hex_height = 0;
    std::size_t hex_view_rows = 0;
    std::size_t ast_width = 0;
    std::size_t ast_height = 0;
    std::size_t ast_view_rows = 0;
    std::size_t preview_width = 0;
    std::size_t preview_height = 0;
    std::size_t preview_view_rows = 0;
};

struct UiState {
    bool help = false;
    std::size_t width = 100;
    std::size_t height = 30;
    PanelGeometry geometry;
};

UiState& ui_state(const Dashboard* dashboard) {
    static thread_local std::unordered_map<const Dashboard*, UiState> states;
    return states[dashboard];
}

[[nodiscard]] std::size_t inner_width(std::size_t width) noexcept {
    return width > 2 ? width - 2 : width;
}

[[nodiscard]] std::size_t inner_height(std::size_t height) noexcept {
    return height > 2 ? height - 2 : height;
}

[[nodiscard]] const char* panel_name(int panel) noexcept {
    switch (panel) {
    case 0: return "Hex";
    case 1: return "AST";
    case 2: return "Preview";
    default: return "Hex";
    }
}

[[nodiscard]] std::string preview_title(const EmitterComponent& preview) {
    const std::string& language = preview.language();
    if (language == "cpp" || language == "c++" || language == "cxx") {
        return "C++ Preview";
    }
    return "Kaitai Preview";
}

class Canvas {
public:
    Canvas(std::size_t width, std::size_t height) : width_(width), rows_(height) {}

    void append(std::size_t row, const std::string& text) {
        if (row < rows_.size()) rows_[row] += text;
    }

    void set(std::size_t row, std::string text) {
        if (row < rows_.size()) rows_[row] = std::move(text);
    }

    [[nodiscard]] std::vector<std::string> finish() const {
        std::vector<std::string> lines;
        lines.reserve(rows_.size());
        for (const auto& row : rows_) lines.push_back(fit(row, width_));
        return lines;
    }

private:
    std::size_t width_;
    std::vector<std::string> rows_;
};

// ---------------------------------------------------------------------------
// Panel rendering
// ---------------------------------------------------------------------------

// Returns exactly `height` lines of exactly `width` columns (or h empty lines
// when there is no width).  A focused panel carries a " *" title marker so the
// focus is visible even with colour disabled.
std::vector<std::string> draw_panel(std::size_t width, std::size_t height,
                                    std::string_view title, bool focused,
                                    const std::vector<std::string>& content, bool color) {
    std::vector<std::string> lines;
    if (width == 0 || height == 0) return lines;

    if (width < 3 || height < 2) {
        lines.reserve(height);
        for (std::size_t i = 0; i < height; ++i) {
            lines.push_back(fit(i < content.size() ? content[i] : std::string{}, width));
        }
        return lines;
    }

    std::string label = "-- ";
    label += title;
    if (focused) label += " *";
    label += " ";
    if (visible_width(label) > width - 2) label = clip_ansi(label, width - 2);
    const std::size_t label_columns = visible_width(label);

    std::string top = "+";
    top += label;
    if (width >= 2 + label_columns) top.append(width - 2 - label_columns, '-');
    top += "+";
    lines.push_back(paint(std::move(top), focused ? kFocusColor : kBlurColor, color));

    const std::size_t body_width = width - 2;
    const std::size_t body_height = height - 2;
    for (std::size_t i = 0; i < body_height; ++i) {
        std::string row = "|";
        row += fit(i < content.size() ? content[i] : std::string{}, body_width);
        row += "|";
        lines.push_back(std::move(row));
    }

    std::string bottom = "+";
    bottom.append(width - 2, '-');
    bottom += "+";
    lines.push_back(paint(std::move(bottom), focused ? kFocusColor : kBlurColor, color));
    return lines;
}

// ---------------------------------------------------------------------------
// Panel content
// ---------------------------------------------------------------------------

std::vector<std::string> hex_content(const HexComponent& hex, const DashboardModel& model,
                                     std::size_t width, std::size_t height, bool color) {
    std::vector<std::string> lines;
    if (width == 0 || height == 0) return lines;

    const std::size_t offset_width = offset_column_width(model.view.size());
    const std::size_t gutter = 1;
    const std::size_t prefix = gutter + offset_width + 1;
    const std::size_t bytes_per_row = hex.bytes_per_row();

    // Too narrow even for one byte cell: degrade to an offset listing.
    if (width <= prefix + 2) {
        for (const HexRow& row : hex.visible_rows(height)) {
            lines.push_back(fit(hex_u64(row.offset, offset_width), width));
        }
        return lines;
    }

    const std::size_t available = width - prefix;
    std::size_t shown = bytes_per_row;
    bool ascii = false;
    if (width >= prefix + bytes_per_row * 3 + 2 + bytes_per_row) {
        shown = bytes_per_row;
        ascii = true;
    } else if (width >= prefix + 8 * 3 + 2 + 8) {
        // Prefer losing a few byte columns over losing the ASCII pane entirely.
        shown = std::min(bytes_per_row, (width - prefix - 2) / 4);
        ascii = true;
    } else {
        shown = std::max<std::size_t>(
            1, std::min(bytes_per_row, available / 3));
    }

    for (const HexRow& row : hex.visible_rows(height)) {
        std::string line;
        const bool cursor_row = row.offset <= hex.cursor_offset() &&
                                hex.cursor_offset() - row.offset <
                                    std::max<std::size_t>(row.length, 1);
        line += cursor_row ? '>' : (row.row_selected ? '*' : ' ');
        line += hex_u64(row.offset, offset_width);
        line += ' ';

        for (std::size_t cell = 0; cell < shown; ++cell) {
            if (cell >= row.length) {
                line += "   ";
                continue;
            }
            const std::uint8_t value = row.bytes[cell];
            char buffer[8];
            if (row.selected[cell]) {
                std::snprintf(buffer, sizeof(buffer), "%02X", static_cast<unsigned>(value));
            } else {
                std::snprintf(buffer, sizeof(buffer), "%02x", static_cast<unsigned>(value));
            }
            std::string text(buffer);
            if (color) {
                std::string codes;
                if (row.selected[cell]) {
                    codes += kSelectionColor;
                } else {
                    const unsigned intensity = row.intensity[cell];
                    const int gray = 232 + static_cast<int>(intensity) * 23 / 255;
                    const int foreground = intensity > 140U ? 16 : 231;
                    codes += "\x1b[38;5;";
                    codes += std::to_string(foreground);
                    codes += ";48;5;";
                    codes += std::to_string(gray);
                    codes += 'm';
                }
                if (row.offset + cell == hex.cursor_offset()) codes += "\x1b[4m";
                line += paint(std::move(text), codes, true);
            } else {
                line += text;
            }
            line += ' ';
        }

        if (ascii) {
            line += "  ";
            for (std::size_t cell = 0; cell < shown; ++cell) {
                line += cell < row.length ? row.ascii[cell] : ' ';
            }
        }
        lines.push_back(fit(line, width));
    }
    return lines;
}

std::vector<std::string> ast_content(const AstComponent& ast, std::size_t width,
                                     std::size_t height, bool color) {
    std::vector<std::string> lines;
    if (width == 0 || height == 0) return lines;

    const std::vector<AstRow>& rows = ast.rows();
    std::size_t first = 0;
    if (rows.size() > height) {
        const std::size_t selected = ast.selected_row();
        first = selected >= height ? selected - height + 1 : 0;
        if (first + height > rows.size()) first = rows.size() - height;
    }

    for (std::size_t line_index = 0; line_index < height; ++line_index) {
        const std::size_t index = first + line_index;
        if (index >= rows.size()) {
            lines.emplace_back();
            continue;
        }
        const AstRow& row = rows[index];
        std::string line;
        line += row.selected ? '>' : ' ';
        const std::size_t indent =
            static_cast<std::size_t>(std::min(row.depth, 12)) * 2;
        line.append(indent, ' ');
        line += row.has_children ? (row.expanded ? '-' : '+') : ' ';
        line += ' ';
        line += row.label;
        line += "  ";
        line += row.type_name;
        line += "  @0x";
        line += hex_u64(row.offset);
        line += " +";
        line += std::to_string(row.size);
        line += "  ";
        line += percent_text(row.confidence);

        if (color && row.selected) {
            line = paint(fit(line, width), kSelectionColor, true);
        } else {
            line = fit(line, width);
        }
        lines.push_back(std::move(line));
    }
    return lines;
}

std::vector<std::string> preview_content(const EmitterComponent& preview, std::size_t width,
                                         std::size_t height, bool color) {
    std::vector<std::string> lines;
    if (width == 0 || height == 0) return lines;

    std::size_t number_width = 0;
    if (width >= 30) {
        const std::int64_t top = std::max<std::int64_t>(preview.top_line(), 0);
        const std::uint64_t last =
            static_cast<std::uint64_t>(top) + static_cast<std::uint64_t>(height);
        number_width = std::max<std::size_t>(4, decimal_digits(last)) + 1;
        if (number_width + 8 > width) number_width = 0;
    }

    const std::size_t text_width =
        width > number_width ? width - number_width : width;
    const std::vector<std::string> visible = preview.visible_lines(height, text_width);
    lines.reserve(visible.size());

    for (std::size_t i = 0; i < visible.size(); ++i) {
        std::string line;
        if (number_width != 0) {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "%*lld ",
                          static_cast<int>(number_width - 1),
                          static_cast<long long>(preview.top_line() +
                                                 static_cast<std::int64_t>(i) + 1));
            line += paint(std::string(buffer), kNumberColor, color);
        }
        line += visible[i];
        lines.push_back(fit(line, width));
    }
    return lines;
}

// ---------------------------------------------------------------------------
// Header / footer / help
// ---------------------------------------------------------------------------

std::string header_text(const DashboardModel& model, int focus, bool color) {
    const std::string& name =
        !model.source_name.empty() ? model.source_name : model.view.name();
    std::string line = " TypeMorph | ";
    line += name.empty() ? "<unnamed>" : name;
    line += " | ";
    line += model.format_name.empty() ? "recovered" : model.format_name;
    line += " | focus: ";
    line += panel_name(focus);
    line += " | Tab focus  ? help  q quit ";
    return paint(std::move(line), kHeaderColor, color);
}

std::string footer_text(const HexComponent& hex, const DashboardModel& model) {
    std::string line = " 0x";
    line += hex_u64(hex.cursor_offset(), 8);
    if (hex.has_selection()) {
        line += "  sel 0x";
        line += hex_u64(hex.selection_offset(), 8);
        line += "+";
        line += std::to_string(hex.selection_length());
    } else {
        line += "  sel none";
    }
    line += "  file ";
    line += std::to_string(model.view.size());
    line += " B  |  Tab focus  s/w save  g/G jump  Up/Down move  Enter toggle  e/K preview  ? help  q quit";
    return line;
}

std::vector<std::string> help_content() {
    return {
        "Keyboard shortcuts",
        "",
        "  Tab            cycle focus: Hex -> AST -> Preview",
        "  Up / Down      move cursor, tree selection or preview scroll",
        "  Left / Right   byte step (hex), collapse/expand (AST)",
        "  PgUp / PgDn    move one page",
        "  Home / End     jump to the start / end",
        "  g / G          jump hex cursor to start / end",
        "  s / w          save the active preview to disk",
        "  Enter          toggle the selected AST node",
        "  e              show the Kaitai preview",
        "  K              show the C++ preview",
        "  ?              toggle this help",
        "  q / Esc        quit",
    };
}

// ---------------------------------------------------------------------------
// Terminal backend
// ---------------------------------------------------------------------------

[[nodiscard]] std::pair<std::size_t, std::size_t> environment_size() {
    std::size_t width = 100;
    std::size_t height = 30;
    if (const char* columns = std::getenv("COLUMNS")) {
        const long value = std::strtol(columns, nullptr, 10);
        if (value > 0) width = static_cast<std::size_t>(value);
    }
    if (const char* rows = std::getenv("LINES")) {
        const long value = std::strtol(rows, nullptr, 10);
        if (value > 0) height = static_cast<std::size_t>(value);
    }
    return {width, height};
}

#ifdef _WIN32
[[nodiscard]] bool stdout_is_terminal() { return _isatty(_fileno(stdout)) != 0; }
#else
[[nodiscard]] bool stdout_is_terminal() { return ::isatty(STDOUT_FILENO) != 0; }
#endif

class TerminalSession {
public:
    TerminalSession() {
#ifdef _WIN32
        output_ = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output_ != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(output_, &mode) != 0) {
                output_mode_ = mode;
                output_mode_valid_ = true;
                SetConsoleMode(output_, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                                           ENABLE_PROCESSED_OUTPUT);
            }
        }
        input_ = GetStdHandle(STD_INPUT_HANDLE);
        if (input_ != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(input_, &mode) != 0) {
                input_mode_ = mode;
                input_mode_valid_ = true;
                DWORD raw = mode;
                raw &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
                raw |= ENABLE_EXTENDED_FLAGS;
                SetConsoleMode(input_, raw);
            }
        }
        code_page_ = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
#else
        if (::isatty(STDIN_FILENO) != 0 && ::tcgetattr(STDIN_FILENO, &saved_) == 0) {
            termios raw = saved_;
            raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | ISIG | IEXTEN));
            raw.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL));
            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;
            if (::tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) saved_valid_ = true;
        }
#endif
    }

    TerminalSession(const TerminalSession&) = delete;
    TerminalSession& operator=(const TerminalSession&) = delete;

    ~TerminalSession() { restore(); }

    void enter_alternate_screen() {
        write("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        alternate_ = true;
    }

    void leave_alternate_screen() {
        if (!alternate_) return;
        write("\x1b[?25h\x1b[?1049l");
        alternate_ = false;
    }

    void write(std::string_view data) const {
        if (data.empty()) return;
        std::fwrite(data.data(), 1, data.size(), stdout);
        std::fflush(stdout);
    }

    [[nodiscard]] int read_key() const {
#ifdef _WIN32
        const int first = _getch();
        if (first == 0 || first == 224) {
            const int extended = _getch();
            switch (extended) {
            case 72: return key_up;
            case 80: return key_down;
            case 75: return key_left;
            case 77: return key_right;
            case 73: return key_page_up;
            case 81: return key_page_down;
            case 71: return key_home;
            case 79: return key_end;
            default: return -1;
            }
        }
        return first;
#else
        unsigned char first = 0;
        const auto got = ::read(STDIN_FILENO, &first, 1);
        if (got <= 0) return -1;
        if (first != 0x1BU) return first;

        // Escape either starts a VT sequence or is the bare Escape key.
        fd_set set;
        FD_ZERO(&set);
        FD_SET(STDIN_FILENO, &set);
        timeval timeout{};
        timeout.tv_usec = 50000;
        if (::select(STDIN_FILENO + 1, &set, nullptr, nullptr, &timeout) <= 0) {
            return key_escape;
        }
        unsigned char second = 0;
        if (::read(STDIN_FILENO, &second, 1) <= 0) return key_escape;
        if (second != '[' && second != 'O') return key_escape;

        std::string parameters;
        char final_byte = 0;
        for (int i = 0; i < 8; ++i) {
            fd_set more;
            FD_ZERO(&more);
            FD_SET(STDIN_FILENO, &more);
            timeval wait{};
            wait.tv_usec = 50000;
            if (::select(STDIN_FILENO + 1, &more, nullptr, nullptr, &wait) <= 0) break;
            unsigned char byte = 0;
            if (::read(STDIN_FILENO, &byte, 1) <= 0) break;
            if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                byte == '~') {
                final_byte = static_cast<char>(byte);
                break;
            }
            parameters.push_back(static_cast<char>(byte));
        }
        switch (final_byte) {
        case 'A': return key_up;
        case 'B': return key_down;
        case 'C': return key_right;
        case 'D': return key_left;
        case 'H': return key_home;
        case 'F': return key_end;
        case '~':
            if (parameters == "5") return key_page_up;
            if (parameters == "6") return key_page_down;
            return -1;
        default: return -1;
        }
#endif
    }

private:
    void restore() {
        leave_alternate_screen();
#ifdef _WIN32
        if (output_mode_valid_ && output_ != INVALID_HANDLE_VALUE) {
            SetConsoleMode(output_, output_mode_);
        }
        if (input_mode_valid_ && input_ != INVALID_HANDLE_VALUE) {
            SetConsoleMode(input_, input_mode_);
        }
        if (code_page_ != 0) SetConsoleOutputCP(code_page_);
#else
        if (saved_valid_) {
            ::tcsetattr(STDIN_FILENO, TCSANOW, &saved_);
            saved_valid_ = false;
        }
#endif
    }

    bool alternate_ = false;
#ifdef _WIN32
    void* output_ = nullptr;
    void* input_ = nullptr;
    DWORD output_mode_ = 0;
    DWORD input_mode_ = 0;
    bool output_mode_valid_ = false;
    bool input_mode_valid_ = false;
    UINT code_page_ = 0;
#else
    termios saved_{};
    bool saved_valid_ = false;
#endif
};

[[nodiscard]] std::pair<std::size_t, std::size_t> terminal_size() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info{};
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(output, &info) != 0) {
        const int width = static_cast<int>(info.srWindow.Right) -
                          static_cast<int>(info.srWindow.Left) + 1;
        const int height = static_cast<int>(info.srWindow.Bottom) -
                           static_cast<int>(info.srWindow.Top) + 1;
        if (width > 0 && height > 0) {
            return {static_cast<std::size_t>(width), static_cast<std::size_t>(height)};
        }
    }
#else
    winsize size{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0 &&
        size.ws_row > 0) {
        return {static_cast<std::size_t>(size.ws_col),
                static_cast<std::size_t>(size.ws_row)};
    }
#endif
    return environment_size();
}

[[nodiscard]] bool is_quit_key(int key) noexcept {
    return key == 'q' || key == 'Q' || key == key_escape || key == 3;
}

}  // namespace

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

Dashboard::Dashboard(DashboardModel model, DashboardOptions options)
    : model_(std::move(model)),
      options_(options),
      hex_(model_.view, 16),
      ast_(model_.root) {
    ui_state(this) = UiState{};
    if (options_.initial_hex_offset != 0) {
        hex_.scroll_to(options_.initial_hex_offset);
        hex_.set_cursor(options_.initial_hex_offset);
    }
    sync_preview();
}

std::string Dashboard::render_frame(std::size_t width, std::size_t height,
                                    int active_panel) const {
    UiState& state = ui_state(this);
    state.width = width;
    state.height = height;
    if (width == 0 || height == 0) return {};

    int focus = active_panel;
    if (focus < 0) focus = 0;
    if (focus > 2) focus = 2;
    const bool color = options_.color;

    const std::size_t header_height = 1;
    std::size_t footer_height = 0;
    std::size_t body_height = height - header_height;
    if (height >= 6) {
        footer_height = 1;
        body_height = height - header_height - footer_height;
    }
    const std::size_t body_row = header_height;

    Canvas canvas(width, height);
    canvas.set(0, fit(header_text(model_, focus, color), width));

    if (state.help) {
        if (body_height > 0) {
            const std::vector<std::string> block =
                draw_panel(width, body_height, "Help", true,
                           help_content(), color);
            for (std::size_t i = 0; i < block.size(); ++i) {
                canvas.set(body_row + i, block[i]);
            }
        }
        return join_lines(canvas.finish());
    }

    PanelGeometry geometry{};
    auto place_block = [&canvas](std::size_t row,
                                 const std::vector<std::string>& block) {
        for (std::size_t i = 0; i < block.size(); ++i) canvas.append(row + i, block[i]);
    };
    auto make_content = [&](int panel, std::size_t panel_width,
                            std::size_t panel_height) {
        const std::size_t content_width = inner_width(panel_width);
        const std::size_t content_height = inner_height(panel_height);
        switch (panel) {
        case 0:
            return hex_content(hex_, model_, content_width, content_height, color);
        case 1:
            return ast_content(ast_, content_width, content_height, color);
        default:
            return preview_content(preview_, content_width, content_height, color);
        }
    };

    if (body_height > 0) {
        const bool three_columns = width >= 150 && body_height >= 8;
        const bool two_columns = !three_columns && width >= 76 && body_height >= 6;
        const bool stacked = !three_columns && !two_columns && width >= 32 &&
                             body_height >= 9;

        if (three_columns) {
            std::size_t hex_width = std::max<std::size_t>(56, width * 44 / 100);
            std::size_t ast_width = std::max<std::size_t>(30, width * 24 / 100);
            if (hex_width + ast_width + 12 > width) {
                hex_width = width / 2;
                ast_width = width / 4;
            }
            const std::size_t preview_width = width - hex_width - ast_width;

            geometry.hex_width = hex_width;
            geometry.hex_height = body_height;
            geometry.hex_view_rows = inner_height(body_height);
            geometry.ast_width = ast_width;
            geometry.ast_height = body_height;
            geometry.ast_view_rows = inner_height(body_height);
            geometry.preview_width = preview_width;
            geometry.preview_height = body_height;
            geometry.preview_view_rows = inner_height(body_height);

            place_block(body_row,
                        draw_panel(hex_width, body_height, "Hex + Entropy", focus == 0,
                                   make_content(0, hex_width, body_height), color));
            place_block(body_row,
                        draw_panel(ast_width, body_height,
                                   "AST Tree (" + std::to_string(ast_.rows().size()) + ")",
                                   focus == 1, make_content(1, ast_width, body_height), color));
            place_block(body_row,
                        draw_panel(preview_width, body_height, preview_title(preview_),
                                   focus == 2,
                                   make_content(2, preview_width, body_height), color));
        } else if (two_columns) {
            std::size_t hex_width = std::max<std::size_t>(56, width * 60 / 100);
            if (hex_width > width - 24) hex_width = width / 2;
            const std::size_t side_width = width - hex_width;
            const std::size_t ast_height = body_height / 2;
            const std::size_t preview_height = body_height - ast_height;

            geometry.hex_width = hex_width;
            geometry.hex_height = body_height;
            geometry.hex_view_rows = inner_height(body_height);
            geometry.ast_width = side_width;
            geometry.ast_height = ast_height;
            geometry.ast_view_rows = inner_height(ast_height);
            geometry.preview_width = side_width;
            geometry.preview_height = preview_height;
            geometry.preview_view_rows = inner_height(preview_height);

            place_block(body_row,
                        draw_panel(hex_width, body_height, "Hex + Entropy", focus == 0,
                                   make_content(0, hex_width, body_height), color));
            place_block(body_row,
                        draw_panel(side_width, ast_height,
                                   "AST Tree (" + std::to_string(ast_.rows().size()) + ")",
                                   focus == 1, make_content(1, side_width, ast_height), color));
            place_block(body_row + ast_height,
                        draw_panel(side_width, preview_height, preview_title(preview_),
                                   focus == 2,
                                   make_content(2, side_width, preview_height), color));
        } else if (stacked) {
            std::size_t hex_height = std::max<std::size_t>(3, body_height * 2 / 5);
            std::size_t ast_height = std::max<std::size_t>(3, body_height / 3);
            if (hex_height + ast_height + 3 > body_height) {
                ast_height = std::max<std::size_t>(3, (body_height - 3) / 2);
                hex_height = body_height - 3 - ast_height;
            }
            const std::size_t preview_height = body_height - hex_height - ast_height;

            geometry.hex_width = width;
            geometry.hex_height = hex_height;
            geometry.hex_view_rows = inner_height(hex_height);
            geometry.ast_width = width;
            geometry.ast_height = ast_height;
            geometry.ast_view_rows = inner_height(ast_height);
            geometry.preview_width = width;
            geometry.preview_height = preview_height;
            geometry.preview_view_rows = inner_height(preview_height);

            place_block(body_row,
                        draw_panel(width, hex_height, "Hex + Entropy", focus == 0,
                                   make_content(0, width, hex_height), color));
            place_block(body_row + hex_height,
                        draw_panel(width, ast_height,
                                   "AST Tree (" + std::to_string(ast_.rows().size()) + ")",
                                   focus == 1, make_content(1, width, ast_height), color));
            place_block(body_row + hex_height + ast_height,
                        draw_panel(width, preview_height, preview_title(preview_),
                                   focus == 2, make_content(2, width, preview_height), color));
        } else {
            // Tiny terminal: dedicate the whole body to the focused panel.
            geometry.hex_view_rows = focus == 0 ? inner_height(body_height) : 0;
            geometry.ast_view_rows = focus == 1 ? inner_height(body_height) : 0;
            geometry.preview_view_rows = focus == 2 ? inner_height(body_height) : 0;
            if (focus == 0) {
                geometry.hex_width = width;
                geometry.hex_height = body_height;
            } else if (focus == 1) {
                geometry.ast_width = width;
                geometry.ast_height = body_height;
            } else {
                geometry.preview_width = width;
                geometry.preview_height = body_height;
            }
            const std::string title = focus == 0
                                          ? std::string("Hex + Entropy")
                                          : (focus == 1
                                                 ? "AST Tree (" +
                                                       std::to_string(ast_.rows().size()) + ")"
                                                 : preview_title(preview_));
            const std::vector<std::string> block =
                draw_panel(width, body_height, title, true,
                           make_content(focus, width, body_height), color);
            for (std::size_t i = 0; i < block.size(); ++i) {
                canvas.set(body_row + i, block[i]);
            }
        }
    }

    if (footer_height != 0) {
        canvas.set(header_height + body_height,
                   fit(paint(footer_text(hex_, model_), kFooterColor, color), width));
    }

    state.geometry = geometry;
    return join_lines(canvas.finish());
}

bool Dashboard::handle_key(int key) {
    UiState& state = ui_state(this);

    if (state.help) {
        state.help = false;
        if (is_quit_key(key)) {
            quit_ = true;
            return false;
        }
        return true;
    }

    if (is_quit_key(key)) {
        quit_ = true;
        return false;
    }
    if (key == '?') {
        state.help = true;
        return true;
    }
    if (key == '\t') {
        active_panel_ = (active_panel_ + 1) % 3;
        return true;
    }
    if (key == 'e') {
        active_panel_ = 2;
        preview_.set_active_language("kaitai");
        sync_preview();
        return true;
    }
    if (key == 'K') {
        active_panel_ = 2;
        preview_.set_active_language("cpp");
        sync_preview();
        return true;
    }
    if (key == 's' || key == 'w') {
        save_active_preview();
        return true;
    }
    if (key == 'g') {
        jump_to(0);
        return true;
    }
    if (key == 'G') {
        const auto last = model_.view.empty() ? 0 : static_cast<std::uint64_t>(model_.view.size() - 1);
        jump_to(last);
        return true;
    }

    const auto rows_or = [](std::size_t stored, std::size_t fallback) {
        return stored > 2 ? stored : fallback;
    };
    const std::size_t hex_rows = rows_or(state.geometry.hex_view_rows, 8);
    const std::size_t ast_rows = rows_or(state.geometry.ast_view_rows, 8);
    const std::size_t preview_rows = rows_or(state.geometry.preview_view_rows, 8);
    const std::int64_t byte_row = static_cast<std::int64_t>(hex_.bytes_per_row());

    // Keep the hex cursor inside the real panel height after a navigation key.
    auto keep_hex_cursor_visible = [&]() {
        const std::size_t bpr = hex_.bytes_per_row();
        if (bpr == 0) return;
        const std::uint64_t cursor_row = hex_.cursor_offset() / bpr;
        const std::uint64_t top_row = hex_.top_offset() / bpr;
        if (cursor_row < top_row) {
            hex_.scroll_to(hex_.cursor_offset());
        } else if (cursor_row >= top_row + hex_rows) {
            hex_.scroll_to((cursor_row - hex_rows + 1) * bpr);
        }
    };
    auto sync_selection = [&]() {
        const core::TypeNode* node = ast_.selected_node();
        if (node != nullptr && ast_.selected_size() != 0) {
            hex_.set_selection(ast_.selected_offset(), ast_.selected_size());
        }
    };
    constexpr std::size_t no_row = std::numeric_limits<std::size_t>::max();
    auto find_parent_row = [&](std::size_t row) -> std::size_t {
        const std::vector<AstRow>& rows = ast_.rows();
        if (row >= rows.size()) return no_row;
        const int depth = rows[row].depth;
        for (std::size_t i = row; i > 0; --i) {
            const std::size_t candidate = i - 1;
            if (rows[candidate].depth < depth) return candidate;
        }
        return no_row;
    };

    switch (active_panel_) {
    case 0:
        if (key == key_up || key == 'k') {
            hex_.move_cursor(-byte_row);
        } else if (key == key_down || key == 'j') {
            hex_.move_cursor(byte_row);
        } else if (key == key_left || key == 'h') {
            hex_.move_cursor(-1);
        } else if (key == key_right || key == 'l') {
            hex_.move_cursor(1);
        } else if (key == key_page_up || key == key_page_down) {
            // Paging scrolls the viewport by one full screen and then keeps the
            // cursor inside the newly visible window (cursor-first navigation
            // would leave the viewport parked on a tiny file).
            const std::int64_t direction = key == key_page_up ? -1 : 1;
            hex_.scroll_rows(direction * static_cast<std::int64_t>(hex_rows));
            const std::uint64_t bpr = hex_.bytes_per_row();
            const std::uint64_t top = hex_.top_offset();
            if (bpr != 0 && !model_.view.empty()) {
                const std::uint64_t last_visible = std::min<std::uint64_t>(
                    top + bpr * static_cast<std::uint64_t>(hex_rows) - 1,
                    static_cast<std::uint64_t>(model_.view.size() - 1));
                if (hex_.cursor_offset() < top) {
                    hex_.set_cursor(top);
                } else if (hex_.cursor_offset() > last_visible) {
                    hex_.set_cursor(last_visible);
                }
                hex_.scroll_to(top);
            }
        } else if (key == key_home) {
            hex_.scroll_to(0);
            hex_.set_cursor(0);
        } else if (key == key_end) {
            const std::uint64_t last = model_.view.empty()
                                           ? 0
                                           : static_cast<std::uint64_t>(model_.view.size() - 1);
            hex_.scroll_to(last);
            hex_.set_cursor(last);
        } else if (key == '\r' || key == '\n') {
            ast_.select_offset(hex_.cursor_offset());
            sync_selection();
        } else {
            return true;
        }
        keep_hex_cursor_visible();
        return true;

    case 1:
        if (key == key_up || key == 'k') {
            ast_.move_selection(-1);
        } else if (key == key_down || key == 'j') {
            ast_.move_selection(1);
        } else if (key == key_page_up) {
            ast_.move_selection(-static_cast<std::int64_t>(ast_rows));
        } else if (key == key_page_down) {
            ast_.move_selection(static_cast<std::int64_t>(ast_rows));
        } else if (key == key_home) {
            ast_.select_row(0);
        } else if (key == key_end) {
            if (!ast_.rows().empty()) ast_.select_row(ast_.rows().size() - 1);
        } else if (key == key_left) {
            const std::size_t row = ast_.selected_row();
            const std::vector<AstRow>& rows = ast_.rows();
            if (row < rows.size() && rows[row].has_children && rows[row].expanded) {
                ast_.toggle(row);
            } else {
                // Leaf or collapsed node: jump to the parent.  If the parent is
                // expanded, collapse it as well so Left walks back up the tree.
                const std::size_t parent = find_parent_row(row);
                if (parent != no_row) {
                    ast_.select_row(parent);
                    if (parent < ast_.rows().size() &&
                        ast_.rows()[parent].has_children &&
                        ast_.rows()[parent].expanded) {
                        ast_.toggle(parent);
                    }
                }
            }
        } else if (key == key_right) {
            const std::size_t row = ast_.selected_row();
            const core::TypeNode* node = ast_.selected_node();
            if (node != nullptr && row < ast_.rows().size() &&
                ast_.rows()[row].has_children && !ast_.rows()[row].expanded) {
                ast_.toggle(row);
            } else {
                ast_.move_selection(1);
            }
        } else if (key == '\r' || key == '\n') {
            ast_.toggle(ast_.selected_row());
        } else {
            return true;
        }
        sync_selection();
        return true;

    default:
        if (key == key_up || key == 'k') {
            preview_.scroll(-1);
        } else if (key == key_down || key == 'j') {
            preview_.scroll(1);
        } else if (key == key_page_up) {
            preview_.page(-1, preview_rows);
        } else if (key == key_page_down) {
            preview_.page(1, preview_rows);
        } else if (key == key_home) {
            preview_.scroll_to(0);
        } else if (key == key_end) {
            preview_.scroll_to(std::numeric_limits<std::int64_t>::max());
        }
        return true;
    }
}

int Dashboard::run() {
    if (!stdout_is_terminal()) {
        // `--render-once` style behaviour: no alternate screen, no input loop.
        const auto [width, height] = terminal_size();
        const std::string frame = render_frame(width, height, active_panel_);
        std::fwrite(frame.data(), 1, frame.size(), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
        return 0;
    }

    TerminalSession session;
    if (options_.use_alternate_screen) {
        session.enter_alternate_screen();
    } else {
        session.write("\x1b[?25l\x1b[2J\x1b[H");
    }
    for (;;) {
        const auto [width, height] = terminal_size();
        const std::string frame = render_frame(width, height, active_panel_);
        std::string output = "\x1b[H";
        output += frame;
        output += "\x1b[J";
        session.write(output);

        const int key = session.read_key();
        if (key == -1) continue;
        if (!handle_key(key)) break;
    }
    if (options_.use_alternate_screen) {
        session.leave_alternate_screen();
    } else {
        session.write("\x1b[?25h");
    }
    return 0;
}

void Dashboard::sync_preview() {
    if (preview_.language() == "cpp" || preview_.language() == "c++" ||
        preview_.language() == "cxx") {
        preview_.set_text(model_.cpp_preview);
    } else {
        preview_.set_text(model_.kaitai_preview);
    }
}

void Dashboard::jump_to(std::uint64_t offset) {
    if (model_.view.empty()) return;
    if (offset >= model_.view.size()) offset = static_cast<std::uint64_t>(model_.view.size() - 1);
    hex_.scroll_to(offset);
    hex_.set_cursor(offset);
}

bool Dashboard::save_active_preview(const std::string& path) {
    std::string target = path;
    if (target.empty()) {
        std::string base = model_.source_name.empty() ? model_.format_name : model_.source_name;
        if (base.empty()) base = "recovered";
        const auto dot = base.find_last_of('.');
        if (dot != std::string::npos) base = base.substr(0, dot);
        if (preview_.language() == "cpp" || preview_.language() == "c++" ||
            preview_.language() == "cxx") {
            target = base + ".hpp";
        } else if (preview_.language() == "imhex" || preview_.language() == "hexpat") {
            target = base + ".hexpat";
        } else {
            target = base + ".ksy";
        }
    }
    std::ofstream stream(target, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    const std::string& text = preview_.text();
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return stream.good();
}

}  // namespace typemorph::tui

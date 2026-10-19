// TypeMorph - interactive terminal dashboard.
//
// The dashboard is implemented with a self-contained ANSI terminal backend so
// that the single binary never depends on a system package being present.  When
// FTXUI is found by CMake the same model is exposed to an FTXUI frontend; the
// native backend remains the portable fallback (and is what runs in CI).
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/tui/ast_component.hpp"
#include "typemorph/tui/emitter_component.hpp"
#include "typemorph/tui/hex_component.hpp"

#include <cstddef>
#include <string>

namespace typemorph::tui {

struct DashboardModel {
    core::BinaryView view;
    core::TypePtr root;
    std::string kaitai_preview;
    std::string cpp_preview;
    std::string source_name;
    std::string format_name = "recovered";
};

struct DashboardOptions {
    bool color = true;
    bool use_alternate_screen = true;
    std::size_t initial_hex_offset = 0;
};

class Dashboard {
public:
    explicit Dashboard(DashboardModel model, DashboardOptions options = {});

    // Interactive loop; returns the process exit code.
    int run();

    // Deterministic rendering hook used by tests and by --render-once.
    [[nodiscard]] std::string render_frame(std::size_t width, std::size_t height,
                                           int active_panel) const;

    // Processes a logical key.  Returns false when the dashboard requested quit.
    bool handle_key(int key);

    // Jumps the hex cursor and scroll position to the specified offset.
    void jump_to(std::uint64_t offset);

    // Saves the active preview text to disk. If path is empty, derives default filename.
    bool save_active_preview(const std::string& path = "");

    [[nodiscard]] int active_panel() const noexcept { return active_panel_; }
    [[nodiscard]] HexComponent& hex() noexcept { return hex_; }
    [[nodiscard]] AstComponent& ast() noexcept { return ast_; }
    [[nodiscard]] EmitterComponent& preview() noexcept { return preview_; }

private:
    void sync_preview();

    DashboardModel model_;
    DashboardOptions options_;
    HexComponent hex_;
    AstComponent ast_;
    EmitterComponent preview_;
    int active_panel_ = 0;
    bool quit_ = false;
};

}  // namespace typemorph::tui

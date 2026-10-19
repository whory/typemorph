// TypeMorph - TUI unit tests.
//
// These tests never touch a real terminal: the dashboard is exercised through
// its deterministic render_frame() hook and its logical handle_key() input.
#include "typemorph/tui/ast_component.hpp"
#include "typemorph/tui/dashboard.hpp"
#include "typemorph/tui/emitter_component.hpp"
#include "typemorph/tui/hex_component.hpp"

#include "test_framework.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

// Logical key codes with external linkage, defined in src/tui/dashboard.cpp.
namespace typemorph::tui {
extern const int key_up;
extern const int key_down;
extern const int key_left;
extern const int key_right;
extern const int key_page_up;
extern const int key_page_down;
extern const int key_home;
extern const int key_end;
extern const int key_escape;
}  // namespace typemorph::tui

namespace {

using typemorph::core::BinaryView;
using typemorph::core::ByteOrder;
using typemorph::core::PrimitiveKind;
using typemorph::core::TypeField;
using typemorph::core::TypeNode;
using typemorph::core::TypePtr;

BinaryView make_view(std::vector<std::uint8_t> bytes, std::string name) {
    return BinaryView::from_owned(std::move(bytes), std::move(name));
}

std::vector<std::uint8_t> pattern_bytes(std::size_t count) {
    std::vector<std::uint8_t> bytes(count);
    for (std::size_t i = 0; i < count; ++i) {
        bytes[i] = static_cast<std::uint8_t>(i & 0xFFU);
    }
    return bytes;
}

TypePtr make_leaf(std::string name, std::uint64_t offset, std::uint64_t size,
                  double confidence, PrimitiveKind kind = PrimitiveKind::u16) {
    auto node = std::make_shared<TypeNode>();
    node->node = typemorph::core::PrimitiveNode{kind, ByteOrder::little};
    node->name = std::move(name);
    node->offset = offset;
    node->size = size;
    node->confidence = confidence;
    return node;
}

TypeField make_field(std::string name, TypePtr type, std::uint64_t offset,
                     double confidence) {
    TypeField field;
    field.name = std::move(name);
    field.type = std::move(type);
    field.offset = offset;
    field.confidence = confidence;
    return field;
}

TypePtr make_struct(std::string name, std::uint64_t offset, std::uint64_t size,
                    double confidence, std::vector<TypeField> fields) {
    auto node = std::make_shared<TypeNode>();
    typemorph::core::StructNode structure;
    structure.fields = std::move(fields);
    structure.declared_size = size;
    structure.alignment = 1;
    node->node = std::move(structure);
    node->name = std::move(name);
    node->offset = offset;
    node->size = size;
    node->confidence = confidence;
    return node;
}

// Root (offset 0, size 8)
//   magic : u32 @ 0 (confidence 0.99)
//   Pair  : struct @ 4 (confidence 0.90)
//     x   : u16 @ 0 within Pair (absolute 4, confidence 0.80)
//     y   : u16 @ 2 within Pair (absolute 6, confidence 0.70)
TypePtr make_test_tree() {
    auto pair = make_struct(
        "Pair", 4, 4, 0.90,
        {make_field("x", make_leaf("x", 0, 2, 0.80), 0, 0.80),
         make_field("y", make_leaf("y", 2, 2, 0.70), 2, 0.70)});
    return make_struct(
        "Root", 0, 8, 1.0,
        {make_field("magic", make_leaf("magic", 0, 4, 0.99, PrimitiveKind::u32), 0,
                    0.99),
         make_field("pair", std::move(pair), 4, 0.90)});
}

struct DashboardFixture {
    typemorph::tui::DashboardModel model;
    std::string kaitai_text;
    std::string cpp_text;
};

DashboardFixture make_dashboard_fixture() {
    DashboardFixture fixture;
    fixture.kaitai_text = "meta:\n  id: u4\n  pair:\n    x: u2\n    y: u2\n";
    fixture.cpp_text = "struct Root {\n  uint32_t magic;\n  Pair pair;\n};\n";
    fixture.model.view = make_view(pattern_bytes(64), "sample.bin");
    fixture.model.root = make_test_tree();
    fixture.model.kaitai_preview = fixture.kaitai_text;
    fixture.model.cpp_preview = fixture.cpp_text;
    fixture.model.source_name = "sample.bin";
    fixture.model.format_name = "testfmt";
    return fixture;
}

typemorph::tui::DashboardOptions plain_options() {
    typemorph::tui::DashboardOptions options;
    options.color = false;
    return options;
}

std::size_t count_lines(const std::string& frame) {
    if (frame.empty()) return 0;
    return static_cast<std::size_t>(std::count(frame.begin(), frame.end(), '\n')) + 1;
}

std::vector<std::string> split_lines(const std::string& frame) {
    std::vector<std::string> lines;
    std::string current;
    for (const char character : frame) {
        if (character == '\n') {
            lines.push_back(current);
            current.clear();
        } else {
            current.push_back(character);
        }
    }
    lines.push_back(current);
    return lines;
}

bool is_valid_utf8(const std::string& text) {
    std::size_t index = 0;
    while (index < text.size()) {
        const auto lead = static_cast<unsigned char>(text[index]);
        std::size_t length = 1;
        if (lead < 0x80U) {
            length = 1;
        } else if ((lead & 0xE0U) == 0xC0U) {
            length = 2;
        } else if ((lead & 0xF0U) == 0xE0U) {
            length = 3;
        } else if ((lead & 0xF8U) == 0xF0U) {
            length = 4;
        } else {
            return false;
        }
        if (index + length > text.size()) return false;
        for (std::size_t i = 1; i < length; ++i) {
            const auto continuation = static_cast<unsigned char>(text[index + i]);
            if ((continuation & 0xC0U) != 0x80U) return false;
        }
        index += length;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// HexComponent
// ---------------------------------------------------------------------------

TEST_CASE("tui.hex.visible_rows_ascii_and_tail") {
    typemorph::tui::HexComponent hex(make_view(pattern_bytes(70), "hex.bin"), 16);
    CHECK_EQ(hex.bytes_per_row(), std::size_t{16});
    CHECK_EQ(hex.total_rows(), std::size_t{5});
    CHECK_EQ(hex.cursor_offset(), std::uint64_t{0});
    CHECK_EQ(hex.top_offset(), std::uint64_t{0});

    const std::vector<typemorph::tui::HexRow> rows = hex.visible_rows(3);
    REQUIRE(rows.size() == 3);
    CHECK_EQ(rows[0].offset, std::uint64_t{0});
    CHECK_EQ(rows[0].length, std::size_t{16});
    CHECK_EQ(rows[0].bytes[0], std::uint8_t{0});
    CHECK_EQ(rows[0].bytes[15], std::uint8_t{15});
    CHECK_EQ(rows[0].ascii[0], '.');
    CHECK_EQ(rows[2].offset, std::uint64_t{32});
    CHECK_EQ(rows[2].ascii[0], ' ');   // 0x20 is printable
    CHECK_EQ(rows[2].ascii[1], '!');   // 0x21
    CHECK_EQ(rows[2].ascii[2], '"');   // 0x22

    const std::vector<typemorph::tui::HexRow> all = hex.visible_rows(8);
    REQUIRE(all.size() == 5);
    CHECK_EQ(all.back().offset, std::uint64_t{64});
    CHECK_EQ(all.back().length, std::size_t{6});
    CHECK_EQ(all.back().bytes[5], std::uint8_t{69});
}

TEST_CASE("tui.hex.empty_and_short_views_are_bounds_safe") {
    typemorph::tui::HexComponent empty(make_view({}, "empty.bin"));
    CHECK_EQ(empty.total_rows(), std::size_t{0});
    CHECK(empty.visible_rows(8).empty());
    empty.set_cursor(100);
    CHECK_EQ(empty.cursor_offset(), std::uint64_t{0});
    empty.move_cursor(-50);
    empty.scroll_rows(10);
    empty.scroll_to(999);
    CHECK_EQ(empty.top_offset(), std::uint64_t{0});
    empty.set_selection(0, 32);
    CHECK(!empty.has_selection());

    typemorph::tui::HexComponent short_view(make_view(pattern_bytes(5), "short.bin"), 16);
    CHECK_EQ(short_view.total_rows(), std::size_t{1});
    const auto rows = short_view.visible_rows(4);
    REQUIRE(rows.size() == 1);
    CHECK_EQ(rows[0].length, std::size_t{5});
    CHECK_EQ(rows[0].bytes[5], std::uint8_t{0});
    CHECK_EQ(rows[0].bytes[15], std::uint8_t{0});

    // A request for zero rows never fabricates output.
    CHECK(short_view.visible_rows(0).empty());
}

TEST_CASE("tui.hex.cursor_scroll_page_and_clamp") {
    typemorph::tui::HexComponent hex(make_view(pattern_bytes(100), "scroll.bin"), 16);
    CHECK_EQ(hex.total_rows(), std::size_t{7});

    hex.set_cursor(1000);
    CHECK_EQ(hex.cursor_offset(), std::uint64_t{99});
    hex.set_cursor(20);
    hex.move_cursor(-1000);
    CHECK_EQ(hex.cursor_offset(), std::uint64_t{0});
    hex.move_cursor(1000);
    CHECK_EQ(hex.cursor_offset(), std::uint64_t{99});

    hex.scroll_rows(2);
    CHECK_EQ(hex.top_offset(), std::uint64_t{32});
    hex.scroll_rows(-1000);
    CHECK_EQ(hex.top_offset(), std::uint64_t{0});
    hex.scroll_rows(1000);
    CHECK_EQ(hex.top_offset(), std::uint64_t{96});  // last row of 7

    hex.page(1, 3);
    CHECK_EQ(hex.top_offset(), std::uint64_t{96});
    hex.page(-1, 3);
    CHECK_EQ(hex.top_offset(), std::uint64_t{48});
    hex.page(-1000, 3);
    CHECK_EQ(hex.top_offset(), std::uint64_t{0});
    hex.page(1000, 3);
    CHECK_EQ(hex.top_offset(), std::uint64_t{96});

    hex.scroll_to(50);
    CHECK_EQ(hex.top_offset(), std::uint64_t{48});  // row aligned
    hex.set_cursor(0);
    CHECK_EQ(hex.cursor_offset(), std::uint64_t{0});
    CHECK_EQ(hex.top_offset(), std::uint64_t{0});  // follows the cursor back
}

TEST_CASE("tui.hex.selection_mapping_and_eof_clamping") {
    typemorph::tui::HexComponent hex(make_view(pattern_bytes(100), "select.bin"), 16);

    hex.set_selection(5, 20);
    CHECK(hex.has_selection());
    CHECK_EQ(hex.selection_offset(), std::uint64_t{5});
    CHECK_EQ(hex.selection_length(), std::uint64_t{20});

    hex.scroll_to(0);
    const auto rows = hex.visible_rows(5);
    REQUIRE(rows.size() >= 3);
    CHECK(rows[0].selected[5]);
    CHECK(rows[0].selected[15]);
    CHECK(!rows[0].selected[4]);
    CHECK(rows[0].row_selected);
    CHECK(rows[1].selected[0]);   // absolute 16
    CHECK(rows[1].selected[8]);   // absolute 24
    CHECK(!rows[1].selected[9]);  // absolute 25 outside [5, 25)
    CHECK(rows[1].row_selected);
    CHECK(!rows[2].row_selected);

    // Selection extending past EOF is clipped, not rejected.
    hex.set_selection(95, 100);
    CHECK(hex.has_selection());
    CHECK_EQ(hex.selection_offset(), std::uint64_t{95});
    CHECK_EQ(hex.selection_length(), std::uint64_t{5});

    // Selection starting past EOF degrades to no selection.
    hex.set_selection(200, 5);
    CHECK(!hex.has_selection());
    hex.set_selection(99, 0);
    CHECK(!hex.has_selection());

    hex.set_selection(0, 4);
    hex.clear_selection();
    CHECK(!hex.has_selection());
}

TEST_CASE("tui.hex.entropy_heat_map_tracks_information_density") {
    std::vector<std::uint8_t> bytes(64, 0x00);
    for (std::size_t i = 0; i < 256; ++i) {
        bytes.push_back(static_cast<std::uint8_t>(i));
    }
    typemorph::tui::HexComponent hex(make_view(std::move(bytes), "entropy.bin"), 16);
    const auto rows = hex.visible_rows(20);
    REQUIRE(rows.size() == 20);

    // Row 0 covers 64 zero bytes: zero entropy, zero intensity.
    CHECK_EQ(rows[0].intensity[0], std::uint8_t{0});
    // Row 4 starts inside the high-entropy region and must be brighter.
    CHECK(rows[4].intensity[0] > rows[0].intensity[0]);
    CHECK(rows[4].intensity[0] > 0);

    // Selection never leaks into the entropy computation: it is an overlay.
    hex.set_selection(0, 16);
    const auto selected_rows = hex.visible_rows(2);
    REQUIRE(selected_rows.size() == 2);
    CHECK(selected_rows[0].row_selected);
    CHECK(selected_rows[0].selected[0]);
}

// ---------------------------------------------------------------------------
// AstComponent
// ---------------------------------------------------------------------------

TEST_CASE("tui.ast.flatten_expand_and_selection") {
    TypePtr root = make_test_tree();
    typemorph::tui::AstComponent ast(root);

    REQUIRE(ast.rows().size() == 3);  // root + magic + collapsed Pair
    CHECK_EQ(ast.rows()[0].depth, 0);
    CHECK_EQ(ast.rows()[0].label, std::string("Root"));
    CHECK(ast.rows()[0].expanded);
    CHECK(ast.rows()[0].has_children);
    CHECK_EQ(ast.rows()[1].label, std::string("magic"));
    CHECK_EQ(ast.rows()[1].type_name, std::string("u32"));
    CHECK(!ast.rows()[1].has_children);
    CHECK_EQ(ast.rows()[2].label, std::string("Pair"));
    CHECK_EQ(ast.rows()[2].type_name, std::string("struct"));
    CHECK_EQ(ast.rows()[2].offset, std::uint64_t{4});  // absolute
    CHECK_EQ(ast.rows()[2].size, std::uint64_t{4});
    CHECK(ast.rows()[2].has_children);
    CHECK(!ast.rows()[2].expanded);
    CHECK_NEAR(ast.rows()[2].confidence, 0.90, 1e-9);

    CHECK_EQ(ast.selected_row(), std::size_t{0});
    REQUIRE(ast.selected_node() != nullptr);
    CHECK_EQ(ast.selected_node()->name, std::string("Root"));
    CHECK_EQ(ast.selected_offset(), std::uint64_t{0});
    CHECK_EQ(ast.selected_size(), std::uint64_t{8});

    ast.toggle(2);
    REQUIRE(ast.rows().size() == 5);
    CHECK(ast.rows()[2].expanded);
    CHECK_EQ(ast.rows()[3].label, std::string("x"));
    CHECK_EQ(ast.rows()[3].offset, std::uint64_t{4});
    CHECK_EQ(ast.rows()[3].size, std::uint64_t{2});
    CHECK_EQ(ast.rows()[4].label, std::string("y"));
    CHECK_EQ(ast.rows()[4].offset, std::uint64_t{6});
    CHECK_NEAR(ast.rows()[3].confidence, 0.80, 1e-9);

    ast.collapse_all();
    CHECK_EQ(ast.rows().size(), std::size_t{1});
    ast.expand_all();
    CHECK_EQ(ast.rows().size(), std::size_t{5});
    ast.collapse_all();
    CHECK_EQ(ast.rows().size(), std::size_t{1});

    ast.move_selection(5);
    CHECK_EQ(ast.selected_row(), std::size_t{0});
    ast.move_selection(-5);
    CHECK_EQ(ast.selected_row(), std::size_t{0});
}

TEST_CASE("tui.ast.select_offset_reveals_hidden_nodes") {
    TypePtr root = make_test_tree();
    typemorph::tui::AstComponent ast(root);
    ast.collapse_all();
    CHECK_EQ(ast.rows().size(), std::size_t{1});

    ast.select_offset(6);  // inside y
    CHECK_EQ(ast.rows().size(), std::size_t{5});
    CHECK_EQ(ast.selected_offset(), std::uint64_t{6});
    CHECK_EQ(ast.selected_size(), std::uint64_t{2});
    REQUIRE(ast.selected_node() != nullptr);
    CHECK_EQ(ast.selected_node()->name, std::string("y"));

    ast.select_offset(4);  // most specific node containing 4 is x
    CHECK_EQ(ast.selected_offset(), std::uint64_t{4});
    CHECK_EQ(ast.selected_size(), std::uint64_t{2});
    REQUIRE(ast.selected_node() != nullptr);
    CHECK_EQ(ast.selected_node()->name, std::string("x"));

    // No node contains this offset: selection is unchanged and no crash.
    const std::uint64_t before = ast.selected_offset();
    ast.select_offset(0xFFFFFFFFULL);
    CHECK_EQ(ast.selected_offset(), before);
}

TEST_CASE("tui.ast.selection_survives_rebuild_without_dangling") {
    TypePtr root = make_test_tree();
    typemorph::tui::AstComponent ast(root);
    ast.expand_all();
    ast.select_row(4);  // y

    const TypeNode* before = ast.selected_node();
    REQUIRE(before != nullptr);
    CHECK_EQ(before->name, std::string("y"));

    ast.rebuild();
    const TypeNode* after = ast.selected_node();
    REQUIRE(after != nullptr);
    CHECK(before == after);
    CHECK_EQ(ast.selected_offset(), std::uint64_t{6});

    // Collapsing an ancestor moves the selection to the nearest visible ancestor
    // instead of leaving a dangling row index.
    ast.collapse_all();
    const TypeNode* collapsed_selection = ast.selected_node();
    REQUIRE(collapsed_selection != nullptr);
    CHECK_EQ(collapsed_selection->name, std::string("Root"));

    // Dropping the caller's handle must be safe: the component owns the root.
    ast.set_root(nullptr);
    CHECK(ast.rows().empty());
    CHECK(ast.selected_node() == nullptr);
    CHECK_EQ(ast.selected_offset(), std::uint64_t{0});
    CHECK_EQ(ast.selected_size(), std::uint64_t{0});
    ast.toggle(0);
    ast.move_selection(3);
    ast.select_row(10);
    ast.select_offset(0);
}

TEST_CASE("tui.ast.default_component_is_empty") {
    typemorph::tui::AstComponent ast;
    CHECK(ast.rows().empty());
    CHECK(ast.selected_node() == nullptr);
    CHECK_EQ(ast.selected_offset(), std::uint64_t{0});
    ast.expand_all();
    ast.collapse_all();
    CHECK(ast.rows().empty());

    ast.set_root(make_test_tree());
    CHECK_EQ(ast.rows().size(), std::size_t{3});
}

// ---------------------------------------------------------------------------
// EmitterComponent
// ---------------------------------------------------------------------------

TEST_CASE("tui.emitter.line_splitting_and_scrolling") {
    typemorph::tui::EmitterComponent preview;
    CHECK_EQ(preview.language(), std::string("kaitai"));

    std::string text;
    for (int i = 0; i < 50; ++i) text += "line " + std::to_string(i) + "\n";
    preview.set_text(text);
    CHECK_EQ(preview.text(), text);
    CHECK_EQ(preview.top_line(), std::int64_t{0});

    std::vector<std::string> visible = preview.visible_lines(5, 80);
    REQUIRE(visible.size() == 5);
    CHECK_EQ(visible[0], std::string("line 0"));
    CHECK_EQ(visible[4], std::string("line 4"));

    preview.scroll(10);
    CHECK_EQ(preview.top_line(), std::int64_t{10});
    visible = preview.visible_lines(1, 80);
    REQUIRE(visible.size() == 1);
    CHECK_EQ(visible[0], std::string("line 10"));

    preview.page(2, 5);
    CHECK_EQ(preview.top_line(), std::int64_t{20});
    preview.page(-1, 5);
    CHECK_EQ(preview.top_line(), std::int64_t{15});
    preview.scroll_to(1000);
    CHECK_EQ(preview.top_line(), std::int64_t{49});
    preview.scroll(1000);
    CHECK_EQ(preview.top_line(), std::int64_t{49});
    preview.scroll(-1000);
    CHECK_EQ(preview.top_line(), std::int64_t{0});

    preview.scroll_to(7);
    preview.set_text("fresh\n");
    CHECK_EQ(preview.top_line(), std::int64_t{0});
}

TEST_CASE("tui.emitter.width_clipping_and_utf8") {
    typemorph::tui::EmitterComponent preview;
    preview.set_text("0123456789\nshort\n\ttabbed\n");
    std::vector<std::string> visible = preview.visible_lines(4, 4);
    REQUIRE(visible.size() == 4);
    CHECK_EQ(visible[0], std::string("0123"));
    CHECK_EQ(visible[1], std::string("shor"));
    CHECK_EQ(visible[2], std::string("    "));  // tab expanded to a 4-column stop
    CHECK_EQ(visible[3], std::string(""));

    // Multi-byte sequences are never split; each code point is one column.
    preview.set_text("\xC3\xA9\xC3\xA9\xC3\xA9\n");
    visible = preview.visible_lines(1, 2);
    REQUIRE(visible.size() == 1);
    CHECK_EQ(visible[0], std::string("\xC3\xA9\xC3\xA9"));
    CHECK_EQ(visible[0].size(), std::size_t{4});
    CHECK(is_valid_utf8(visible[0]));

    visible = preview.visible_lines(2, 0);
    REQUIRE(visible.size() == 2);
    CHECK(visible[0].empty());
    CHECK(visible[1].empty());

    preview.set_text("");
    visible = preview.visible_lines(3, 10);
    REQUIRE(visible.size() == 3);
    CHECK(visible[0].empty());
    CHECK(visible[1].empty());
    CHECK(visible[2].empty());
    CHECK(preview.visible_lines(0, 10).empty());

    preview.set_active_language("cpp");
    CHECK_EQ(preview.language(), std::string("cpp"));
}

// ---------------------------------------------------------------------------
// Dashboard rendering
// ---------------------------------------------------------------------------

TEST_CASE("tui.dashboard.render_frame_100x30_has_three_panels") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());

    const std::string frame = dashboard.render_frame(100, 30, 0);
    CHECK(!frame.empty());
    CHECK(frame.find("TypeMorph") != std::string::npos);
    CHECK(frame.find("sample.bin") != std::string::npos);
    CHECK(frame.find("testfmt") != std::string::npos);
    CHECK(frame.find("Hex + Entropy") != std::string::npos);
    CHECK(frame.find("AST Tree") != std::string::npos);
    CHECK(frame.find("Kaitai Preview") != std::string::npos);
    CHECK(frame.find("Keyboard shortcuts") == std::string::npos);

    CHECK_EQ(count_lines(frame), std::size_t{30});
    for (const std::string& line : split_lines(frame)) {
        CHECK(line.size() <= 100);
        CHECK(line.find('\x1b') == std::string::npos);  // colour disabled
    }

    // Deterministic: identical inputs produce identical output.
    CHECK_EQ(frame, dashboard.render_frame(100, 30, 0));
}

TEST_CASE("tui.dashboard.panel_focus_and_switching") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());

    CHECK_EQ(dashboard.active_panel(), 0);
    CHECK(dashboard.render_frame(100, 30, 0).find("Hex + Entropy *") !=
          std::string::npos);

    CHECK(dashboard.handle_key('\t'));
    CHECK_EQ(dashboard.active_panel(), 1);
    CHECK(dashboard.render_frame(100, 30, 1).find("AST Tree (3) *") !=
          std::string::npos);

    CHECK(dashboard.handle_key('\t'));
    CHECK_EQ(dashboard.active_panel(), 2);
    CHECK(dashboard.render_frame(100, 30, 2).find("Kaitai Preview *") !=
          std::string::npos);

    CHECK(dashboard.handle_key('\t'));
    CHECK_EQ(dashboard.active_panel(), 0);

    // e / K select the preview source and focus the preview pane.
    CHECK(dashboard.handle_key('e'));
    CHECK_EQ(dashboard.active_panel(), 2);
    CHECK_EQ(dashboard.preview().language(), std::string("kaitai"));
    CHECK_EQ(dashboard.preview().text(), fixture.kaitai_text);

    CHECK(dashboard.handle_key('K'));
    CHECK_EQ(dashboard.active_panel(), 2);
    CHECK_EQ(dashboard.preview().language(), std::string("cpp"));
    CHECK_EQ(dashboard.preview().text(), fixture.cpp_text);
    CHECK(dashboard.render_frame(100, 30, 2).find("C++ Preview *") !=
          std::string::npos);
}

TEST_CASE("tui.dashboard.hex_navigation_and_offset_selection") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());

    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{0});
    CHECK(dashboard.handle_key(typemorph::tui::key_down));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{16});
    CHECK(dashboard.handle_key(typemorph::tui::key_right));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{17});
    CHECK(dashboard.handle_key(typemorph::tui::key_left));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{16});
    CHECK(dashboard.handle_key(typemorph::tui::key_up));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{0});

    (void)dashboard.render_frame(100, 30, 0);  // publish real panel geometry
    CHECK(dashboard.handle_key(typemorph::tui::key_page_down));
    CHECK(dashboard.hex().cursor_offset() > 0);
    CHECK(dashboard.hex().top_offset() > 0);

    CHECK(dashboard.handle_key(typemorph::tui::key_home));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{0});
    CHECK_EQ(dashboard.hex().top_offset(), std::uint64_t{0});
    CHECK(dashboard.handle_key(typemorph::tui::key_end));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{63});

    // Enter on the hex pane jumps the AST selection to the node at the cursor.
    dashboard.handle_key(typemorph::tui::key_home);
    CHECK(!dashboard.hex().has_selection());
    CHECK(dashboard.handle_key('\r'));
    REQUIRE(dashboard.ast().selected_node() != nullptr);
    CHECK_EQ(dashboard.ast().selected_node()->name, std::string("magic"));
    CHECK(dashboard.hex().has_selection());
    CHECK_EQ(dashboard.hex().selection_offset(), std::uint64_t{0});
    CHECK_EQ(dashboard.hex().selection_length(), std::uint64_t{4});
}

TEST_CASE("tui.dashboard.ast_toggle_and_navigation") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());

    CHECK(dashboard.handle_key('\t'));  // focus AST
    CHECK_EQ(dashboard.ast().rows().size(), std::size_t{3});

    CHECK(dashboard.handle_key('\r'));  // collapse Root
    CHECK_EQ(dashboard.ast().rows().size(), std::size_t{1});
    CHECK(dashboard.handle_key('\r'));  // expand Root again
    CHECK_EQ(dashboard.ast().rows().size(), std::size_t{3});

    CHECK(dashboard.handle_key(typemorph::tui::key_down));
    CHECK_EQ(dashboard.ast().selected_row(), std::size_t{1});
    CHECK(dashboard.handle_key(typemorph::tui::key_down));
    CHECK_EQ(dashboard.ast().selected_row(), std::size_t{2});
    CHECK_EQ(dashboard.ast().selected_node()->name, std::string("Pair"));

    CHECK(dashboard.handle_key(typemorph::tui::key_right));  // expand Pair
    CHECK_EQ(dashboard.ast().rows().size(), std::size_t{5});
    CHECK(dashboard.handle_key(typemorph::tui::key_down));
    CHECK_EQ(dashboard.ast().selected_node()->name, std::string("x"));

    CHECK(dashboard.handle_key(typemorph::tui::key_left));  // collapse Pair
    CHECK_EQ(dashboard.ast().rows().size(), std::size_t{3});
    CHECK(dashboard.handle_key(typemorph::tui::key_home));
    CHECK_EQ(dashboard.ast().selected_row(), std::size_t{0});
    CHECK(dashboard.handle_key(typemorph::tui::key_end));
    CHECK_EQ(dashboard.ast().selected_row(), std::size_t{2});
}

TEST_CASE("tui.dashboard.preview_scrolling_keys") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());
    CHECK(dashboard.handle_key('K'));  // C++ preview has four lines
    CHECK_EQ(dashboard.preview().top_line(), std::int64_t{0});

    (void)dashboard.render_frame(100, 30, 2);
    CHECK(dashboard.handle_key(typemorph::tui::key_down));
    CHECK_EQ(dashboard.preview().top_line(), std::int64_t{1});
    CHECK(dashboard.handle_key(typemorph::tui::key_up));
    CHECK_EQ(dashboard.preview().top_line(), std::int64_t{0});
    CHECK(dashboard.handle_key(typemorph::tui::key_end));
    CHECK_EQ(dashboard.preview().top_line(), std::int64_t{3});
    CHECK(dashboard.handle_key(typemorph::tui::key_home));
    CHECK_EQ(dashboard.preview().top_line(), std::int64_t{0});
}

TEST_CASE("tui.dashboard.tiny_terminals_and_help_overlay") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());

    CHECK(dashboard.render_frame(0, 30, 0).empty());
    CHECK(dashboard.render_frame(100, 0, 0).empty());

    const std::string one_by_one = dashboard.render_frame(1, 1, 0);
    CHECK(!one_by_one.empty());
    CHECK_EQ(count_lines(one_by_one), std::size_t{1});

    const std::string narrow = dashboard.render_frame(20, 5, 0);
    CHECK(!narrow.empty());
    CHECK_EQ(count_lines(narrow), std::size_t{5});
    for (const std::string& line : split_lines(narrow)) CHECK(line.size() <= 20);

    const std::string medium = dashboard.render_frame(40, 8, 0);
    CHECK_EQ(count_lines(medium), std::size_t{8});
    CHECK(medium.find("Hex + Entropy") != std::string::npos);

    const std::string wide = dashboard.render_frame(180, 40, 0);
    CHECK_EQ(count_lines(wide), std::size_t{40});
    CHECK(wide.find("Hex + Entropy") != std::string::npos);
    CHECK(wide.find("AST Tree") != std::string::npos);
    CHECK(wide.find("Kaitai Preview") != std::string::npos);

    CHECK(dashboard.handle_key('?'));
    const std::string help = dashboard.render_frame(100, 30, 0);
    CHECK(help.find("Help") != std::string::npos);
    CHECK(help.find("Keyboard shortcuts") != std::string::npos);
    CHECK_EQ(count_lines(help), std::size_t{30});

    // Any key dismisses the overlay; '?' toggles it explicitly.
    CHECK(dashboard.handle_key('x'));
    CHECK(dashboard.render_frame(100, 30, 0).find("Keyboard shortcuts") ==
          std::string::npos);
    CHECK(dashboard.handle_key('?'));
    CHECK(dashboard.render_frame(100, 30, 0).find("Keyboard shortcuts") !=
          std::string::npos);
    CHECK(dashboard.handle_key('?'));
    CHECK(dashboard.render_frame(100, 30, 0).find("Keyboard shortcuts") ==
          std::string::npos);
    CHECK_EQ(count_lines(dashboard.render_frame(8, 3, 0)), std::size_t{3});
}

TEST_CASE("tui.dashboard.quit_keys") {
    DashboardFixture fixture = make_dashboard_fixture();
    {
        typemorph::tui::Dashboard dashboard(fixture.model, plain_options());
        CHECK(dashboard.handle_key('e'));  // non-quit still returns true
        CHECK(!dashboard.handle_key('q'));
    }
    {
        typemorph::tui::Dashboard dashboard(fixture.model, plain_options());
        CHECK(!dashboard.handle_key(typemorph::tui::key_escape));
    }
    {
        typemorph::tui::Dashboard dashboard(fixture.model, plain_options());
        CHECK(!dashboard.handle_key(3));  // Ctrl-C
    }
}

TEST_CASE("tui.dashboard.colour_output_is_deterministic") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::DashboardOptions options;
    options.color = true;
    typemorph::tui::Dashboard dashboard(fixture.model, options);

    const std::string coloured = dashboard.render_frame(100, 30, 0);
    CHECK(!coloured.empty());
    CHECK(coloured.find("\x1b[") != std::string::npos);
    CHECK_EQ(coloured, dashboard.render_frame(100, 30, 0));
    CHECK_EQ(count_lines(coloured), std::size_t{30});
}

TEST_CASE("tui.dashboard.navigation_jump_and_save") {
    DashboardFixture fixture = make_dashboard_fixture();
    typemorph::tui::Dashboard dashboard(fixture.model, plain_options());

    // jump_to method
    dashboard.jump_to(20);
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{20});

    // 'g' key jumps to 0
    CHECK(dashboard.handle_key('g'));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{0});

    // 'G' key jumps to end (64 bytes in fixture -> index 63)
    CHECK(dashboard.handle_key('G'));
    CHECK_EQ(dashboard.hex().cursor_offset(), std::uint64_t{63});

    // 's' and 'w' key saves active preview
    const auto save_path = std::filesystem::current_path() / "test_preview_save.ksy";
    CHECK(dashboard.save_active_preview(save_path.string()));
    REQUIRE(std::filesystem::exists(save_path));
    std::filesystem::remove(save_path);

    // key 's' with default path
    CHECK(dashboard.handle_key('s'));
    const auto default_path = std::filesystem::current_path() / "sample.ksy";
    if (std::filesystem::exists(default_path)) {
        std::filesystem::remove(default_path);
    }
}


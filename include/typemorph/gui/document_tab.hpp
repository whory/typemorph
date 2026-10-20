// TypeMorph - Native C++ port of dnSpy Tabs Architecture (TabGroup.cs, TabItemImpl.cs, ITabContent.cs)
#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace typemorph::gui {

// Colors matching dnSpy Dark Theme (ThemeService / dark.dntheme)
namespace theme {
    constexpr COLORREF kClrTabBackground      = RGB(45, 45, 48);     // #2D2D30
    constexpr COLORREF kClrTabSelectedBg      = RGB(30, 30, 30);     // #1E1E1E
    constexpr COLORREF kClrTabHoverBg         = RGB(62, 62, 64);     // #3E3E40
    constexpr COLORREF kClrTabText            = RGB(241, 241, 241);  // #F1F1F1
    constexpr COLORREF kClrTabTextInactive    = RGB(150, 150, 150);  // #969696
    constexpr COLORREF kClrTabBorder          = RGB(63, 63, 70);     // #3F3F46
    constexpr COLORREF kClrTabSelectedBorder  = RGB(0, 122, 204);    // #007ACC (accent blue)
}

enum class TabVisibilityEvent {
    Added,
    Removed,
    Selected,
    Deselected
};

// C++ equivalent of dnSpy's ITabContent
class ITabContent {
public:
    virtual ~ITabContent() = default;
    [[nodiscard]] virtual std::string title() const = 0;
    [[nodiscard]] virtual std::string tooltip() const = 0;
    [[nodiscard]] virtual std::string content() const = 0;
    [[nodiscard]] virtual std::string language_id() const { return "csharp"; }
    virtual void on_visibility_changed(TabVisibilityEvent ev) { (void)ev; }
};

// Simple text/code tab content
class CodeDocumentTabContent : public ITabContent {
public:
    CodeDocumentTabContent(std::string title, std::string content, std::string lang = "csharp")
        : title_(std::move(title)), content_(std::move(content)), lang_(std::move(lang)) {}

    [[nodiscard]] std::string title() const override { return title_; }
    [[nodiscard]] std::string tooltip() const override { return title_ + " (" + lang_ + ")"; }
    [[nodiscard]] std::string content() const override { return content_; }
    [[nodiscard]] std::string language_id() const override { return lang_; }

    void set_content(std::string content) { content_ = std::move(content); }

private:
    std::string title_;
    std::string content_;
    std::string lang_;
};

// C++ Port of dnSpy TabItemImpl
struct TabItem {
    std::shared_ptr<ITabContent> content;
    RECT rect{};
    bool is_hovered = false;
    bool is_close_hovered = false;
};

// C++ Port of dnSpy TabGroup and TabControl
class DocumentTabGroup {
public:
    DocumentTabGroup() = default;
    ~DocumentTabGroup() {
        if (font_) DeleteObject(font_);
    }

    void initialize(HWND hwnd_parent, int id);
    void set_bounds(int x, int y, int width, int height);

    int add_tab(std::shared_ptr<ITabContent> tab, bool select = true);
    void close_tab(int index);
    void select_tab(int index);

    [[nodiscard]] int active_tab_index() const { return active_index_; }
    [[nodiscard]] std::shared_ptr<ITabContent> active_tab() const;
    [[nodiscard]] std::size_t count() const { return tabs_.size(); }

    void on_paint(HDC hdc);
    void on_mouse_move(int x, int y);
    void on_mouse_leave();
    bool on_lbutton_down(int x, int y);

    using SelectionChangedHandler = std::function<void(std::shared_ptr<ITabContent>)>;
    void set_on_selection_changed(SelectionChangedHandler handler) {
        on_selection_changed_ = std::move(handler);
    }

private:
    void recalculate_tab_rects();

    HWND hwnd_parent_ = nullptr;
    int id_ = 0;
    RECT bounds_{0, 0, 0, 0};
    HFONT font_ = nullptr;

    std::vector<TabItem> tabs_;
    int active_index_ = -1;
    SelectionChangedHandler on_selection_changed_;
};

} // namespace typemorph::gui
#endif // _WIN32

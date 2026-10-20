// TypeMorph - Implementation of native C++ dnSpy Document Tabs
#ifdef _WIN32

#include "typemorph/gui/document_tab.hpp"
#include <algorithm>

namespace typemorph::gui {

void DocumentTabGroup::initialize(HWND hwnd_parent, int id) {
    hwnd_parent_ = hwnd_parent;
    id_ = id;
    font_ = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
}

void DocumentTabGroup::set_bounds(int x, int y, int width, int height) {
    bounds_ = {x, y, x + width, y + height};
    recalculate_tab_rects();
}

int DocumentTabGroup::add_tab(std::shared_ptr<ITabContent> tab, bool select) {
    if (!tab) return -1;

    // If tab already exists, activate it
    for (std::size_t i = 0; i < tabs_.size(); ++i) {
        if (tabs_[i].content->title() == tab->title()) {
            if (select) select_tab(static_cast<int>(i));
            return static_cast<int>(i);
        }
    }

    TabItem item;
    item.content = tab;
    item.content->on_visibility_changed(TabVisibilityEvent::Added);
    tabs_.push_back(std::move(item));

    recalculate_tab_rects();

    int new_idx = static_cast<int>(tabs_.size()) - 1;
    if (select || active_index_ == -1) {
        select_tab(new_idx);
    }
    return new_idx;
}

void DocumentTabGroup::close_tab(int index) {
    if (index < 0 || index >= static_cast<int>(tabs_.size())) return;

    tabs_[index].content->on_visibility_changed(TabVisibilityEvent::Removed);
    tabs_.erase(tabs_.begin() + index);

    if (tabs_.empty()) {
        active_index_ = -1;
        if (on_selection_changed_) on_selection_changed_(nullptr);
    } else {
        if (active_index_ >= static_cast<int>(tabs_.size())) {
            active_index_ = static_cast<int>(tabs_.size()) - 1;
        }
        select_tab(active_index_);
    }

    recalculate_tab_rects();
    if (hwnd_parent_) InvalidateRect(hwnd_parent_, &bounds_, FALSE);
}

void DocumentTabGroup::select_tab(int index) {
    if (index < 0 || index >= static_cast<int>(tabs_.size())) return;

    if (active_index_ >= 0 && active_index_ < static_cast<int>(tabs_.size())) {
        tabs_[active_index_].content->on_visibility_changed(TabVisibilityEvent::Deselected);
    }

    active_index_ = index;
    tabs_[active_index_].content->on_visibility_changed(TabVisibilityEvent::Selected);

    if (on_selection_changed_) {
        on_selection_changed_(tabs_[active_index_].content);
    }

    if (hwnd_parent_) InvalidateRect(hwnd_parent_, &bounds_, FALSE);
}

std::shared_ptr<ITabContent> DocumentTabGroup::active_tab() const {
    if (active_index_ >= 0 && active_index_ < static_cast<int>(tabs_.size())) {
        return tabs_[active_index_].content;
    }
    return nullptr;
}

void DocumentTabGroup::recalculate_tab_rects() {
    int cur_x = bounds_.left + 4;
    int tab_h = bounds_.bottom - bounds_.top;
    if (tab_h <= 0) tab_h = 26;

    for (auto& tab : tabs_) {
        int title_len = static_cast<int>(tab.content->title().length());
        int tab_w = std::clamp(title_len * 8 + 36, 90, 220);

        tab.rect = {cur_x, bounds_.top, cur_x + tab_w, bounds_.bottom};
        cur_x += tab_w + 2;
    }
}

void DocumentTabGroup::on_paint(HDC hdc) {
    if (bounds_.bottom <= bounds_.top || bounds_.right <= bounds_.left) return;

    // Fill tab strip background (dnSpy header color #2D2D30)
    HBRUSH bg_brush = CreateSolidBrush(theme::kClrTabBackground);
    FillRect(hdc, &bounds_, bg_brush);
    DeleteObject(bg_brush);

    // Bottom border line
    HPEN border_pen = CreatePen(PS_SOLID, 1, theme::kClrTabBorder);
    HGDIOBJ old_pen = SelectObject(hdc, border_pen);
    MoveToEx(hdc, bounds_.left, bounds_.bottom - 1, nullptr);
    LineTo(hdc, bounds_.right, bounds_.bottom - 1);
    SelectObject(hdc, old_pen);
    DeleteObject(border_pen);

    HGDIOBJ old_font = SelectObject(hdc, font_);
    SetBkMode(hdc, TRANSPARENT);

    for (std::size_t i = 0; i < tabs_.size(); ++i) {
        const auto& tab = tabs_[i];
        bool is_active = (static_cast<int>(i) == active_index_);

        COLORREF tab_bg = is_active ? theme::kClrTabSelectedBg :
                          (tab.is_hovered ? theme::kClrTabHoverBg : theme::kClrTabBackground);

        HBRUSH item_brush = CreateSolidBrush(tab_bg);
        FillRect(hdc, &tab.rect, item_brush);
        DeleteObject(item_brush);

        // Active top indicator (dnSpy Blue Accent #007ACC)
        if (is_active) {
            RECT top_accent = {tab.rect.left, tab.rect.top, tab.rect.right, tab.rect.top + 2};
            HBRUSH accent_brush = CreateSolidBrush(theme::kClrTabSelectedBorder);
            FillRect(hdc, &top_accent, accent_brush);
            DeleteObject(accent_brush);
        }

        // Side separator
        HPEN sep_pen = CreatePen(PS_SOLID, 1, theme::kClrTabBorder);
        old_pen = SelectObject(hdc, sep_pen);
        MoveToEx(hdc, tab.rect.right - 1, tab.rect.top + 4, nullptr);
        LineTo(hdc, tab.rect.right - 1, tab.rect.bottom - 4);
        SelectObject(hdc, old_pen);
        DeleteObject(sep_pen);

        // Tab Title Text
        SetTextColor(hdc, is_active ? theme::kClrTabText : theme::kClrTabTextInactive);
        RECT text_rc = tab.rect;
        text_rc.left += 10;
        text_rc.right -= 22; // room for close 'x'

        std::string title = tab.content->title();
        int wide_len = MultiByteToWideChar(CP_UTF8, 0, title.c_str(), -1, nullptr, 0);
        std::wstring wtitle(wide_len, 0);
        MultiByteToWideChar(CP_UTF8, 0, title.c_str(), -1, &wtitle[0], wide_len);

        DrawTextW(hdc, wtitle.c_str(), -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        // Close 'x' button
        RECT close_rc = {tab.rect.right - 20, tab.rect.top + 5, tab.rect.right - 4, tab.rect.bottom - 5};
        SetTextColor(hdc, tab.is_close_hovered ? RGB(255, 100, 100) : theme::kClrTabTextInactive);
        DrawTextW(hdc, L"✕", -1, &close_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    SelectObject(hdc, old_font);
}

void DocumentTabGroup::on_mouse_move(int x, int y) {
    bool need_redraw = false;
    for (auto& tab : tabs_) {
        bool now_hovered = (x >= tab.rect.left && x <= tab.rect.right &&
                            y >= tab.rect.top && y <= tab.rect.bottom);

        RECT close_rc = {tab.rect.right - 20, tab.rect.top + 5, tab.rect.right - 4, tab.rect.bottom - 5};
        bool now_close_hovered = (x >= close_rc.left && x <= close_rc.right &&
                                  y >= close_rc.top && y <= close_rc.bottom);

        if (tab.is_hovered != now_hovered || tab.is_close_hovered != now_close_hovered) {
            tab.is_hovered = now_hovered;
            tab.is_close_hovered = now_close_hovered;
            need_redraw = true;
        }
    }

    if (need_redraw && hwnd_parent_) {
        InvalidateRect(hwnd_parent_, &bounds_, FALSE);
    }
}

void DocumentTabGroup::on_mouse_leave() {
    bool need_redraw = false;
    for (auto& tab : tabs_) {
        if (tab.is_hovered || tab.is_close_hovered) {
            tab.is_hovered = false;
            tab.is_close_hovered = false;
            need_redraw = true;
        }
    }
    if (need_redraw && hwnd_parent_) {
        InvalidateRect(hwnd_parent_, &bounds_, FALSE);
    }
}

bool DocumentTabGroup::on_lbutton_down(int x, int y) {
    if (y < bounds_.top || y > bounds_.bottom) return false;

    for (std::size_t i = 0; i < tabs_.size(); ++i) {
        const auto& tab = tabs_[i];
        if (x >= tab.rect.left && x <= tab.rect.right) {
            RECT close_rc = {tab.rect.right - 20, tab.rect.top + 5, tab.rect.right - 4, tab.rect.bottom - 5};
            if (x >= close_rc.left && x <= close_rc.right && y >= close_rc.top && y <= close_rc.bottom) {
                close_tab(static_cast<int>(i));
                return true;
            }
            select_tab(static_cast<int>(i));
            return true;
        }
    }
    return false;
}

} // namespace typemorph::gui
#endif // _WIN32

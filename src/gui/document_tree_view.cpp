// TypeMorph - Implementation of native C++ dnSpy DocumentTreeView
#ifdef _WIN32

#include "typemorph/gui/document_tree_view.hpp"
#include <map>

namespace typemorph::gui {

namespace {
    constexpr COLORREF kClrTreeDarkBg = RGB(37, 37, 38);      // #252526
    constexpr COLORREF kClrTreeText   = RGB(241, 241, 241);   // #F1F1F1
}

DocumentTreeView::~DocumentTreeView() {
    if (font_) {
        DeleteObject(font_);
        font_ = nullptr;
    }
    if (himl_) {
        ImageList_Destroy(himl_);
        himl_ = nullptr;
    }
}

void DocumentTreeView::create(HWND hwnd_parent, int id, RECT bounds) {
    hwnd_parent_ = hwnd_parent;
    id_ = id;

    hwnd_tree_ = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        hwnd_parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr), nullptr);

    font_ = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    SendMessageW(hwnd_tree_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    TreeView_SetBkColor(hwnd_tree_, kClrTreeDarkBg);
    TreeView_SetTextColor(hwnd_tree_, kClrTreeText);
}

void DocumentTreeView::set_bounds(int x, int y, int width, int height) {
    if (hwnd_tree_) {
        MoveWindow(hwnd_tree_, x, y, width, height, TRUE);
    }
}

void DocumentTreeView::clear() {
    if (hwnd_tree_) {
        TreeView_DeleteAllItems(hwnd_tree_);
    }
    node_registry_.clear();
    root_node_.reset();
}

void DocumentTreeView::set_root_node(std::shared_ptr<DocumentTreeNodeData> root) {
    clear();
    root_node_ = std::move(root);
    if (!root_node_ || !hwnd_tree_) return;

    SendMessageW(hwnd_tree_, WM_SETREDRAW, FALSE, 0);
    insert_node_recursive(TVI_ROOT, root_node_);
    SendMessageW(hwnd_tree_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hwnd_tree_, nullptr, TRUE);
}

void DocumentTreeView::insert_node_recursive(HTREEITEM h_parent, const std::shared_ptr<DocumentTreeNodeData>& node_data) {
    if (!node_data) return;

    node_registry_.push_back(node_data);
    auto* raw_ptr = node_data.get();

    std::string text_utf8 = node_data->text();
    int wide_sz = MultiByteToWideChar(CP_UTF8, 0, text_utf8.c_str(), -1, nullptr, 0);
    std::wstring wtext(wide_sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, text_utf8.c_str(), -1, &wtext[0], wide_sz);

    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = h_parent;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
    tvis.item.pszText = const_cast<LPWSTR>(wtext.c_str());
    tvis.item.lParam = reinterpret_cast<LPARAM>(raw_ptr);

    HTREEITEM h_cur = TreeView_InsertItem(hwnd_tree_, &tvis);

    for (const auto& child : node_data->children()) {
        insert_node_recursive(h_cur, child);
    }

    if (h_parent == TVI_ROOT) {
        TreeView_Expand(hwnd_tree_, h_cur, TVE_EXPAND);
    }
}

void DocumentTreeView::on_selection_changed(LPARAM lparam) {
    auto* pnmtv = reinterpret_cast<LPNMTREEVIEWW>(lparam);
    if (!pnmtv || pnmtv->itemNew.lParam == 0) return;

    auto* node_ptr = reinterpret_cast<DocumentTreeNodeData*>(pnmtv->itemNew.lParam);
    if (node_ptr && on_node_selected_) {
        for (const auto& n : node_registry_) {
            if (n.get() == node_ptr) {
                on_node_selected_(n);
                break;
            }
        }
    }
}

} // namespace typemorph::gui
#endif // _WIN32

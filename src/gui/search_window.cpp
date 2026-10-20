// TypeMorph - Implementation of native C++ dnSpy Search Window
#ifdef _WIN32

#include "typemorph/gui/search_window.hpp"
#include <algorithm>
#include <sstream>

namespace typemorph::gui {

namespace {
    constexpr int IDC_SEARCH_EDIT   = 3001;
    constexpr int IDC_SEARCH_FILTER = 3002;
    constexpr int IDC_SEARCH_LIST   = 3003;
    constexpr int IDC_SEARCH_STATUS = 3004;

    SearchWindow* g_active_search_window = nullptr;

    inline void EnableImmersiveDarkMode(HWND hwnd) {
        HMODULE hDwm = LoadLibraryA("dwmapi.dll");
        if (hDwm) {
            typedef HRESULT (WINAPI* pfnDwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);
            auto pDwmSet = reinterpret_cast<pfnDwmSetWindowAttribute>(GetProcAddress(hDwm, "DwmSetWindowAttribute"));
            if (pDwmSet) {
                BOOL darkMode = TRUE;
                if (FAILED(pDwmSet(hwnd, 20, &darkMode, sizeof(darkMode)))) {
                    pDwmSet(hwnd, 19, &darkMode, sizeof(darkMode));
                }
            }
            FreeLibrary(hDwm);
        }
    }
}

SearchWindow::~SearchWindow() {
    if (hwnd_dlg_) {
        DestroyWindow(hwnd_dlg_);
        hwnd_dlg_ = nullptr;
    }
}

LRESULT CALLBACK SearchWindow::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        EnableImmersiveDarkMode(hwnd);
        break;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);

        if (g_active_search_window) {
            MoveWindow(g_active_search_window->hwnd_query_, 10, 10, w - 170, 24, TRUE);
            MoveWindow(g_active_search_window->hwnd_filter_, w - 150, 10, 140, 24, TRUE);
            MoveWindow(g_active_search_window->hwnd_list_, 10, 42, w - 20, h - 72, TRUE);
            MoveWindow(g_active_search_window->hwnd_status_, 10, h - 24, w - 20, 20, TRUE);
        }
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);

        if (id == IDC_SEARCH_EDIT && code == EN_CHANGE) {
            if (g_active_search_window) {
                g_active_search_window->update_search();
            }
            return 0;
        }

        if (id == IDC_SEARCH_FILTER && code == CBN_SELCHANGE) {
            if (g_active_search_window) {
                g_active_search_window->update_search();
            }
            return 0;
        }

        if (id == IDC_SEARCH_LIST && code == LBN_DBLCLK) {
            if (g_active_search_window && g_active_search_window->hwnd_list_) {
                LRESULT cur = SendMessageW(g_active_search_window->hwnd_list_, LB_GETCURSEL, 0, 0);
                if (cur != LB_ERR && cur < static_cast<LRESULT>(g_active_search_window->current_results_.size())) {
                    if (g_active_search_window->on_navigate_) {
                        g_active_search_window->on_navigate_(g_active_search_window->current_results_[cur]);
                    }
                }
            }
            return 0;
        }
        break;
    }

    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        SetTextColor(hdc, RGB(241, 241, 241));
        SetBkColor(hdc, RGB(30, 30, 30));
        static HBRUSH hBrushDark = CreateSolidBrush(RGB(30, 30, 30));
        return reinterpret_cast<INT_PTR>(hBrushDark);
    }

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void SearchWindow::show(HWND hwnd_parent) {
    g_active_search_window = this;

    if (!hwnd_dlg_) {
        HINSTANCE hInst = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = DialogProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"TypeMorphSearchWindowClass";
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(RGB(45, 45, 48));
        RegisterClassExW(&wc);

        hwnd_dlg_ = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            L"TypeMorphSearchWindowClass",
            L"Search (Ctrl+F) - dnSpy Symbol & Metadata Search",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 700, 480,
            hwnd_parent, nullptr, hInst, nullptr);

        HFONT hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        hwnd_query_ = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            10, 10, 520, 24, hwnd_dlg_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SEARCH_EDIT)),
            hInst, nullptr);
        SendMessageW(hwnd_query_, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);

        hwnd_filter_ = CreateWindowExW(
            0, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            540, 10, 140, 200, hwnd_dlg_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SEARCH_FILTER)),
            hInst, nullptr);
        SendMessageW(hwnd_filter_, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);

        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"All Symbols"));
        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Types"));
        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Methods / Functions"));
        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Fields"));
        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Properties"));
        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Events"));
        SendMessageW(hwnd_filter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Strings"));
        SendMessageW(hwnd_filter_, CB_SETCURSEL, 0, 0);

        hwnd_list_ = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            10, 42, 670, 380, hwnd_dlg_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SEARCH_LIST)),
            hInst, nullptr);
        SendMessageW(hwnd_list_, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);

        hwnd_status_ = CreateWindowExW(
            0, L"STATIC", L"Ready. Type query to search across metadata and decompiled symbols.",
            WS_CHILD | WS_VISIBLE,
            10, 430, 670, 20, hwnd_dlg_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SEARCH_STATUS)),
            hInst, nullptr);
        SendMessageW(hwnd_status_, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
    }

    ShowWindow(hwnd_dlg_, SW_SHOW);
    SetFocus(hwnd_query_);
    update_search();
}

void SearchWindow::update_search() {
    if (!hwnd_query_ || !hwnd_list_) return;

    wchar_t buf[256] = L"";
    GetWindowTextW(hwnd_query_, buf, 256);
    char mb[256] = "";
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, mb, 256, nullptr, nullptr);
    std::string query = mb;

    LRESULT sel_filter = SendMessageW(hwnd_filter_, CB_GETCURSEL, 0, 0);
    SymbolSearchType filter_type = SymbolSearchType::All;
    switch (sel_filter) {
    case 1: filter_type = SymbolSearchType::Type; break;
    case 2: filter_type = SymbolSearchType::Method; break;
    case 3: filter_type = SymbolSearchType::Field; break;
    case 4: filter_type = SymbolSearchType::Property; break;
    case 5: filter_type = SymbolSearchType::Event; break;
    case 6: filter_type = SymbolSearchType::StringLiteral; break;
    default: filter_type = SymbolSearchType::All; break;
    }

    if (search_provider_) {
        current_results_ = search_provider_(query, filter_type);
    }

    SendMessageW(hwnd_list_, LB_RESETCONTENT, 0, 0);
    for (const auto& r : current_results_) {
        int wide_sz = MultiByteToWideChar(CP_UTF8, 0, r.display_text.c_str(), -1, nullptr, 0);
        std::wstring wdisp(wide_sz, 0);
        MultiByteToWideChar(CP_UTF8, 0, r.display_text.c_str(), -1, &wdisp[0], wide_sz);
        SendMessageW(hwnd_list_, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(wdisp.c_str()));
    }

    std::string status_str = "Found " + std::to_string(current_results_.size()) + " matches.";
    int s_wide = MultiByteToWideChar(CP_UTF8, 0, status_str.c_str(), -1, nullptr, 0);
    std::wstring wstat(s_wide, 0);
    MultiByteToWideChar(CP_UTF8, 0, status_str.c_str(), -1, &wstat[0], s_wide);
    SetWindowTextW(hwnd_status_, wstat.c_str());
}

} // namespace typemorph::gui
#endif // _WIN32

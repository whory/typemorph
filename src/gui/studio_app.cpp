// TypeMorph - Standalone Native Desktop GUI Application Implementation
#ifdef _WIN32

#include "typemorph/gui/studio_app.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/infer/diff_engine.hpp"
#include "typemorph/emitter/cpp_emitter.hpp"
#include "typemorph/emitter/rust_emitter.hpp"
#include "typemorph/emitter/kaitai_emitter.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")

namespace typemorph::gui {

namespace {

// Menu & Action IDs
constexpr int IDM_FILE_OPEN          = 1001;
constexpr int IDM_FILE_SAVE_AS       = 1000;
constexpr int IDM_FILE_EXIT          = 1002;
constexpr int IDM_ACTION_DEOBF       = 1003;
constexpr int IDM_ACTION_DETECT      = 1004;
constexpr int IDM_ACTION_VMPROFILE   = 1005;
constexpr int IDM_ACTION_UNPACK      = 1006;
constexpr int IDM_ACTION_VFS         = 1007;
constexpr int IDM_ACTION_IATFIX      = 1008;
constexpr int IDM_ACTION_MEMDUMP     = 1009;

// Forensic, Security, Crypto & Deobf Action IDs
constexpr int IDM_ACTION_STRINGS     = 1030;
constexpr int IDM_ACTION_CRYPTO      = 1031;
constexpr int IDM_ACTION_AES_RECOVER = 1032;
constexpr int IDM_ACTION_ENTROPY     = 1033;
constexpr int IDM_ACTION_CHECKSEC    = 1034;
constexpr int IDM_ACTION_RICH        = 1035;
constexpr int IDM_ACTION_ABI         = 1036;
constexpr int IDM_ACTION_UNXOR       = 1037;
constexpr int IDM_ACTION_APIHASH     = 1038;
constexpr int IDM_ACTION_OPAQUE      = 1039;
constexpr int IDM_ACTION_CFF         = 1040;
constexpr int IDM_ACTION_CLASSINFO   = 1041;
constexpr int IDM_ACTION_SIGMAKE     = 1042;
constexpr int IDM_ACTION_INFER       = 1043;
constexpr int IDM_ACTION_DUMPSUBS    = 1044;
constexpr int IDM_ACTION_APPLYCALLEE = 1045;

// Decompiler Modes
constexpr int IDM_VIEW_CSHARP        = 1010;
constexpr int IDM_VIEW_C             = 1011;
constexpr int IDM_VIEW_RUST          = 1012;
constexpr int IDM_VIEW_GO            = 1017;
constexpr int IDM_VIEW_JAVA          = 1013;
constexpr int IDM_VIEW_DELPHI        = 1014;
constexpr int IDM_VIEW_VB            = 1015;
constexpr int IDM_VIEW_AUTOIT        = 1016;
constexpr int IDM_VIEW_LUA           = 1018;

constexpr int IDM_HELP_ABOUT         = 1020;

// Child Controls
constexpr int IDC_TREEVIEW           = 2001;
constexpr int IDC_CODE_EDITOR        = 2002;
constexpr int IDC_LOG_LIST           = 2003;
constexpr int IDC_STATUS_BAR         = 2004;

constexpr COLORREF kClrDarkBg        = RGB(30, 30, 30);      // dnSpy main background #1E1E1E
constexpr COLORREF kClrTreeBg        = RGB(37, 37, 38);      // dnSpy treeview #252526
constexpr COLORREF kClrText          = RGB(241, 241, 241);   // dnSpy foreground text #F1F1F1
constexpr COLORREF kClrHeader        = RGB(45, 45, 48);      // dnSpy toolbar / header #2D2D30
constexpr COLORREF kClrBtnNormal     = RGB(45, 45, 48);      // dnSpy button normal #2D2D30
constexpr COLORREF kClrBtnHover      = RGB(62, 62, 64);      // dnSpy button hover #3E3E40
constexpr COLORREF kClrBtnPressed    = RGB(80, 80, 80);      // dnSpy button pressed #505050
constexpr COLORREF kClrBtnBorder     = RGB(62, 62, 64);      // dnSpy button border #3E3E40
constexpr COLORREF kClrStatusBg      = RGB(0, 122, 204);     // dnSpy status bar accent #007ACC
constexpr COLORREF kClrStatusText    = RGB(255, 255, 255);   // dnSpy status bar text #FFFFFF

HWND g_hwndMain   = nullptr;
HWND g_hwndTree   = nullptr;
HWND g_hwndCode   = nullptr;
HWND g_hwndLog    = nullptr;
HWND g_hwndStatus = nullptr;

std::vector<HWND> g_toolbarButtons;

struct ToolbarBtnDef {
    int id;
    const wchar_t* label;
    int width;
};

const ToolbarBtnDef kToolBtns[] = {
    {IDM_FILE_OPEN,        L"Open Binary",      88},
    {IDM_FILE_SAVE_AS,     L"Save Code",        74},
    {IDM_ACTION_DEOBF,     L"Deobfuscate",      84},
    {IDM_ACTION_DETECT,    L"Detect (DIE)",     84},
    {IDM_ACTION_VMPROFILE, L"VMProfiler",       78},
    {IDM_ACTION_CHECKSEC,  L"checksec",         64},
    {IDM_ACTION_ABI,       L"ABI / Subs",       74},
    {IDM_ACTION_STRINGS,   L"Strings",          58},
    {IDM_ACTION_CRYPTO,    L"Crypto",           56},
    {IDM_ACTION_IATFIX,    L"IAT Fix",          58},
    {IDM_ACTION_INFER,     L"Infer Schema",     88},
    {IDM_VIEW_C,           L"C Pseudocode",     90},
    {IDM_VIEW_CSHARP,      L"C# (.NET)",        70},
    {IDM_VIEW_RUST,        L"Rust",             48},
    {IDM_VIEW_GO,          L"Go",               38},
    {IDM_HELP_ABOUT,       L"About",            48},
};

HFONT g_hFontCode   = nullptr;
HFONT g_hFontUI     = nullptr;
HFONT g_hFontBtn    = nullptr;
HBRUSH g_hBrushDark = nullptr;
HBRUSH g_hBrushTree = nullptr;

StudioApp* g_pApp = nullptr;

std::string to_wide_hex(std::uint64_t val) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(val));
    return std::string(buf);
}

std::string format_hex_dump(std::span<const std::uint8_t> data, std::uint64_t base_offset = 0, std::size_t max_bytes = 256) {
    std::ostringstream ss;
    std::size_t count = std::min(data.size(), max_bytes);
    for (std::size_t i = 0; i < count; i += 16) {
        char line_addr[32];
        std::snprintf(line_addr, sizeof(line_addr), "%08llx  ", static_cast<unsigned long long>(base_offset + i));
        ss << line_addr;

        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < count) {
                char b_buf[8];
                std::snprintf(b_buf, sizeof(b_buf), "%02x ", data[i + j]);
                ss << b_buf;
            } else {
                ss << "   ";
            }
            if (j == 7) ss << " ";
        }
        ss << " |";

        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < count) {
                std::uint8_t b = data[i + j];
                ss << ((b >= 32 && b <= 126) ? static_cast<char>(b) : '.');
            } else {
                ss << ' ';
            }
        }
        ss << "|\n";
    }
    if (data.size() > max_bytes) {
        ss << "  ... (" << (data.size() - max_bytes) << " additional bytes truncated) ...\n";
    }
    return ss.str();
}

std::wstring to_wide(std::string_view str) {
    if (str.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    std::wstring out(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), &out[0], sz);
    return out;
}

std::wstring to_wide(const std::string& str) {
    return to_wide(std::string_view(str));
}

std::wstring normalize_crlf(const std::string& text) {
    std::wstring w = to_wide(text);
    std::wstring out;
    out.reserve(w.size() + 1024);
    for (wchar_t ch : w) {
        if (ch == L'\n') out += L"\r\n";
        else out.push_back(ch);
    }
    return out;
}

void LogMessage(const std::string& msg) {
    if (!g_hwndLog) return;
    std::wstring wmsg = to_wide(msg);
    SendMessageW(g_hwndLog, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(wmsg.c_str()));
    LRESULT count = SendMessageW(g_hwndLog, LB_GETCOUNT, 0, 0);
    SendMessageW(g_hwndLog, LB_SETCURSEL, count - 1, 0);
}

void SetStatusBarText(int part, const std::string& text) {
    if (!g_hwndStatus) return;
    std::wstring wtext = to_wide(text);
    SendMessageW(g_hwndStatus, SB_SETTEXTW, part, reinterpret_cast<LPARAM>(wtext.c_str()));
}

typedef void (WINAPI *pfnDragAcceptFiles)(HWND, BOOL);
typedef UINT (WINAPI *pfnDragQueryFileW)(HDROP, UINT, LPWSTR, UINT);
typedef void (WINAPI *pfnDragFinish)(HDROP);

inline void SafeDragAcceptFiles(HWND hwnd, BOOL accept) {
    HMODULE hShell = LoadLibraryA("shell32.dll");
    if (hShell) {
        auto pfn = reinterpret_cast<pfnDragAcceptFiles>(GetProcAddress(hShell, "DragAcceptFiles"));
        if (pfn) pfn(hwnd, accept);
    }
}

inline UINT SafeDragQueryFileW(HDROP hDrop, UINT iFile, LPWSTR lpszFile, UINT cch) {
    HMODULE hShell = GetModuleHandleA("shell32.dll");
    if (!hShell) hShell = LoadLibraryA("shell32.dll");
    if (hShell) {
        auto pfn = reinterpret_cast<pfnDragQueryFileW>(GetProcAddress(hShell, "DragQueryFileW"));
        if (pfn) return pfn(hDrop, iFile, lpszFile, cch);
    }
    return 0;
}

inline void SafeDragFinish(HDROP hDrop) {
    HMODULE hShell = GetModuleHandleA("shell32.dll");
    if (!hShell) hShell = LoadLibraryA("shell32.dll");
    if (hShell) {
        auto pfn = reinterpret_cast<pfnDragFinish>(GetProcAddress(hShell, "DragFinish"));
        if (pfn) pfn(hDrop);
    }
}


inline void EnableImmersiveDarkMode(HWND hwnd) {
    HMODULE hDwm = LoadLibraryA("dwmapi.dll");
    if (hDwm) {
        typedef HRESULT (WINAPI* pfnDwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);
        auto pDwmSet = reinterpret_cast<pfnDwmSetWindowAttribute>(GetProcAddress(hDwm, "DwmSetWindowAttribute"));
        if (pDwmSet) {
            BOOL darkMode = TRUE;
            // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10 20H1+ and Windows 11)
            // Fallback: 19 for Windows 10 1809 - 1909
            if (FAILED(pDwmSet(hwnd, 20, &darkMode, sizeof(darkMode)))) {
                pDwmSet(hwnd, 19, &darkMode, sizeof(darkMode));
            }
        }
        FreeLibrary(hDwm);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        EnableImmersiveDarkMode(hwnd);
        INITCOMMONCONTROLSEX icex = {sizeof(icex), ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES};
        InitCommonControlsEx(&icex);

        g_hFontUI = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        g_hFontCode = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        g_hBrushDark = CreateSolidBrush(kClrDarkBg);
        g_hBrushTree = CreateSolidBrush(kClrTreeBg);

        // Assembly / Symbol Explorer (TreeView)
        g_hwndTree = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
            WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
            0, 32, 300, 400, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_TREEVIEW)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndTree, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontUI), TRUE);
        TreeView_SetBkColor(g_hwndTree, kClrTreeBg);
        TreeView_SetTextColor(g_hwndTree, kClrText);

        // Multi-Language Code & Disassembly View
        g_hwndCode = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            300, 32, 600, 400, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CODE_EDITOR)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndCode, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontCode), TRUE);

        // Deobfuscation & Diagnostic Console
        g_hwndLog = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            0, 400, 900, 140, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOG_LIST)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndLog, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontCode), TRUE);

        // Quick Action Toolbar Buttons
        g_toolbarButtons.clear();
        for (const auto& btn : kToolBtns) {
            HWND hBtn = CreateWindowExW(
                0, L"BUTTON", btn.label,
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                0, 0, btn.width, 24, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(btn.id)),
                GetModuleHandleW(nullptr), nullptr);
            SendMessageW(hBtn, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontUI), TRUE);
            g_toolbarButtons.push_back(hBtn);
        }

        // Drag & Drop binary files onto window (dynamically resolved)
        SafeDragAcceptFiles(hwnd, TRUE);

        // Status Bar
        g_hwndStatus = CreateWindowExW(
            0, STATUSCLASSNAMEW, L"",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS_BAR)),
            GetModuleHandleW(nullptr), nullptr);

        int parts[] = {360, 720, -1};
        SendMessageW(g_hwndStatus, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
        SendMessageW(g_hwndStatus, SB_SETBKCOLOR, 0, static_cast<LPARAM>(kClrDarkBg));
        SetStatusBarText(0, "Ready - TypeMorph Decompiler Studio");
        SetStatusBarText(1, "TypeMorph Semantic Engine");
        SetStatusBarText(2, "TypeMorph v0.7.0 C++20");

        LogMessage("// TypeMorph Studio native Win32 desktop UI initialized.");
        LogMessage("// Drag-and-drop or Open any PE64, ELF, Mach-O, .NET, DEX, Delphi or VMProtect binary.");
        return 0;
    }

    case WM_ERASEBKGND: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_hBrushDark);
        return 1;
    }

    case WM_DRAWITEM: {
        auto* pDis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (pDis && pDis->CtlType == ODT_BUTTON) {
            bool is_pressed = (pDis->itemState & ODS_SELECTED) != 0;
            bool is_disabled = (pDis->itemState & ODS_DISABLED) != 0;
            bool is_focused = (pDis->itemState & ODS_FOCUS) != 0;

            COLORREF bg = is_pressed ? kClrBtnPressed : (is_focused ? kClrBtnHover : kClrBtnNormal);
            HBRUSH hBgBrush = CreateSolidBrush(bg);
            FillRect(pDis->hDC, &pDis->rcItem, hBgBrush);
            DeleteObject(hBgBrush);

            HPEN hPen = CreatePen(PS_SOLID, 1, kClrBtnBorder);
            HGDIOBJ hOldPen = SelectObject(pDis->hDC, hPen);
            HGDIOBJ hOldBrush = SelectObject(pDis->hDC, GetStockObject(NULL_BRUSH));
            Rectangle(pDis->hDC, pDis->rcItem.left, pDis->rcItem.top, pDis->rcItem.right, pDis->rcItem.bottom);
            SelectObject(pDis->hDC, hOldBrush);
            SelectObject(pDis->hDC, hOldPen);
            DeleteObject(hPen);

            wchar_t btn_text[128] = L"";
            GetWindowTextW(pDis->hwndItem, btn_text, 128);
            SetBkMode(pDis->hDC, TRANSPARENT);
            SetTextColor(pDis->hDC, is_disabled ? RGB(100, 100, 100) : kClrText);
            HGDIOBJ hOldFont = SelectObject(pDis->hDC, g_hFontUI);
            RECT rcText = pDis->rcItem;
            if (is_pressed) {
                OffsetRect(&rcText, 1, 1);
            }
            DrawTextW(pDis->hDC, btn_text, -1, &rcText, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(pDis->hDC, hOldFont);
            return TRUE;
        }
        break;
    }

    case WM_DROPFILES: {
        HDROP hDrop = reinterpret_cast<HDROP>(wParam);
        wchar_t szFile[MAX_PATH] = L"";
        if (SafeDragQueryFileW(hDrop, 0, szFile, MAX_PATH)) {
            char path_mb[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, szFile, -1, path_mb, MAX_PATH, nullptr, nullptr);
            if (g_pApp) g_pApp->open_file(path_mb);
        }
        SafeDragFinish(hDrop);
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);

        RECT rcStatus;
        SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
        GetWindowRect(g_hwndStatus, &rcStatus);
        int status_h = rcStatus.bottom - rcStatus.top;

        int top_bar_h = 32;
        int cur_x = 4;
        for (std::size_t i = 0; i < g_toolbarButtons.size(); ++i) {
            MoveWindow(g_toolbarButtons[i], cur_x, 4, kToolBtns[i].width, 24, TRUE);
            cur_x += kToolBtns[i].width + 4;
        }

        int log_h = 140;
        int tree_w = 300;
        int main_h = h - status_h - log_h - top_bar_h;
        if (main_h < 50) main_h = 50;

        MoveWindow(g_hwndTree, 0, top_bar_h, tree_w, main_h, TRUE);
        MoveWindow(g_hwndCode, tree_w, top_bar_h, w - tree_w, main_h, TRUE);
        MoveWindow(g_hwndLog, 0, top_bar_h + main_h, w, log_h, TRUE);
        return 0;
    }

    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND ctl = reinterpret_cast<HWND>(lParam);
        if (ctl == g_hwndCode || ctl == g_hwndLog) {
            SetTextColor(hdc, kClrText);
            SetBkColor(hdc, kClrDarkBg);
            return reinterpret_cast<INT_PTR>(g_hBrushDark);
        }
        break;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDM_FILE_OPEN) {
            wchar_t szFile[MAX_PATH] = L"";
            OPENFILENAMEW ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"All Supported Files (*.exe;*.dll;*.dex;*.luac)\0*.exe;*.dll;*.dex;*.luac\0Executables (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

            if (GetOpenFileNameW(&ofn)) {
                char path_mb[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, szFile, -1, path_mb, MAX_PATH, nullptr, nullptr);
                if (g_pApp) g_pApp->open_file(path_mb);
            }
            return 0;
        }
        if (id == IDM_FILE_SAVE_AS) {
            if (g_pApp) g_pApp->save_decompiled_output();
            return 0;
        }
        if (id == IDM_ACTION_DEOBF) {
            if (g_pApp) g_pApp->deobfuscate_current();
            return 0;
        }
        if (id == IDM_ACTION_DETECT) {
            if (g_pApp) g_pApp->run_detection();
            return 0;
        }
        if (id == IDM_ACTION_VMPROFILE) {
            if (g_pApp) g_pApp->run_vm_analysis();
            return 0;
        }
        if (id == IDM_ACTION_UNPACK) {
            if (g_pApp) g_pApp->run_unpack();
            return 0;
        }
        if (id == IDM_ACTION_VFS) {
            if (g_pApp) g_pApp->run_vfs_extract();
            return 0;
        }
        if (id == IDM_ACTION_IATFIX) {
            if (g_pApp) g_pApp->run_iat_fix();
            return 0;
        }
        if (id == IDM_ACTION_MEMDUMP) {
            if (g_pApp) g_pApp->run_memdump_fix();
            return 0;
        }
        if (id == IDM_ACTION_CHECKSEC) {
            if (g_pApp) g_pApp->run_checksec();
            return 0;
        }
        if (id == IDM_ACTION_RICH) {
            if (g_pApp) g_pApp->run_rich_header();
            return 0;
        }
        if (id == IDM_ACTION_ABI) {
            if (g_pApp) g_pApp->run_abi_classifier();
            return 0;
        }
        if (id == IDM_ACTION_STRINGS) {
            if (g_pApp) g_pApp->run_string_revealer();
            return 0;
        }
        if (id == IDM_ACTION_CRYPTO) {
            if (g_pApp) g_pApp->run_crypto_scanner();
            return 0;
        }
        if (id == IDM_ACTION_AES_RECOVER) {
            if (g_pApp) g_pApp->run_aes_recovery();
            return 0;
        }
        if (id == IDM_ACTION_ENTROPY) {
            if (g_pApp) g_pApp->run_entropy_analysis();
            return 0;
        }
        if (id == IDM_ACTION_UNXOR) {
            if (g_pApp) g_pApp->run_unxorer();
            return 0;
        }
        if (id == IDM_ACTION_APIHASH) {
            if (g_pApp) g_pApp->run_apihash_scan();
            return 0;
        }
        if (id == IDM_ACTION_OPAQUE) {
            if (g_pApp) g_pApp->run_opaque_predicates();
            return 0;
        }
        if (id == IDM_ACTION_CFF) {
            if (g_pApp) g_pApp->run_cff_reconstruction();
            return 0;
        }
        if (id == IDM_ACTION_CLASSINFO) {
            if (g_pApp) g_pApp->run_classinformer();
            return 0;
        }
        if (id == IDM_ACTION_SIGMAKE) {
            if (g_pApp) g_pApp->run_sigmaker();
            return 0;
        }
        if (id == IDM_ACTION_INFER) {
            if (g_pApp) g_pApp->run_infer();
            return 0;
        }
        if (id == IDM_ACTION_DUMPSUBS) {
            if (g_pApp) g_pApp->run_dumpsubs();
            return 0;
        }
        if (id == IDM_ACTION_APPLYCALLEE) {
            if (g_pApp) g_pApp->run_applycalletype();
            return 0;
        }

        // View Mode Switches
        if (id == IDM_VIEW_CSHARP) { if (g_pApp) g_pApp->set_mode(DecompilerMode::csharp); return 0; }
        if (id == IDM_VIEW_C)      { if (g_pApp) g_pApp->set_mode(DecompilerMode::c_source); return 0; }
        if (id == IDM_VIEW_RUST)   { if (g_pApp) g_pApp->set_mode(DecompilerMode::rust_source); return 0; }
        if (id == IDM_VIEW_GO)     { if (g_pApp) g_pApp->set_mode(DecompilerMode::go_source); return 0; }
        if (id == IDM_VIEW_JAVA)   { if (g_pApp) g_pApp->set_mode(DecompilerMode::dex_java); return 0; }
        if (id == IDM_VIEW_DELPHI) { if (g_pApp) g_pApp->set_mode(DecompilerMode::delphi_pascal); return 0; }
        if (id == IDM_VIEW_VB)     { if (g_pApp) g_pApp->set_mode(DecompilerMode::vb_source); return 0; }
        if (id == IDM_VIEW_AUTOIT) { if (g_pApp) g_pApp->set_mode(DecompilerMode::autoit_script); return 0; }
        if (id == IDM_VIEW_LUA)    { if (g_pApp) g_pApp->set_mode(DecompilerMode::lua_source); return 0; }

        if (id == IDM_FILE_EXIT) {
            DestroyWindow(hwnd);
            return 0;
        }
        if (id == IDM_HELP_ABOUT) {
            MessageBoxW(hwnd,
                L"TypeMorph Studio v0.7.0\n\n"
                L"Next-generation reverse engineering suite with multi-engine decompilation,\n"
                L"virtual machine profiling & automated packer reconstruction.\n\n"
                L"Engines:\n"
                L"• .NET / C# Decompiler & ConfuserEx / .NET Reactor Cleaner\n"
                L"• C Pseudocode & Rust Trait/VTable Reconstructor\n"
                L"• Golang pclntab & Struct Recovery\n"
                L"• Delphi & C++Builder VCL Form Rescuer (IDR/DeDe)\n"
                L"• Android Dalvik DEX & Java Engine (JADX style)\n"
                L"• Visual Basic 5/6 Native & P-Code Reconstructor\n"
                L"• AutoIt v3 Token Decompiler (Exe2Aut)\n"
                L"• Lua & LuaJIT 2.0/2.1 Bytecode Decompiler\n"
                L"• Virtual Machine Profiler (VMProtect / Themida / NoVmp)\n"
                L"• Universal PE Unpacker (UPX / ASPack / PECompact)\n"
                L"• VFS Container Extractor (Spoon Studio / Enigma Virtual Box)\n"
                L"• Memory Dump Fixer & PE Reconstructor (vmpdump / Scylla)\n"
                L"• ClassInformer C++ RTTI & Polymorphic Hierarchy\n"
                L"• SigMaker (IDA / YARA / C Bytes Pattern Generator)\n"
                L"• Cryptographic Constant Scanner & AES Key Recovery\n"
                L"• Control Flow Flattening (CFF) Unflattener (OLLVM/Tigress)\n"
                L"• Differential Binary Format & Schema Inference",
                L"About TypeMorph Studio", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;
    }

    case WM_NOTIFY: {
        LPNMHDR pnm = reinterpret_cast<LPNMHDR>(lParam);
        if (pnm->idFrom == IDC_TREEVIEW && pnm->code == TVN_SELCHANGEDW) {
            LPNMTREEVIEWW pnmtv = reinterpret_cast<LPNMTREEVIEWW>(lParam);
            if (pnmtv->itemNew.lParam != 0) {
                const auto* info = reinterpret_cast<const TreeItemInfo*>(pnmtv->itemNew.lParam);
                if (info && !info->content.empty()) {
                    SetWindowTextW(g_hwndCode, normalize_crlf(info->content).c_str());
                    SetStatusBarText(0, info->title);
                    if (!info->status_info.empty()) {
                        SetStatusBarText(1, info->status_info);
                    }
                    LogMessage("Selected: " + info->title);
                    break;
                }
            }
            wchar_t text_buf[256] = L"";
            TVITEMW item = {};
            item.hItem = pnmtv->itemNew.hItem;
            item.mask = TVIF_TEXT;
            item.pszText = text_buf;
            item.cchTextMax = 256;
            SendMessageW(g_hwndTree, TVM_GETITEMW, 0, reinterpret_cast<LPARAM>(&item));

            char mb[256];
            WideCharToMultiByte(CP_UTF8, 0, text_buf, -1, mb, 256, nullptr, nullptr);
            LogMessage(std::string("Selected: ") + mb);
        }
        break;
    }

    case WM_DESTROY:
        if (g_hFontUI) DeleteObject(g_hFontUI);
        if (g_hFontCode) DeleteObject(g_hFontCode);
        if (g_hBrushDark) DeleteObject(g_hBrushDark);
        if (g_hBrushTree) DeleteObject(g_hBrushTree);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void SetupMenus(HWND hwnd) {
    HMENU hMenuBar = CreateMenu();

    // File Menu
    HMENU hFile = CreatePopupMenu();
    AppendMenuW(hFile, MF_STRING, IDM_FILE_OPEN,    L"&Open Binary / Assembly...\tCtrl+O");
    AppendMenuW(hFile, MF_STRING, IDM_FILE_SAVE_AS, L"&Save Decompiled Code As...\tCtrl+S");
    AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFile, MF_STRING, IDM_FILE_EXIT,    L"E&xit");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFile), L"&File");

    // Decompile Language Menu
    HMENU hDecompile = CreatePopupMenu();
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_CSHARP, L"&C# Decompiler (.NET)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_C,      L"Structured &C Pseudocode (Native x86/x64)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_RUST,   L"&Rust Semantic Source Reconstructor");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_GO,     L"&Go Source Reconstructor (pclntab)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_JAVA,   L"&Java Source (Android Dalvik DEX)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_DELPHI, L"&Pascal Units (Delphi VCL Forms)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_VB,     L"&Visual Basic 5/6 Source (.frm / .bas)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_AUTOIT, L"&AutoIt v3 Script (.au3)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_LUA,    L"&Lua Source Reconstructor (.lua)");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDecompile), L"&Decompile");

    // Protection & Analysis Menu
    HMENU hAnalysis = CreatePopupMenu();
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_DETECT,      L"&Compiler & Packer Detection (DIE Engine)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_CHECKSEC,    L"&Binary Hardening & Mitigations (checksec)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_RICH,        L"&MSVC Rich Header & Compiler Fingerprint");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_ABI,         L"&Calling Convention & ABI Classifier");
    AppendMenuW(hAnalysis, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_DUMPSUBS,    L"&Subroutines & Stack Purge Dumper (CSV / Table)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_APPLYCALLEE, L"&Propagate Callee Types & Signatures (ApplyCalleeType)");
    AppendMenuW(hAnalysis, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_VMPROFILE,   L"&Virtual Machine Profiler (VMProtect / Themida)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_UNPACK,      L"&Universal PE Unpacker & Header Fix (UPX / ASPack)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_VFS,         L"&Virtual Filesystem Payload Extractor (Spoon/Enigma)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_IATFIX,      L"&Import Address Table (IAT) Reconstructor");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_MEMDUMP,     L"&Memory Dump Fixer & PE Reconstructor (vmpdump / Scylla)");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hAnalysis), L"&Analysis");

    // Forensics & Cryptography Menu
    HMENU hForensics = CreatePopupMenu();
    AppendMenuW(hForensics, MF_STRING, IDM_ACTION_STRINGS,     L"&Extract Obfuscated Strings (ASCII / UTF-16 / Stack / XOR / Base64)");
    AppendMenuW(hForensics, MF_STRING, IDM_ACTION_CRYPTO,      L"&Cryptographic Constants Scanner (AES / SHA / MD5 / CRC)");
    AppendMenuW(hForensics, MF_STRING, IDM_ACTION_AES_RECOVER, L"&AES Key Schedule Recovery & White-box Analyzer");
    AppendMenuW(hForensics, MF_STRING, IDM_ACTION_ENTROPY,     L"&Shannon Entropy Distribution & High-Entropy Zones");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hForensics), L"&Forensics");

    // Deobfuscation & Advanced Reversing Menu
    HMENU hDeobf = CreatePopupMenu();
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_DEOBF,      L"&Clean .NET Assembly (ConfuserEx / .NET Reactor)\tF5");
    AppendMenuW(hDeobf, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_UNXOR,      L"&Automated XOR Key Discovery (UnXORer)");
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_APIHASH,    L"&Resolve Obfuscated API Hashes (ROR13 / DJB2 / FNV1a)");
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_OPAQUE,     L"&Detect Opaque Predicates & Dead Branches");
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_CFF,        L"&Control Flow Flattening (CFF) Unflattener (OLLVM / Tigress)");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDeobf), L"De&obfuscate");

    // Tools & Signatures Menu
    HMENU hTools = CreatePopupMenu();
    AppendMenuW(hTools, MF_STRING, IDM_ACTION_INFER,      L"&Infer Binary Format & Schema (Kaitai / C++ / Rust)");
    AppendMenuW(hTools, MF_STRING, IDM_ACTION_CLASSINFO,  L"&ClassInformer C++ RTTI Explorer");
    AppendMenuW(hTools, MF_STRING, IDM_ACTION_SIGMAKE,    L"&SigMaker (IDA / YARA / Byte Signature Generator)");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hTools), L"&Tools");

    // Help Menu
    HMENU hHelp = CreatePopupMenu();
    AppendMenuW(hHelp, MF_STRING, IDM_HELP_ABOUT, L"&About TypeMorph Studio...");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelp), L"&Help");

    SetMenu(hwnd, hMenuBar);
}

}  // namespace

void StudioApp::populate_tree(const core::BinaryView& view) {
    if (!g_hwndTree) return;
    tree_items_.clear();
    SendMessageW(g_hwndTree, TVM_DELETEITEM, 0, reinterpret_cast<LPARAM>(TVI_ROOT));

    std::string filename = current_file_;
    auto last_slash = filename.find_last_of("\\/");
    if (last_slash != std::string::npos) filename = filename.substr(last_slash + 1);
    if (filename.empty()) filename = "Target_Binary";

    // 0. Root Binary Node
    auto root_info = std::make_unique<TreeItemInfo>();
    root_info->title = filename;
    root_info->category = "Root";

    std::ostringstream root_ss;
    root_ss << "TypeMorph Binary Analysis & Decompiler Studio\n"
            << "================================================================================\n"
            << "Target File:       " << current_file_ << "\n"
            << "File Size:         " << view.size() << " bytes (" << (view.size() / 1024) << " KB)\n";

    auto img_res = core::ExecutableImage::parse(view);
    if (img_res) {
        const auto& img = img_res.value();
        root_ss << "Image Format:      " << core::to_string(img.format()) << " (" << img.bits() << "-bit)\n"
                << "Image Base:        0x" << std::hex << img.image_base() << "\n"
                << "Entry Point:       0x" << std::hex << img.entry_point() << std::dec << "\n"
                << "Sections Count:    " << img.sections().size() << "\n"
                << "Symbols Count:     " << img.symbols().size() << "\n";
    }

    if (!detect_result_.primary_compiler.empty() || !detect_result_.primary_packer.empty()) {
        root_ss << "Compiler Verdict:  " << (detect_result_.primary_compiler.empty() ? "Unknown" : detect_result_.primary_compiler) << "\n"
                << "Packer / Protector:" << (detect_result_.primary_packer.empty() ? "None" : detect_result_.primary_packer) << "\n";
    }
    if (vm_report_.is_virtualized) {
        root_ss << "Virtual Machine:   " << vm_report_.detected_protector
                << " (" << vm_report_.total_handlers << " handlers identified)\n";
    }
    root_ss << "================================================================================\n\n"
            << "Select any section, export, subroutine, or VM entry in the tree to inspect details.\n";

    root_info->content = root_ss.str();
    root_info->status_info = filename + " (" + std::to_string(view.size()) + " B)";

    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

    std::wstring wroot_text = to_wide(filename);
    if (img_res) {
        wroot_text += L" [" + to_wide(core::to_string(img_res->format())) + L" " + std::to_wstring(img_res->bits()) + L"-bit]";
    }
    tvis.item.pszText = const_cast<LPWSTR>(wroot_text.c_str());
    tvis.item.lParam = reinterpret_cast<LPARAM>(root_info.get());
    HTREEITEM hRoot = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));
    tree_items_.push_back(std::move(root_info));

    // 1. Native Executable (PE / ELF / Mach-O)
    if (img_res) {
        const auto& img = img_res.value();
        c_report_ = decompile::CDecompiler{}.decompile(img, std::nullopt);
        abi_report_ = abi::AbiClassifier{}.analyze(img, std::nullopt);

        std::map<std::uint64_t, std::string> decompile_map;
        for (const auto& f : c_report_.functions) {
            decompile_map[f.entry_va] = f.pseudocode;
        }

        // PE Security / Hardening Node
        auto sec_check_info = std::make_unique<TreeItemInfo>();
        sec_check_info->title = "Binary Hardening & Security (checksec)";
        sec_check_info->category = "Security";
        security::SecurityAnalyzer sec_analyzer;
        auto sec_rep = sec_analyzer.analyze_view(view);
        {
            std::ostringstream ss;
            char ep_buf[32];
            std::snprintf(ep_buf, sizeof(ep_buf), "0x%llx", static_cast<unsigned long long>(sec_rep.entry_point));
            ss << "Binary Hardening & Security Profile (checksec)\n"
               << "================================================================================\n"
               << "Target: " << current_file_ << "\n"
               << "Format: " << core::to_string(sec_rep.format) << " (" << sec_rep.bits << "-bit)\n"
               << "Entry:  " << ep_buf << (sec_rep.entry_point_outside_code ? " [WARNING: Outside code section!]" : "") << "\n\n"
               << "Mitigations:\n"
               << "  ASLR:                  " << (sec_rep.mitigations.aslr ? "Enabled" : "Disabled") << "\n"
               << "  High-Entropy VA:       " << (sec_rep.mitigations.high_entropy_va ? "Enabled" : "Disabled") << "\n"
               << "  DEP / NX:              " << (sec_rep.mitigations.dep_nx ? "Enabled" : "Disabled") << "\n"
               << "  Control Flow Guard:    " << (sec_rep.mitigations.cfg ? "Enabled" : "Disabled") << "\n"
               << "  CET Shadow Stack:      " << (sec_rep.mitigations.cet_shadow_stack ? "Enabled" : "Disabled") << "\n";
            if (sec_rep.format == core::ImageFormat::pe) {
                ss << "  SafeSEH:               " << (sec_rep.mitigations.safe_seh ? "Enabled" : "Disabled / N/A") << "\n"
                   << "  Authenticode Signed:   " << (sec_rep.mitigations.signed_binary ? "Signed" : "No signature") << "\n"
                   << "  TLS Callbacks:         " << (sec_rep.has_tls_callbacks ? "Present" : "None") << "\n";
            }
            if (!sec_rep.packers.empty()) {
                ss << "\nPackers Detected:\n";
                for (const auto& p : sec_rep.packers) {
                    ss << "  - " << p.name << " (" << (p.confidence * 100.0) << "%): " << p.rationale << "\n";
                }
            }
            sec_check_info->content = ss.str();
        }
        sec_check_info->status_info = "checksec: ASLR=" + std::string(sec_rep.mitigations.aslr ? "ON" : "OFF") +
                                      " DEP=" + std::string(sec_rep.mitigations.dep_nx ? "ON" : "OFF");
        TVINSERTSTRUCTW ins_sec = {};
        ins_sec.hParent = hRoot;
        ins_sec.hInsertAfter = TVI_LAST;
        ins_sec.item.mask = TVIF_TEXT | TVIF_PARAM;
        std::wstring wsec_label = L"Security Mitigations (checksec)";
        ins_sec.item.pszText = const_cast<LPWSTR>(wsec_label.c_str());
        ins_sec.item.lParam = reinterpret_cast<LPARAM>(sec_check_info.get());
        SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ins_sec));
        tree_items_.push_back(std::move(sec_check_info));

        // Sections Node
        if (!img.sections().empty()) {
            auto sec_parent_info = std::make_unique<TreeItemInfo>();
            sec_parent_info->title = "Sections (" + std::to_string(img.sections().size()) + ")";
            sec_parent_info->category = "Sections";
            std::ostringstream ss_all_sec;
            ss_all_sec << "Executable Sections Overview (" << img.sections().size() << " sections)\n"
                       << "================================================================================\n"
                       << "Name       Virtual Address     Virtual Size   Raw Offset   Raw Size     Entropy  Flags\n"
                       << "--------------------------------------------------------------------------------\n";
            for (const auto& s : img.sections()) {
                auto sbytes = img.section_bytes(s);
                double ent = sbytes ? core::shannon_entropy(sbytes.value()) : 0.0;
                char line[128];
                std::snprintf(line, sizeof(line), "%-10s 0x%016llx  0x%08llx     0x%08llx   0x%08llx   %5.2f    ",
                              s.name.empty() ? "(none)" : s.name.c_str(),
                              static_cast<unsigned long long>(s.virtual_address),
                              static_cast<unsigned long long>(s.virtual_size),
                              static_cast<unsigned long long>(s.file_offset),
                              static_cast<unsigned long long>(s.file_size),
                              ent);
                ss_all_sec << line;
                if (s.executable()) ss_all_sec << "EXEC ";
                if (s.writable()) ss_all_sec << "WRITE ";
                if (s.read_only()) ss_all_sec << "READ ";
                ss_all_sec << "\n";
            }
            sec_parent_info->content = ss_all_sec.str();
            sec_parent_info->status_info = std::to_string(img.sections().size()) + " sections in image";

            TVINSERTSTRUCTW ins_sec_parent = {};
            ins_sec_parent.hParent = hRoot;
            ins_sec_parent.hInsertAfter = TVI_LAST;
            ins_sec_parent.item.mask = TVIF_TEXT | TVIF_PARAM;
            std::wstring wsec_p = to_wide("Sections (" + std::to_string(img.sections().size()) + ")");
            ins_sec_parent.item.pszText = const_cast<LPWSTR>(wsec_p.c_str());
            ins_sec_parent.item.lParam = reinterpret_cast<LPARAM>(sec_parent_info.get());
            HTREEITEM hSections = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ins_sec_parent)));
            tree_items_.push_back(std::move(sec_parent_info));

            // Individual Section Child Nodes
            for (const auto& s : img.sections()) {
                auto s_info = std::make_unique<TreeItemInfo>();
                std::string s_name = s.name.empty() ? "(unnamed)" : s.name;
                s_info->title = "Section " + s_name;
                s_info->category = "Section";
                s_info->va = s.virtual_address;
                s_info->size = static_cast<std::size_t>(s.virtual_size);

                auto sbytes = img.section_bytes(s);
                double ent = sbytes ? core::shannon_entropy(sbytes.value()) : 0.0;

                std::ostringstream s_detail;
                s_detail << "Section Header Details: " << s_name << "\n"
                         << "================================================================================\n"
                         << "Virtual Address:   0x" << std::hex << s.virtual_address << "\n"
                         << "Virtual Size:      0x" << s.virtual_size << " (" << std::dec << s.virtual_size << " bytes)\n"
                         << "Raw File Offset:   0x" << std::hex << s.file_offset << "\n"
                         << "Raw File Size:     0x" << s.file_size << " (" << std::dec << s.file_size << " bytes)\n"
                         << "Characteristics:   " << (s.executable() ? "EXECUTABLE " : "")
                                                << (s.writable() ? "WRITABLE " : "")
                                                << (s.read_only() ? "READ-ONLY " : "") << "\n"
                         << "Shannon Entropy:   " << std::fixed << std::setprecision(2) << ent
                         << " (" << core::entropy_label(ent) << ")\n\n"
                         << "Hex & ASCII Preview (First 256 bytes):\n"
                         << "--------------------------------------------------------------------------------\n";
                if (sbytes && !sbytes.value().empty()) {
                    s_detail << format_hex_dump(sbytes.value(), s.virtual_address, 256);
                } else {
                    s_detail << "  (Section has no raw file data - uninitialized or BSS zero-fill)\n";
                }
                s_info->content = s_detail.str();
                s_info->status_info = s_name + " | VA: 0x" + to_wide_hex(s.virtual_address) + " | Entropy: " + std::to_string(ent).substr(0, 4);

                TVINSERTSTRUCTW s_ins = {};
                s_ins.hParent = hSections;
                s_ins.hInsertAfter = TVI_LAST;
                s_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                std::string s_label = s_name + " [0x" + to_wide_hex(s.virtual_address) + "] (" + std::to_string(s.virtual_size) + " B)";
                std::wstring ws_label = to_wide(s_label);
                s_ins.item.pszText = const_cast<LPWSTR>(ws_label.c_str());
                s_ins.item.lParam = reinterpret_cast<LPARAM>(s_info.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&s_ins));
                tree_items_.push_back(std::move(s_info));
            }
        }

        // Subroutines & ABI Functions Node
        if (!abi_report_.signatures.empty()) {
            auto subs_parent = std::make_unique<TreeItemInfo>();
            subs_parent->title = "Subroutines & ABI (" + std::to_string(abi_report_.signatures.size()) + ")";
            subs_parent->category = "Subroutines";
            std::ostringstream ss_subs;
            ss_subs << "Discovered Subroutines & Calling Conventions (" << abi_report_.signatures.size() << " functions)\n"
                    << "================================================================================\n";
            for (const auto& sig : abi_report_.signatures) {
                char line[128];
                std::snprintf(line, sizeof(line), "  [0x%016llx] %-14s Frame: %3uB  %s\n",
                              static_cast<unsigned long long>(sig.entry_va),
                              std::string(to_string(sig.convention)).c_str(),
                              static_cast<unsigned int>(sig.stack_frame_size),
                              sig.prototype.c_str());
                ss_subs << line;
            }
            subs_parent->content = ss_subs.str();
            subs_parent->status_info = std::to_string(abi_report_.signatures.size()) + " subroutines classified";

            TVINSERTSTRUCTW ins_sub_p = {};
            ins_sub_p.hParent = hRoot;
            ins_sub_p.hInsertAfter = TVI_LAST;
            ins_sub_p.item.mask = TVIF_TEXT | TVIF_PARAM;
            std::wstring wsub_p = to_wide("Subroutines (" + std::to_string(abi_report_.signatures.size()) + ")");
            ins_sub_p.item.pszText = const_cast<LPWSTR>(wsub_p.c_str());
            ins_sub_p.item.lParam = reinterpret_cast<LPARAM>(subs_parent.get());
            HTREEITEM hSubs = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ins_sub_p)));
            tree_items_.push_back(std::move(subs_parent));

            // Populate individual subroutines
            std::size_t sub_limit = std::min<std::size_t>(abi_report_.signatures.size(), 150);
            for (std::size_t i = 0; i < sub_limit; ++i) {
                const auto& sig = abi_report_.signatures[i];
                auto fn_info = std::make_unique<TreeItemInfo>();
                fn_info->title = sig.prototype;
                fn_info->category = "Subroutine";
                fn_info->va = sig.entry_va;

                std::ostringstream fn_detail;
                fn_detail << "Subroutine Details: " << sig.prototype << "\n"
                          << "================================================================================\n"
                          << "Entry Point VA:     0x" << std::hex << sig.entry_va << std::dec << "\n"
                          << "Calling Convention: " << to_string(sig.convention) << "\n"
                          << "Stack Frame Size:   " << sig.stack_frame_size << " bytes\n"
                          << "Stack Purge:        " << sig.stack_purge_bytes << " bytes\n"
                          << "Classification:     " << sig.rationale << "\n\n"
                          << "Decompiled C Pseudocode:\n"
                          << "--------------------------------------------------------------------------------\n";
                auto it_code = decompile_map.find(sig.entry_va);
                if (it_code != decompile_map.end() && !it_code->second.empty()) {
                    fn_detail << it_code->second << "\n";
                } else {
                    fn_detail << sig.prototype << " {\n"
                              << "    // High-level pseudocode: frame size " << sig.stack_frame_size << " bytes\n"
                              << "    // Target convention: " << to_string(sig.convention) << "\n"
                              << "    return sub_" << std::hex << sig.entry_va << "();\n}\n";
                }
                fn_info->content = fn_detail.str();
                fn_info->status_info = "Function 0x" + to_wide_hex(sig.entry_va) + " [" + std::string(to_string(sig.convention)) + "]";

                TVINSERTSTRUCTW fn_ins = {};
                fn_ins.hParent = hSubs;
                fn_ins.hInsertAfter = TVI_LAST;
                fn_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                std::string fn_lbl = sig.prototype + " [0x" + to_wide_hex(sig.entry_va) + "]";
                std::wstring wfn_lbl = to_wide(fn_lbl);
                fn_ins.item.pszText = const_cast<LPWSTR>(wfn_lbl.c_str());
                fn_ins.item.lParam = reinterpret_cast<LPARAM>(fn_info.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&fn_ins));
                tree_items_.push_back(std::move(fn_info));
            }
        }

        // Exports & Symbols Node
        if (!img.symbols().empty()) {
            auto sym_parent = std::make_unique<TreeItemInfo>();
            sym_parent->title = "Export Symbols (" + std::to_string(img.symbols().size()) + ")";
            sym_parent->category = "Exports";
            std::ostringstream ss_sym;
            ss_sym << "Export Symbols Directory (" << img.symbols().size() << " symbols)\n"
                   << "================================================================================\n";
            for (const auto& s : img.symbols()) {
                char line[128];
                std::snprintf(line, sizeof(line), "  [0x%016llx] (size %4llu)  %s\n",
                              static_cast<unsigned long long>(s.address),
                              static_cast<unsigned long long>(s.size),
                              s.name.c_str());
                ss_sym << line;
            }
            sym_parent->content = ss_sym.str();
            sym_parent->status_info = std::to_string(img.symbols().size()) + " export symbols";

            TVINSERTSTRUCTW ins_sym_p = {};
            ins_sym_p.hParent = hRoot;
            ins_sym_p.hInsertAfter = TVI_LAST;
            ins_sym_p.item.mask = TVIF_TEXT | TVIF_PARAM;
            std::wstring wsym_p = to_wide("Exports (" + std::to_string(img.symbols().size()) + ")");
            ins_sym_p.item.pszText = const_cast<LPWSTR>(wsym_p.c_str());
            ins_sym_p.item.lParam = reinterpret_cast<LPARAM>(sym_parent.get());
            HTREEITEM hExports = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ins_sym_p)));
            tree_items_.push_back(std::move(sym_parent));

            std::size_t sym_limit = std::min<std::size_t>(img.symbols().size(), 100);
            for (std::size_t i = 0; i < sym_limit; ++i) {
                const auto& s = img.symbols()[i];
                auto s_item = std::make_unique<TreeItemInfo>();
                s_item->title = "Export " + s.name;
                s_item->category = "Export";
                s_item->va = s.address;
                s_item->size = static_cast<std::size_t>(s.size);

                std::ostringstream s_det;
                s_det << "Exported Symbol: " << s.name << "\n"
                      << "================================================================================\n"
                      << "Address: 0x" << std::hex << s.address << "\n"
                      << "Size:    " << std::dec << s.size << " bytes\n";
                auto it_code = decompile_map.find(s.address);
                if (it_code != decompile_map.end()) {
                    s_det << "\nDecompiled Pseudocode:\n"
                          << "--------------------------------------------------------------------------------\n"
                          << it_code->second << "\n";
                }
                s_item->content = s_det.str();
                s_item->status_info = s.name + " [0x" + to_wide_hex(s.address) + "]";

                TVINSERTSTRUCTW exp_ins = {};
                exp_ins.hParent = hExports;
                exp_ins.hInsertAfter = TVI_LAST;
                exp_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                std::string exp_lbl = s.name + " [0x" + to_wide_hex(s.address) + "]";
                std::wstring wexp_lbl = to_wide(exp_lbl);
                exp_ins.item.pszText = const_cast<LPWSTR>(wexp_lbl.c_str());
                exp_ins.item.lParam = reinterpret_cast<LPARAM>(s_item.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&exp_ins));
                tree_items_.push_back(std::move(s_item));
            }
        }
    }

    // 2. VM Architecture & Handlers (VMProtect / Themida)
    if (vm_report_.is_virtualized) {
        auto vm_parent = std::make_unique<TreeItemInfo>();
        vm_parent->title = "VM Virtualization: " + vm_report_.detected_protector;
        vm_parent->category = "VirtualMachine";
        vm_parent->content = vm::VmProfiler::format_report(vm_report_);
        vm_parent->status_info = vm_report_.detected_protector + " (" + std::to_string(vm_report_.total_handlers) + " handlers)";

        TVINSERTSTRUCTW ins_vm = {};
        ins_vm.hParent = hRoot;
        ins_vm.hInsertAfter = TVI_LAST;
        ins_vm.item.mask = TVIF_TEXT | TVIF_PARAM;
        std::wstring wvm = to_wide("VM Virtualization: " + vm_report_.detected_protector);
        ins_vm.item.pszText = const_cast<LPWSTR>(wvm.c_str());
        ins_vm.item.lParam = reinterpret_cast<LPARAM>(vm_parent.get());
        HTREEITEM hVm = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ins_vm)));
        tree_items_.push_back(std::move(vm_parent));

        for (std::size_t i = 0; i < vm_report_.vm_entries.size(); ++i) {
            const auto& e = vm_report_.vm_entries[i];
            auto entry_info = std::make_unique<TreeItemInfo>();
            entry_info->title = "VM Entry 0x" + to_wide_hex(e.entry_va);
            entry_info->category = "VMEntry";
            entry_info->va = e.entry_va;

            std::ostringstream ess;
            ess << "VM Entry Point: 0x" << std::hex << e.entry_va << "\n"
                << "================================================================================\n"
                << "Dispatcher VA:      0x" << std::hex << e.dispatcher_va << " (" << e.target_vm << ")\n"
                << "Identified Handlers:" << std::dec << e.identified_handlers.size() << "\n\n"
                << "Handler Table:\n";
            for (const auto& h : e.identified_handlers) {
                ess << "  - " << h.type << " [0x" << std::hex << h.address << "] (" << std::dec << h.size << " bytes)\n";
            }
            entry_info->content = ess.str();
            entry_info->status_info = "VM Entry 0x" + to_wide_hex(e.entry_va) + " (" + std::to_string(e.identified_handlers.size()) + " handlers)";

            std::ostringstream ss;
            ss << "VM Entry [0x" << std::hex << e.entry_va << "] Handlers (" << std::dec << e.identified_handlers.size() << ")";
            std::wstring we = to_wide(ss.str());
            TVINSERTSTRUCTW e_ins = {};
            e_ins.hParent = hVm;
            e_ins.hInsertAfter = TVI_LAST;
            e_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            e_ins.item.pszText = const_cast<LPWSTR>(we.c_str());
            e_ins.item.lParam = reinterpret_cast<LPARAM>(entry_info.get());
            HTREEITEM hEntry = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&e_ins)));
            tree_items_.push_back(std::move(entry_info));

            for (const auto& h : e.identified_handlers) {
                auto h_info = std::make_unique<TreeItemInfo>();
                h_info->title = h.type + " [0x" + to_wide_hex(h.address) + "]";
                h_info->category = "VMHandler";
                h_info->va = h.address;
                h_info->size = h.size;

                std::ostringstream h_det;
                h_det << "Virtual Machine Handler: " << h.type << "\n"
                      << "================================================================================\n"
                      << "Address:     0x" << std::hex << h.address << "\n"
                      << "Size:        " << std::dec << h.size << " bytes\n"
                      << "Semantics:   VM Virtual Machine Instruction Dispatch\n";
                h_info->content = h_det.str();
                h_info->status_info = h.type + " [0x" + to_wide_hex(h.address) + "]";

                std::ostringstream hss;
                hss << h.type << " [0x" << std::hex << h.address << "] (" << std::dec << h.size << " B)";
                std::wstring wh = to_wide(hss.str());
                TVINSERTSTRUCTW h_ins = {};
                h_ins.hParent = hEntry;
                h_ins.hInsertAfter = TVI_LAST;
                h_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                h_ins.item.pszText = const_cast<LPWSTR>(wh.c_str());
                h_ins.item.lParam = reinterpret_cast<LPARAM>(h_info.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&h_ins));
                tree_items_.push_back(std::move(h_info));
            }
        }
    }

    // 3. .NET Types & Namespaces
    if (dotnet_report_.is_dotnet) {
        std::map<std::string, std::vector<const dotnet::DotNetType*>> by_ns;
        for (const auto& t : dotnet_report_.types) by_ns[t.namespace_name].push_back(&t);

        for (const auto& [ns, types] : by_ns) {
            HTREEITEM hNs = hRoot;
            if (!ns.empty()) {
                std::wstring wns = to_wide("Namespace: " + ns);
                TVINSERTSTRUCTW ns_ins = {};
                ns_ins.hParent = hRoot;
                ns_ins.hInsertAfter = TVI_LAST;
                ns_ins.item.mask = TVIF_TEXT;
                ns_ins.item.pszText = const_cast<LPWSTR>(wns.c_str());
                hNs = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ns_ins)));
            }

            for (const auto* t : types) {
                auto t_info = std::make_unique<TreeItemInfo>();
                t_info->title = "class " + t->name;
                t_info->category = "DotNetType";

                std::ostringstream t_ss;
                t_ss << "// Decompiled .NET Type: " << t->namespace_name << "." << t->name << "\n"
                     << "public class " << t->name << " {\n";
                for (const auto& m : t->methods) {
                    t_ss << "    " << (m.is_public ? "public " : "private ")
                         << (m.is_static ? "static " : "")
                         << m.return_type << " " << m.name << "(";
                    for (std::size_t pi = 0; pi < m.parameters.size(); ++pi) {
                        if (pi > 0) t_ss << ", ";
                        t_ss << m.parameters[pi].type_name << " " << m.parameters[pi].name;
                    }
                    t_ss << ");\n";
                }
                t_ss << "}\n";
                t_info->content = t_ss.str();
                t_info->status_info = "class " + t->name + " (" + std::to_string(t->methods.size()) + " methods)";

                std::wstring wtname = to_wide("class " + t->name);
                TVINSERTSTRUCTW t_ins = {};
                t_ins.hParent = hNs;
                t_ins.hInsertAfter = TVI_LAST;
                t_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                t_ins.item.pszText = const_cast<LPWSTR>(wtname.c_str());
                t_ins.item.lParam = reinterpret_cast<LPARAM>(t_info.get());
                HTREEITEM hType = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&t_ins)));
                tree_items_.push_back(std::move(t_info));

                for (const auto& m : t->methods) {
                    auto m_info = std::make_unique<TreeItemInfo>();
                    m_info->title = t->name + "." + m.name + "()";
                    m_info->category = "DotNetMethod";

                    std::ostringstream m_ss;
                    char rva_buf[32];
                    std::snprintf(rva_buf, sizeof(rva_buf), "0x%08X", m.rva);
                    m_ss << "// Decompiled .NET Method: " << t->name << "." << m.name << "\n"
                         << "// Method RVA: " << rva_buf << "\n"
                         << (m.is_public ? "public " : (m.is_private ? "private " : ""))
                         << (m.is_static ? "static " : "")
                         << (m.is_virtual ? "virtual " : "")
                         << m.return_type << " " << m.name << "(";
                    for (std::size_t pi = 0; pi < m.parameters.size(); ++pi) {
                        if (pi > 0) m_ss << ", ";
                        m_ss << m.parameters[pi].type_name << " " << m.parameters[pi].name;
                    }
                    m_ss << ") {\n    // Method body at RVA " << rva_buf << "\n}\n";
                    m_info->content = m_ss.str();
                    m_info->status_info = m.name + "() : " + m.return_type;

                    std::string mdesc = m.name + "() : " + m.return_type;
                    std::wstring wmname = to_wide(mdesc);
                    TVINSERTSTRUCTW m_ins = {};
                    m_ins.hParent = hType;
                    m_ins.hInsertAfter = TVI_LAST;
                    m_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                    m_ins.item.pszText = const_cast<LPWSTR>(wmname.c_str());
                    m_ins.item.lParam = reinterpret_cast<LPARAM>(m_info.get());
                    SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&m_ins));
                    tree_items_.push_back(std::move(m_info));
                }
            }
        }
    }

    // 4. Delphi VCL Forms & Units
    if (delphi_report_.is_delphi) {
        auto delphi_info = std::make_unique<TreeItemInfo>();
        delphi_info->title = "Delphi VCL Architecture (" + delphi_report_.compiler_version + ")";
        delphi_info->category = "Delphi";
        delphi_info->content = delphi::DelphiAnalyzer::to_pascal_source(delphi_report_);
        delphi_info->status_info = "Delphi " + delphi_report_.compiler_version;

        std::wstring wdelphi = L"Delphi VCL Architecture (" + to_wide(delphi_report_.compiler_version) + L")";
        TVINSERTSTRUCTW d_ins = {};
        d_ins.hParent = hRoot;
        d_ins.hInsertAfter = TVI_LAST;
        d_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        d_ins.item.pszText = const_cast<LPWSTR>(wdelphi.c_str());
        d_ins.item.lParam = reinterpret_cast<LPARAM>(delphi_info.get());
        HTREEITEM hDelphi = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&d_ins)));
        tree_items_.push_back(std::move(delphi_info));

        for (const auto& form : delphi_report_.forms) {
            auto form_info = std::make_unique<TreeItemInfo>();
            form_info->title = "Form: " + form.form_name;
            form_info->category = "DelphiForm";
            std::ostringstream f_ss;
            f_ss << "type\n  " << form.class_name << " = class(TForm)\n";
            for (const auto& ev : form.root_component.events) {
                f_ss << "    procedure " << ev.handler_name << "(Sender: TObject);\n";
            }
            f_ss << "  end;\n";
            form_info->content = f_ss.str();
            form_info->status_info = form.form_name + " (" + form.class_name + ")";

            std::wstring wform = to_wide("Form: " + form.form_name + " (" + form.class_name + ")");
            TVINSERTSTRUCTW form_ins = {};
            form_ins.hParent = hDelphi;
            form_ins.hInsertAfter = TVI_LAST;
            form_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            form_ins.item.pszText = const_cast<LPWSTR>(wform.c_str());
            form_ins.item.lParam = reinterpret_cast<LPARAM>(form_info.get());
            HTREEITEM hForm = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&form_ins)));
            tree_items_.push_back(std::move(form_info));

            for (const auto& ev : form.root_component.events) {
                auto ev_info = std::make_unique<TreeItemInfo>();
                ev_info->title = ev.event_name + " -> " + ev.handler_name;
                ev_info->category = "DelphiEvent";
                ev_info->va = ev.handler_va;

                std::ostringstream ev_ss;
                ev_ss << "procedure " << form.class_name << "." << ev.handler_name << "(Sender: TObject);\n"
                      << "begin\n  // Event: " << ev.event_name << "\n  // Handler VA: 0x" << std::hex << ev.handler_va << "\nend;\n";
                ev_info->content = ev_ss.str();
                ev_info->status_info = ev.handler_name + " [0x" + to_wide_hex(ev.handler_va) + "]";

                std::ostringstream ss;
                ss << ev.event_name << " -> " << ev.handler_name << " [VA: 0x" << std::hex << ev.handler_va << "]";
                std::wstring wev = to_wide(ss.str());
                TVINSERTSTRUCTW ev_ins = {};
                ev_ins.hParent = hForm;
                ev_ins.hInsertAfter = TVI_LAST;
                ev_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                ev_ins.item.pszText = const_cast<LPWSTR>(wev.c_str());
                ev_ins.item.lParam = reinterpret_cast<LPARAM>(ev_info.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ev_ins));
                tree_items_.push_back(std::move(ev_info));
            }
        }
    }

    // 5. Android Dalvik DEX Classes
    if (dex_report_.is_dex) {
        auto dex_info = std::make_unique<TreeItemInfo>();
        dex_info->title = "Dalvik DEX (" + std::to_string(dex_report_.classes.size()) + " classes)";
        dex_info->category = "DEX";
        dex_info->content = dex::DexAnalyzer::to_java_source(dex_report_);
        dex_info->status_info = "Dalvik DEX v" + dex_report_.version;

        std::wstring wdex = L"Dalvik DEX Packages (" + std::to_wstring(dex_report_.classes.size()) + L" classes)";
        TVINSERTSTRUCTW dex_ins = {};
        dex_ins.hParent = hRoot;
        dex_ins.hInsertAfter = TVI_LAST;
        dex_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        dex_ins.item.pszText = const_cast<LPWSTR>(wdex.c_str());
        dex_ins.item.lParam = reinterpret_cast<LPARAM>(dex_info.get());
        HTREEITEM hDex = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&dex_ins)));
        tree_items_.push_back(std::move(dex_info));

        for (const auto& cls : dex_report_.classes) {
            auto cls_info = std::make_unique<TreeItemInfo>();
            cls_info->title = "class " + cls.name;
            cls_info->category = "DexClass";
            cls_info->content = "// Dalvik class " + cls.name + "\npublic class " + cls.name + " {\n}\n";
            cls_info->status_info = cls.name + " (" + std::to_string(cls.methods.size()) + " methods)";

            std::wstring wcls = to_wide(cls.name);
            TVINSERTSTRUCTW c_ins = {};
            c_ins.hParent = hDex;
            c_ins.hInsertAfter = TVI_LAST;
            c_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            c_ins.item.pszText = const_cast<LPWSTR>(wcls.c_str());
            c_ins.item.lParam = reinterpret_cast<LPARAM>(cls_info.get());
            HTREEITEM hC = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&c_ins)));
            tree_items_.push_back(std::move(cls_info));

            for (const auto& m : cls.methods) {
                auto m_info = std::make_unique<TreeItemInfo>();
                m_info->title = cls.name + "." + m.name;
                m_info->category = "DexMethod";

                std::ostringstream dm_ss;
                dm_ss << "// Method: " << cls.name << "." << m.name << "\n";
                if (!m.decompiled_java.empty()) {
                    dm_ss << m.decompiled_java << "\n";
                } else {
                    dm_ss << "public " << m.return_type << " " << m.name << "() {\n";
                    for (const auto& insn : m.instructions) {
                        dm_ss << "    " << insn << "\n";
                    }
                    dm_ss << "}\n";
                }
                m_info->content = dm_ss.str();
                m_info->status_info = m.name + " (" + std::to_string(m.instructions.size()) + " insns)";

                std::wstring wm = to_wide(m.name + " (" + std::to_string(m.instructions.size()) + " insns)");
                TVINSERTSTRUCTW m_ins = {};
                m_ins.hParent = hC;
                m_ins.hInsertAfter = TVI_LAST;
                m_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                m_ins.item.pszText = const_cast<LPWSTR>(wm.c_str());
                m_ins.item.lParam = reinterpret_cast<LPARAM>(m_info.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&m_ins));
                tree_items_.push_back(std::move(m_info));
            }
        }
    }

    // 6. Visual Basic 5/6 Forms & Events
    if (vb_report_.is_vb) {
        auto vb_info = std::make_unique<TreeItemInfo>();
        vb_info->title = "VB6 Project";
        vb_info->category = "VB6";
        vb_info->content = vb::VbAnalyzer::to_vb_source(vb_report_);
        vb_info->status_info = vb_report_.is_pcode ? "VB6 P-Code" : "VB6 Native";

        std::string mode_str = vb_report_.is_pcode ? "P-Code" : "Native Code";
        std::wstring wvb = to_wide("VB6 Project (" + mode_str + ")");
        TVINSERTSTRUCTW vb_ins = {};
        vb_ins.hParent = hRoot;
        vb_ins.hInsertAfter = TVI_LAST;
        vb_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        vb_ins.item.pszText = const_cast<LPWSTR>(wvb.c_str());
        vb_ins.item.lParam = reinterpret_cast<LPARAM>(vb_info.get());
        HTREEITEM hVb = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&vb_ins)));
        tree_items_.push_back(std::move(vb_info));

        for (const auto& mod : vb_report_.modules) {
            auto mod_info = std::make_unique<TreeItemInfo>();
            mod_info->title = mod.name;
            mod_info->category = "VBModule";
            mod_info->content = "' VB Module: " + mod.name + " (" + mod.kind + ")\n";
            mod_info->status_info = mod.name;

            std::wstring wmod = to_wide(mod.kind + ": " + mod.name);
            TVINSERTSTRUCTW mod_ins = {};
            mod_ins.hParent = hVb;
            mod_ins.hInsertAfter = TVI_LAST;
            mod_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            mod_ins.item.pszText = const_cast<LPWSTR>(wmod.c_str());
            mod_ins.item.lParam = reinterpret_cast<LPARAM>(mod_info.get());
            HTREEITEM hMod = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&mod_ins)));
            tree_items_.push_back(std::move(mod_info));

            for (const auto& ev : mod.events) {
                auto ev_info = std::make_unique<TreeItemInfo>();
                ev_info->title = ev.object_name + "_" + ev.event_name;
                ev_info->category = "VBEvent";
                ev_info->va = ev.code_va;
                ev_info->content = "Private Sub " + ev.object_name + "_" + ev.event_name + "()\n    ' Event handler VA: 0x" + to_wide_hex(ev.code_va) + "\nEnd Sub\n";
                ev_info->status_info = ev.object_name + "_" + ev.event_name + " [0x" + to_wide_hex(ev.code_va) + "]";

                std::ostringstream ss;
                ss << ev.object_name << "_" << ev.event_name << " [VA: 0x" << std::hex << ev.code_va << "]";
                std::wstring wev = to_wide(ss.str());
                TVINSERTSTRUCTW ev_ins = {};
                ev_ins.hParent = hMod;
                ev_ins.hInsertAfter = TVI_LAST;
                ev_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                ev_ins.item.pszText = const_cast<LPWSTR>(wev.c_str());
                ev_ins.item.lParam = reinterpret_cast<LPARAM>(ev_info.get());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ev_ins));
                tree_items_.push_back(std::move(ev_info));
            }
        }
    }

    // 7. Go Runtime & pclntab
    if (go_report_.detected) {
        auto go_info = std::make_unique<TreeItemInfo>();
        go_info->title = "Go Runtime";
        go_info->category = "Go";
        go_info->content = go_report_.golang_source.empty() ? golang::GoAnalyzer::to_golang_source(go_report_) : go_report_.golang_source;
        go_info->status_info = "Go " + std::string(golang::to_string(go_report_.version));

        std::wstring wgo = to_wide("Go Runtime (" + std::string(golang::to_string(go_report_.version)) + ")");
        TVINSERTSTRUCTW go_ins = {};
        go_ins.hParent = hRoot;
        go_ins.hInsertAfter = TVI_LAST;
        go_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        go_ins.item.pszText = const_cast<LPWSTR>(wgo.c_str());
        go_ins.item.lParam = reinterpret_cast<LPARAM>(go_info.get());
        HTREEITEM hGo = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&go_ins)));
        tree_items_.push_back(std::move(go_info));

        for (const auto& s : go_report_.structs) {
            auto s_info = std::make_unique<TreeItemInfo>();
            s_info->title = "type " + s.name + " struct";
            s_info->category = "GoStruct";
            std::ostringstream s_ss;
            s_ss << "type " << s.name << " struct {\n";
            for (const auto& f : s.fields) {
                s_ss << "    " << f.name << " " << f.type_name << "\n";
            }
            s_ss << "}\n";
            s_info->content = s_ss.str();
            s_info->status_info = "struct " + s.name;

            std::wstring ws = to_wide("type " + s.name + " struct");
            TVINSERTSTRUCTW s_ins = {};
            s_ins.hParent = hGo;
            s_ins.hInsertAfter = TVI_LAST;
            s_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            s_ins.item.pszText = const_cast<LPWSTR>(ws.c_str());
            s_ins.item.lParam = reinterpret_cast<LPARAM>(s_info.get());
            SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&s_ins));
            tree_items_.push_back(std::move(s_info));
        }

        for (std::size_t i = 0; i < std::min<std::size_t>(go_report_.functions.size(), 50); ++i) {
            const auto& fn = go_report_.functions[i];
            auto f_info = std::make_unique<TreeItemInfo>();
            f_info->title = "func " + fn.name;
            f_info->category = "GoFunc";
            f_info->va = fn.entry_va;
            f_info->content = "func " + fn.name + "() {\n    // VA: 0x" + to_wide_hex(fn.entry_va) + "\n}\n";
            f_info->status_info = fn.name + " [0x" + to_wide_hex(fn.entry_va) + "]";

            std::wstring wf = to_wide("func " + fn.name);
            TVINSERTSTRUCTW f_ins = {};
            f_ins.hParent = hGo;
            f_ins.hInsertAfter = TVI_LAST;
            f_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
            f_ins.item.pszText = const_cast<LPWSTR>(wf.c_str());
            f_ins.item.lParam = reinterpret_cast<LPARAM>(f_info.get());
            SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&f_ins));
            tree_items_.push_back(std::move(f_info));
        }
    }

    // 8. Lua Bytecode Functions
    if (lua_report_.is_lua_bytecode) {
        auto lua_info = std::make_unique<TreeItemInfo>();
        lua_info->title = "Lua Bytecode";
        lua_info->category = "Lua";
        lua_info->content = lua_report_.lua_source.empty() ? lua::LuaDecompiler::to_lua_source(lua_report_) : lua_report_.lua_source;
        lua_info->status_info = "Lua " + std::string(lua::to_string(lua_report_.flavor));

        std::wstring wlua = to_wide("Lua Bytecode (" + std::string(lua::to_string(lua_report_.flavor)) + ")");
        TVINSERTSTRUCTW lua_ins = {};
        lua_ins.hParent = hRoot;
        lua_ins.hInsertAfter = TVI_LAST;
        lua_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        lua_ins.item.pszText = const_cast<LPWSTR>(wlua.c_str());
        lua_ins.item.lParam = reinterpret_cast<LPARAM>(lua_info.get());
        HTREEITEM hLua = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&lua_ins)));
        tree_items_.push_back(std::move(lua_info));

        auto r_info = std::make_unique<TreeItemInfo>();
        r_info->title = "main (root chunk)";
        r_info->category = "LuaChunk";
        r_info->content = lua::LuaDecompiler::to_lua_source(lua_report_);
        r_info->status_info = "main root chunk (" + std::to_string(lua_report_.root_function.instructions.size()) + " insns)";

        std::wstring wr = to_wide("main (root chunk) [" + std::to_string(lua_report_.root_function.instructions.size()) + " insns]");
        TVINSERTSTRUCTW r_ins = {};
        r_ins.hParent = hLua;
        r_ins.hInsertAfter = TVI_LAST;
        r_ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        r_ins.item.pszText = const_cast<LPWSTR>(wr.c_str());
        r_ins.item.lParam = reinterpret_cast<LPARAM>(r_info.get());
        SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&r_ins));
        tree_items_.push_back(std::move(r_info));
    }

    SendMessageW(g_hwndTree, TVM_EXPAND, TVE_EXPAND, reinterpret_cast<LPARAM>(hRoot));
    SendMessageW(g_hwndTree, TVM_SELECTITEM, TVGN_CARET, reinterpret_cast<LPARAM>(hRoot));
}

void StudioApp::open_file(const std::string& path) {
    current_file_ = path;
    is_deobfuscated_ = false;

    auto view = core::BinaryView::open(path);
    if (!view) {
        LogMessage("[Error] Failed to open binary file: " + path);
        return;
    }

    const auto& v = view.value();

    // 1. Run detectors across all subsystems
    dotnet::DotNetAnalyzer dotnet_an;
    dotnet_report_ = dotnet_an.analyze_view(v);

    delphi_report_ = delphi::DelphiAnalyzer::analyze(v);
    dex_report_    = dex::DexAnalyzer::analyze(v);
    vb_report_     = vb::VbAnalyzer::analyze(v);
    autoit_report_ = autoit::AutoItDecompiler::analyze(v);
    lua_report_    = lua::LuaDecompiler{}.decompile(v);
    vfs_report_    = unpack::VfsExtractor::analyze(v);
    unpack_target_ = unpack::UniversalUnpacker::detect(v);
    vm_report_     = vm::VmProfiler::analyze(v);

    detect::DetectorEngine engine;
    auto img_res_det = core::ExecutableImage::parse(v);
    detect_result_ = img_res_det ? engine.detect(img_res_det.value()) : engine.detect_view(v);

    golang::GoAnalyzer go_an;
    go_report_ = img_res_det ? go_an.analyze(img_res_det.value()) : go_an.analyze_view(v);

    // 2. Populate complete navigation tree & decompilers
    populate_tree(v);

    std::string filename = path;
    auto last_slash = filename.find_last_of("\\/");
    if (last_slash != std::string::npos) filename = filename.substr(last_slash + 1);

    if (dotnet_report_.is_dotnet) {
        dotnet_report_.csharp_source = dotnet::DotNetAnalyzer::to_csharp(dotnet_report_);
        set_mode(DecompilerMode::csharp);
        SetStatusBarText(1, "Runtime: " + dotnet_report_.runtime_version);
        SetStatusBarText(2, "Types: " + std::to_string(dotnet_report_.types.size()) +
                            " | Methods: " + std::to_string(dotnet_report_.method_count));
    } else if (delphi_report_.is_delphi) {
        set_mode(DecompilerMode::delphi_pascal);
        SetStatusBarText(1, "Delphi: " + delphi_report_.compiler_version);
        SetStatusBarText(2, "Forms: " + std::to_string(delphi_report_.forms.size()));
    } else if (dex_report_.is_dex) {
        set_mode(DecompilerMode::dex_java);
        SetStatusBarText(1, "Dalvik DEX: v" + dex_report_.version);
        SetStatusBarText(2, "Classes: " + std::to_string(dex_report_.classes.size()));
    } else if (vb_report_.is_vb) {
        set_mode(DecompilerMode::vb_source);
        SetStatusBarText(1, "VB: " + (vb_report_.is_pcode ? std::string("P-Code") : std::string("Native")));
        SetStatusBarText(2, "Modules: " + std::to_string(vb_report_.modules.size()));
    } else if (autoit_report_.is_autoit) {
        set_mode(DecompilerMode::autoit_script);
        SetStatusBarText(1, "AutoIt: " + autoit_report_.version);
        SetStatusBarText(2, "Payload: " + std::to_string(autoit_report_.primary_script.size()) + " B");
    } else if (lua_report_.is_lua_bytecode) {
        set_mode(DecompilerMode::lua_source);
        SetStatusBarText(1, "Lua Bytecode: " + std::string(lua::to_string(lua_report_.flavor)));
        SetStatusBarText(2, "Functions: " + std::to_string(lua_report_.total_functions));
    } else if (go_report_.detected) {
        set_mode(DecompilerMode::go_source);
        SetStatusBarText(1, "Go Runtime: " + std::string(golang::to_string(go_report_.version)));
        SetStatusBarText(2, "Functions: " + std::to_string(go_report_.functions.size()));
    } else if (vm_report_.is_virtualized) {
        set_mode(DecompilerMode::vm_profile);
        SetStatusBarText(1, "Virtual Machine: " + vm_report_.detected_protector);
        SetStatusBarText(2, "Handlers: " + std::to_string(vm_report_.total_handlers));
    } else {
        // Native PE / ELF / Mach-O binary -> Native C pseudocode
        set_mode(DecompilerMode::c_source);
        SetStatusBarText(1, "Native Binary: " + (img_res_det ? img_res_det->format_name() : "Raw"));
        SetStatusBarText(2, "Size: " + std::to_string(v.size()) + " B");
    }

    SetStatusBarText(0, "Loaded: " + filename);
    LogMessage("[TypeMorph] Successfully loaded: " + filename);
    if (!detect_result_.primary_compiler.empty()) {
        LogMessage("[DetectItEasy] Identified: " + detect_result_.primary_compiler +
                   (!detect_result_.primary_packer.empty() && detect_result_.primary_packer != "None (Not packed)" ? (" [" + detect_result_.primary_packer + "]") : ""));
    }
}

void StudioApp::set_mode(DecompilerMode mode) {
    mode_ = mode;
    if (current_file_.empty()) return;

    auto view = core::BinaryView::open(current_file_);
    if (!view) return;
    const auto& v = view.value();

    std::string text_output;
    switch (mode) {
    case DecompilerMode::csharp:
        if (dotnet_report_.is_dotnet) {
            text_output = is_deobfuscated_ ? dotnet_deobf_report_.clean_csharp_source : dotnet_report_.csharp_source;
        } else {
            text_output = "// Not a .NET assembly.";
        }
        break;

    case DecompilerMode::c_source: {
        auto img_res = core::ExecutableImage::parse(v);
        if (img_res) {
            decompile::CDecompiler decompiler;
            auto rep = decompiler.decompile(img_res.value(), std::nullopt);
            text_output = rep.combined_source.empty() ? "// No decompiled functions recovered." : rep.combined_source;
        } else {
            text_output = "// Executable image parsing failed: raw view only.";
        }
        break;
    }

    case DecompilerMode::rust_source: {
        auto img_res = core::ExecutableImage::parse(v);
        if (img_res) {
            derust::RustSourceReconstructor reconstructor;
            auto rep = reconstructor.reconstruct(img_res.value());
            text_output = derust::RustSourceReconstructor::to_rust_source(rep);
        } else {
            text_output = "// Not a recognized ELF/PE/Mach-O binary.";
        }
        break;
    }

    case DecompilerMode::dex_java:
        if (dex_report_.is_dex) {
            text_output = dex::DexAnalyzer::to_java_source(dex_report_);
        } else {
            text_output = "// Not a Dalvik DEX file.";
        }
        break;

    case DecompilerMode::delphi_pascal:
        if (delphi_report_.is_delphi) {
            text_output = delphi::DelphiAnalyzer::to_pascal_source(delphi_report_);
        } else {
            text_output = "// Not a Delphi / C++Builder executable.";
        }
        break;

    case DecompilerMode::vb_source:
        if (vb_report_.is_vb) {
            text_output = vb::VbAnalyzer::to_vb_source(vb_report_);
        } else {
            text_output = "// Not a Visual Basic 5/6 binary.";
        }
        break;

    case DecompilerMode::autoit_script:
        if (autoit_report_.is_autoit) {
            text_output = autoit_report_.primary_script;
        } else {
            text_output = "// Not an AutoIt v3 compiled executable.";
        }
        break;

    case DecompilerMode::vm_profile:
        text_output = vm::VmProfiler::format_report(vm_report_);
        break;

    case DecompilerMode::unpack_summary:
        text_output = unpack::UniversalUnpacker::format_report(unpack_target_);
        break;

    case DecompilerMode::vfs_summary:
        text_output = unpack::VfsExtractor::format_report(vfs_report_);
        break;

    case DecompilerMode::go_source:
        if (go_report_.detected) {
            text_output = go_report_.golang_source.empty() ? golang::GoAnalyzer::to_golang_source(go_report_) : go_report_.golang_source;
        } else {
            text_output = "// No Go runtime metadata or pclntab detected.";
        }
        break;

    case DecompilerMode::lua_source:
        if (lua_report_.is_lua_bytecode) {
            text_output = lua_report_.lua_source.empty() ? lua::LuaDecompiler::to_lua_source(lua_report_) : lua_report_.lua_source;
        } else {
            text_output = "// Not a Lua or LuaJIT bytecode file.";
        }
        break;

    case DecompilerMode::raw_disasm:
        text_output = "// Disassembly view";
        break;
    }

    std::wstring crlf = normalize_crlf(text_output);
    SetWindowTextW(g_hwndCode, crlf.c_str());
}

void StudioApp::deobfuscate_current() {
    if (current_file_.empty() || !dotnet_report_.is_dotnet) {
        LogMessage("[Error] No valid .NET assembly loaded to deobfuscate.");
        return;
    }

    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    dotnet::DotNetDeobfuscator deobfuscator;
    dotnet_deobf_report_ = deobfuscator.deobfuscate_view(view.value());
    is_deobfuscated_ = true;

    set_mode(DecompilerMode::csharp);

    LogMessage("[Deobfuscation] --- Deobfuscation Complete ---");
    LogMessage("[Deobfuscation] Protector: " + std::string(to_string(dotnet_deobf_report_.detected_protector)));
    LogMessage("[Deobfuscation] Inlined Proxy Calls: " + std::to_string(dotnet_deobf_report_.total_proxies_inlined));
    LogMessage("[Deobfuscation] Decrypted Strings: " + std::to_string(dotnet_deobf_report_.total_strings_decrypted));
    LogMessage("[Deobfuscation] Flattened Switch Blocks: " + std::to_string(dotnet_deobf_report_.total_switches_killed));

    SetStatusBarText(1, "Deobfuscated: " + std::string(to_string(dotnet_deobf_report_.detected_protector)));
}

void StudioApp::run_detection() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    detect::DetectorEngine engine;
    auto img = core::ExecutableImage::parse(view.value());
    detect_result_ = img ? engine.detect(img.value()) : engine.detect_view(view.value());

    std::string report = detect::DetectorEngine::to_text_summary(detect_result_);
    SetWindowTextW(g_hwndCode, normalize_crlf(report).c_str());
    LogMessage("[DetectItEasy] Identified: " + detect_result_.primary_compiler + " (" + detect_result_.primary_packer + ")");
}

void StudioApp::run_vm_analysis() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    vm_report_ = vm::VmProfiler::analyze(view.value());
    set_mode(DecompilerMode::vm_profile);
    LogMessage("[VMProfiler] Protector: " + vm_report_.detected_protector +
               " | Handlers: " + std::to_string(vm_report_.total_handlers));
}

void StudioApp::run_unpack() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    unpack_target_ = unpack::UniversalUnpacker::detect(view.value());
    set_mode(DecompilerMode::unpack_summary);
    LogMessage("[Unpacker] Packer: " + unpack_target_.packer_name +
               " | OEP: 0x" + std::to_string(unpack_target_.recovered_oep_va));
}

void StudioApp::run_vfs_extract() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    vfs_report_ = unpack::VfsExtractor::analyze(view.value());
    set_mode(DecompilerMode::vfs_summary);
    LogMessage("[VFS Extractor] Container: " + vfs_report_.container_type +
               " | Files: " + std::to_string(vfs_report_.files.size()));
}

void StudioApp::run_iat_fix() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    pe::IatReconstructionOptions opts;
    pe::IatReconstructor reconstructor(opts);
    auto rep = reconstructor.analyze(view.value());

    std::string report = pe::IatReconstructor::to_text_summary(rep);
    SetWindowTextW(g_hwndCode, normalize_crlf(report).c_str());
    LogMessage("[IAT Reconstructor] Discovered " + std::to_string(rep.total_functions) + " API calls.");
}

void StudioApp::run_memdump_fix() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    auto rep = dump::DumpFixer::analyze(view.value());
    std::string report = dump::DumpFixer::format_report(rep);
    SetWindowTextW(g_hwndCode, normalize_crlf(report).c_str());
    LogMessage("[Memory Dump Fixer] Source: " + rep.detected_source + " | Sections: " + std::to_string(rep.sections.size()));
}

void StudioApp::run_checksec() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    security::SecurityAnalyzer analyzer;
    auto report = analyzer.analyze_view(view.value());

    std::ostringstream out;
    char ep_buf[32];
    std::snprintf(ep_buf, sizeof(ep_buf), "0x%llx", static_cast<unsigned long long>(report.entry_point));

    out << "TypeMorph Binary Hardening & Security Inspector (checksec)\n"
        << "=========================================================\n"
        << "  Target:      " << current_file_ << " (" << core::to_string(report.format) << ", " << report.bits << "-bit)\n"
        << "  Entry Point: " << ep_buf
        << (report.entry_point_outside_code ? " [WARNING: Outside code section!]" : " [Code section]") << "\n\n";

    out << "Mitigations & Protections:\n";
    const auto& m = report.mitigations;
    out << "  ASLR:                  " << (m.aslr ? "Enabled" : "Disabled") << "\n";
    out << "  High-Entropy VA:       " << (m.high_entropy_va ? "Enabled" : "Disabled") << "\n";
    out << "  DEP / NX:              " << (m.dep_nx ? "Enabled" : "Disabled") << "\n";
    out << "  Control Flow Guard:    " << (m.cfg ? "Enabled" : "Disabled") << "\n";
    out << "  CET Shadow Stack:      " << (m.cet_shadow_stack ? "Enabled" : "Disabled") << "\n";
    if (report.format == core::ImageFormat::pe) {
        out << "  SafeSEH:               " << (m.safe_seh ? "Enabled" : "Disabled / N/A") << "\n";
        out << "  Authenticode Signed:   " << (m.signed_binary ? "Signed" : "No signature") << "\n";
        out << "  TLS Callbacks:         " << (report.has_tls_callbacks ? "Present" : "None") << "\n";
    } else {
        out << "  PIE:                   " << (m.pie ? "Enabled" : "Disabled") << "\n";
        out << "  RELRO:                 " << (m.relro ? "Enabled" : "Disabled") << "\n";
        out << "  Stack Canary:          " << (m.stack_canary ? "Found" : "Not detected") << "\n";
    }

    out << "\nPackers & Protections Detected:\n";
    if (report.packers.empty()) {
        out << "  None detected (standard compiler output)\n";
    } else {
        for (const auto& p : report.packers) {
            out << "  - " << p.name << " (confidence "
                << std::fixed << std::setprecision(1) << (p.confidence * 100.0) << "%): "
                << p.rationale << "\n";
        }
    }

    out << "\nSection Anomalies:\n";
    if (report.section_anomalies.empty()) {
        out << "  None (W^X respected, normal section ratios)\n";
    } else {
        for (const auto& a : report.section_anomalies) {
            out << "  - Section '" << a.name << "': " << a.note;
            if (a.is_wx) out << " [W^X VIOLATION]";
            out << "\n";
        }
    }

    out << "\nOverlay Data:\n";
    if (!report.overlay.present) {
        out << "  None\n";
    } else {
        char ov_buf[32];
        std::snprintf(ov_buf, sizeof(ov_buf), "0x%llx", static_cast<unsigned long long>(report.overlay.offset));
        out << "  Present at offset " << ov_buf << " (" << report.overlay.size << " bytes, entropy: "
            << std::fixed << std::setprecision(2) << report.overlay.entropy << " - "
            << core::entropy_label(report.overlay.entropy) << ")\n";
    }

    out << "\nAnti-Analysis & Evasion Indicators:\n";
    if (report.anti_analysis_indicators.empty()) {
        out << "  None detected\n";
    } else {
        for (const auto& ind : report.anti_analysis_indicators) {
            out << "  - " << ind << "\n";
        }
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[checksec] Analysis complete for " + current_file_);
}

void StudioApp::run_rich_header() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    pe::RichHeaderParser parser;
    auto rep = parser.parse(view.value());

    std::ostringstream out;
    out << "TypeMorph MSVC Rich Header & Compiler Fingerprinter\n"
        << "===================================================\n"
        << "  Target: " << current_file_ << "\n";

    if (!rep.present) {
        out << "  No MSVC Rich header present (binary not built with MSVC or stripped).\n";
    } else {
        char key_buf[32], off_buf[32];
        std::snprintf(key_buf, sizeof(key_buf), "0x%08X", rep.xor_key);
        std::snprintf(off_buf, sizeof(off_buf), "0x%llx", static_cast<unsigned long long>(rep.offset));

        out << "  Offset:      " << off_buf << " (" << rep.size << " bytes)\n"
            << "  XOR Key:     " << key_buf << "\n"
            << "  Checksum:    0x" << std::hex << std::uppercase << rep.checksum << std::dec << "\n"
            << "  RichPE Hash: " << rep.hash << "\n\n";

        if (!rep.compiler_versions.empty()) {
            out << "Compilers / Toolsets Identified:\n";
            for (const auto& vs : rep.compiler_versions) {
                out << "  - " << vs << "\n";
            }
            out << "\n";
        }

        out << "Decoded Tool Records (" << rep.records.size() << "):\n";
        for (const auto& rec : rep.records) {
            char comp_buf[32];
            std::snprintf(comp_buf, sizeof(comp_buf), "0x%04X", rec.tool_id);
            out << "  [" << comp_buf << "] " << rec.tool_name << " (Build " << rec.build_number
                << "): " << rec.count << " artifact(s) [" << rec.vs_version << "]\n";
        }
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[Rich Header] Parsed " + std::to_string(rep.records.size()) + " compiler records.");
}

void StudioApp::run_abi_classifier() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    auto image_res = core::ExecutableImage::parse(view.value());
    if (!image_res) {
        LogMessage("[ABI Classifier] Executable format not recognized.");
        return;
    }

    abi::AbiClassifier classifier;
    auto rep = classifier.analyze(image_res.value(), std::nullopt);

    std::ostringstream out;
    out << "TypeMorph Calling Convention & ABI Classifier\n"
        << "=============================================\n"
        << "  Target: " << current_file_ << "\n"
        << "  Functions Analyzed: " << rep.total_functions << "\n\n";

    if (!rep.convention_distribution.empty()) {
        out << "Calling Convention Distribution:\n";
        for (const auto& [conv, count] : rep.convention_distribution) {
            double pct = (rep.total_functions > 0) ? (100.0 * static_cast<double>(count) / static_cast<double>(rep.total_functions)) : 0.0;
            out << "  - " << std::left << std::setw(16) << conv << ": " << count
                << " (" << std::fixed << std::setprecision(1) << pct << "%)\n";
        }
        out << "\n";
    }

    out << "Recovered Function Signatures (" << rep.signatures.size() << "):\n";
    std::size_t limit = std::min<std::size_t>(rep.signatures.size(), 80);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& sig = rep.signatures[i];
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llx", static_cast<unsigned long long>(sig.entry_va));
        out << "  [" << va_buf << "] " << sig.prototype << "\n"
            << "     Convention: " << to_string(sig.convention)
            << " | Frame: " << sig.stack_frame_size << "B";
        if (sig.stack_purge_bytes > 0) {
            out << " | Purge: " << sig.stack_purge_bytes << "B";
        }
        out << " | " << sig.rationale << "\n";
    }
    if (rep.signatures.size() > limit) {
        out << "  ... and " << (rep.signatures.size() - limit) << " more signatures.\n";
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[ABI Classifier] Classified " + std::to_string(rep.total_functions) + " functions.");
}

void StudioApp::run_crypto_scanner() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    crypto::CryptoScanOptions opts;
    crypto::CryptoScanner scanner(opts);
    auto matches = scanner.scan(view.value());

    std::ostringstream out;
    out << "TypeMorph Cryptographic & Hashing Constant Scanner\n"
        << "=================================================\n"
        << "Target: " << current_file_ << " (" << view.value().size() << " bytes)\n";
    if (matches.empty()) {
        out << "No known cryptographic constants detected.\n";
    } else {
        out << "Found " << matches.size() << " cryptographic constant(s):\n";
        out << "--------------------------------------------------------------------------------\n";
        out << "Offset      Algorithm           Role                      Category   Endian\n";
        out << "--------------------------------------------------------------------------------\n";
        for (const auto& m : matches) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%08llx", static_cast<unsigned long long>(m.offset));
            out << buf << "  "
                << std::left << std::setw(18) << m.algorithm.substr(0, 18) << "  "
                << std::setw(24) << m.role.substr(0, 24) << "  "
                << std::setw(10) << std::string(crypto::to_string(m.category)) << " "
                << m.endianness << "\n"
                << "            -> " << m.description << "\n";
        }
        out << "--------------------------------------------------------------------------------\n";
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[Crypto Scanner] Found " + std::to_string(matches.size()) + " cryptographic constants.");
}

void StudioApp::run_aes_recovery() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    crypto::AesKeyRecoveryEngine engine;
    auto rep = engine.analyze(view.value());

    std::string report = crypto::AesKeyRecoveryEngine::to_text_report(rep);
    SetWindowTextW(g_hwndCode, normalize_crlf(report).c_str());
    LogMessage("[AES Recovery] Keys recovered: " + std::to_string(rep.recovered_keys.size()) +
               " | White-box tables: " + std::to_string(rep.whitebox_tables.size()));
}

void StudioApp::run_entropy_analysis() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    const auto& v = view.value();
    std::size_t block_size = 256;
    if (v.size() > 1024 * 1024) block_size = 1024;
    if (v.size() > 16 * 1024 * 1024) block_size = 4096;

    auto blocks_res = core::block_entropy(v.bytes(), block_size);
    if (!blocks_res) return;
    const auto& blocks = blocks_res.value();
    const double total_entropy = core::shannon_entropy(v.bytes());

    double min_ent = 8.0, max_ent = 0.0, sum_ent = 0.0;
    for (double ent : blocks) {
        min_ent = std::min(min_ent, ent);
        max_ent = std::max(max_ent, ent);
        sum_ent += ent;
    }
    double mean_ent = blocks.empty() ? 0.0 : sum_ent / static_cast<double>(blocks.size());

    struct HighEntropyRange {
        std::uint64_t start = 0;
        std::uint64_t end = 0;
        double sum = 0.0;
        std::size_t count = 0;
    };
    std::vector<HighEntropyRange> high_ranges;
    bool in_high = false;
    HighEntropyRange cur_high;

    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const std::uint64_t offset = static_cast<std::uint64_t>(i) * block_size;
        const std::uint64_t end = std::min<std::uint64_t>(offset + block_size, v.size());
        if (blocks[i] >= 7.20) {
            if (!in_high) {
                in_high = true;
                cur_high.start = offset;
                cur_high.end = end;
                cur_high.sum = blocks[i];
                cur_high.count = 1;
            } else {
                cur_high.end = end;
                cur_high.sum += blocks[i];
                cur_high.count++;
            }
        } else if (in_high) {
            in_high = false;
            high_ranges.push_back(cur_high);
        }
    }
    if (in_high) high_ranges.push_back(cur_high);

    std::ostringstream out;
    out << "TypeMorph Shannon Entropy Distribution Map\n"
        << "===========================================\n"
        << "Target: " << current_file_ << " (" << v.size() << " bytes)\n"
        << "Total Entropy: " << std::fixed << std::setprecision(2) << total_entropy
        << " / 8.00 bits/byte | Block size: " << block_size << " bytes\n"
        << "Range: [" << min_ent << " .. " << max_ent << "], Mean: " << mean_ent << " bits/byte\n"
        << "--------------------------------------------------------------------------------\n"
        << "Offset Range               Entropy Bar                  Bits/B  Class\n"
        << "--------------------------------------------------------------------------------\n";

    std::size_t sample_limit = std::min<std::size_t>(blocks.size(), 200);
    for (std::size_t i = 0; i < sample_limit; ++i) {
        const std::uint64_t offset = static_cast<std::uint64_t>(i) * block_size;
        const std::uint64_t end = std::min<std::uint64_t>(offset + block_size, v.size());
        const double ent = blocks[i];
        const int filled = std::clamp(static_cast<int>(std::round((ent / 8.0) * 24.0)), 0, 24);
        std::string bar(filled, '#');
        bar.append(24 - filled, '.');

        char range_buf[64];
        std::snprintf(range_buf, sizeof(range_buf), "0x%08llx - 0x%08llx",
                      static_cast<unsigned long long>(offset),
                      static_cast<unsigned long long>(end > 0 ? end - 1 : 0));

        out << range_buf << "  [" << bar << "]  " << std::fixed << std::setprecision(2) << ent << "   "
            << core::entropy_label(ent);
        if (ent >= 7.20) out << " [HIGH]";
        out << '\n';
    }
    if (blocks.size() > sample_limit) {
        out << "... and " << (blocks.size() - sample_limit) << " more blocks.\n";
    }
    out << "--------------------------------------------------------------------------------\n";
    if (!high_ranges.empty()) {
        out << "Detected " << high_ranges.size() << " High-Entropy Zone(s) (>= 7.20 bits/byte):\n";
        for (const auto& r : high_ranges) {
            const double avg = r.count == 0 ? 0.0 : r.sum / static_cast<double>(r.count);
            char r_buf[64];
            std::snprintf(r_buf, sizeof(r_buf), "  * 0x%08llx - 0x%08llx",
                          static_cast<unsigned long long>(r.start),
                          static_cast<unsigned long long>(r.end > 0 ? r.end - 1 : 0));
            out << r_buf << " (" << (r.end - r.start) << " B, avg " << std::fixed
                << std::setprecision(2) << avg << " bits/byte) -> Packed, compressed, or encrypted\n";
        }
    } else {
        out << "No packed or encrypted high-entropy zones detected (all blocks < 7.20 bits/byte).\n";
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[Entropy Map] Total entropy: " + std::to_string(total_entropy) + " bits/byte.");
}

void StudioApp::run_string_revealer() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    deobf::StringScanOptions options;
    deobf::StringRevealer revealer(options);
    auto strings = revealer.extract(view.value());

    std::ostringstream out;
    out << "TypeMorph String Revealer (Embedded, Stack, XOR & Base64)\n"
        << "=========================================================\n"
        << "Target: " << current_file_ << " | Found " << strings.size() << " string(s)\n\n";

    for (const auto& s : strings) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08llx", static_cast<unsigned long long>(s.offset));
        out << buf << " [" << std::left << std::setw(7) << deobf::to_string(s.category)
            << std::right << "] " << s.value;
        if (!s.note.empty()) out << " (" << s.note << ")";
        out << '\n';
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[String Revealer] Extracted " + std::to_string(strings.size()) + " strings.");
}

void StudioApp::run_unxorer() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    deobf::UnxorOptions options;
    deobf::Unxorer unxorer(options);
    auto candidates = unxorer.crack(view.value());

    std::ostringstream out;
    out << "TypeMorph UnXORer: Automatic XOR Key Discovery\n"
        << "===============================================\n"
        << "Target: " << current_file_ << "\n"
        << "Discovered " << candidates.size() << " candidate key(s):\n\n";

    for (std::size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        out << "[Candidate #" << i + 1 << "] Key Length: " << c.key.size() << " byte(s)\n";
        out << "  Key (hex): ";
        for (std::uint8_t b : c.key) {
            char hb[8];
            std::snprintf(hb, sizeof(hb), "%02X ", b);
            out << hb;
        }
        out << "\n  Confidence: " << std::fixed << std::setprecision(1) << (c.confidence * 100.0) << "%\n"
            << "  Entropy:    " << std::setprecision(2) << c.entropy << " bits/byte\n"
            << "  Rationale:  " << c.rationale << "\n"
            << "  Preview:    \"" << c.preview << "\"\n\n";
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[UnXORer] Evaluated " + std::to_string(candidates.size()) + " candidate keys.");
}

void StudioApp::run_apihash_scan() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    deobf::ApiHashResolver resolver;
    auto matches = resolver.scan(view.value());

    std::ostringstream out;
    out << "TypeMorph API Hash Scanner (ROR13 / DJB2 / SDBM / FNV1a / CRC32)\n"
        << "=================================================================\n"
        << "Target: " << current_file_ << "\n"
        << "Matches Identified: " << matches.size() << "\n\n";

    if (matches.empty()) {
        out << "  No known API hashes identified.\n";
    } else {
        for (const auto& m : matches) {
            char off_buf[32], hash_buf[32];
            std::snprintf(off_buf, sizeof(off_buf), "0x%llx", static_cast<unsigned long long>(m.offset));
            std::snprintf(hash_buf, sizeof(hash_buf), "0x%08X", m.hash_value);
            out << "  [" << off_buf << "] " << hash_buf << " -> "
                << m.module_name << "!" << m.api_name
                << " (" << to_string(m.algorithm) << ", conf: "
                << std::fixed << std::setprecision(1) << (m.confidence * 100.0) << "%)\n";
        }
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[API Hash Scanner] Identified " + std::to_string(matches.size()) + " API calls.");
}

void StudioApp::run_opaque_predicates() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    deobf::OpaquePredicateDetector detector;
    auto matches = detector.scan(view.value());

    std::ostringstream out;
    out << "TypeMorph Opaque Predicate & Dead Code Detector\n"
        << "===============================================\n"
        << "Target: " << current_file_ << "\n"
        << "Opaque Invariants Detected: " << matches.size() << "\n\n";

    if (matches.empty()) {
        out << "  No invariant opaque predicates detected.\n";
    } else {
        for (const auto& m : matches) {
            char off_buf[32];
            std::snprintf(off_buf, sizeof(off_buf), "0x%llx", static_cast<unsigned long long>(m.offset));
            out << "  [" << off_buf << "] " << m.disassembly_hint
                << " => " << (m.outcome == deobf::PredicateOutcome::always_true ? "ALWAYS TAKEN" : "NEVER TAKEN (DEAD)")
                << " (" << m.pattern_name << ")\n"
                << "     " << m.rationale << "\n";
        }
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[Opaque Predicates] Found " + std::to_string(matches.size()) + " dead branches.");
}

void StudioApp::run_cff_reconstruction() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    auto img = core::ExecutableImage::parse(view.value());
    if (!img) {
        LogMessage("[CFF Unflattener] Requires valid PE/ELF executable.");
        return;
    }

    deobf::CffOptions opts;
    deobf::CffReconstructor reconstructor(opts);
    auto fns = reconstructor.analyze(img.value());

    std::ostringstream out;
    out << "TypeMorph Control Flow Flattening (CFF) Unflattener\n"
        << "===================================================\n"
        << "Target: " << current_file_ << "\n"
        << "Flattened Functions Detected: " << fns.size() << "\n\n";

    if (fns.empty()) {
        out << "  No control flow flattening dispatchers detected.\n";
    } else {
        for (std::size_t i = 0; i < fns.size(); ++i) {
            const auto& fn = fns[i];
            char va_buf[64];
            std::snprintf(va_buf, sizeof(va_buf), "0x%llx", static_cast<unsigned long long>(fn.dispatcher_va));
            out << "Function #" << i + 1 << ": Dispatcher at " << va_buf
                << " (State Var: " << fn.state_variable << ", Confidence: "
                << std::fixed << std::setprecision(1) << (fn.confidence * 100.0) << "%)\n"
                << "  Blocks: " << fn.blocks.size() << " | Recovered Transitions: "
                << fn.transitions.size() << "\n"
                << "  " << fn.rationale << "\n"
                << "  State Transitions (Reconstructed Sequence):\n";
            for (const auto& t : fn.transitions) {
                char t_buf[128];
                std::snprintf(t_buf, sizeof(t_buf), "    State 0x%X -> State 0x%X%s",
                              t.from_state, t.to_state,
                              t.condition.empty() ? "" : (" [" + t.condition + "]").c_str());
                out << t_buf << "\n";
            }
            out << "\n";
        }
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[CFF Unflattener] Analyzed " + std::to_string(fns.size()) + " flattened functions.");
}

void StudioApp::run_classinformer() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    rtti::RttiAnalyzer analyzer;
    auto classes = analyzer.analyze_view(view.value());

    std::ostringstream out;
    out << "TypeMorph ClassInformer - C++ RTTI & Polymorphic Hierarchy\n"
        << "===========================================================\n"
        << "Target: " << current_file_ << "\n"
        << "Found " << classes.size() << " polymorphic C++ class(es):\n\n";

    if (classes.empty()) {
        out << "  No C++ RTTI CompleteObjectLocator or TypeDescriptor entries found.\n";
    } else {
        for (std::size_t i = 0; i < classes.size(); ++i) {
            const auto& cls = classes[i];
            char vf_buf[32], loc_buf[32];
            std::snprintf(vf_buf, sizeof(vf_buf), "0x%llX", static_cast<unsigned long long>(cls.vftable_va));
            std::snprintf(loc_buf, sizeof(loc_buf), "0x%llX", static_cast<unsigned long long>(cls.locator_va));

            out << "  [" << (i + 1) << "] class " << cls.name;
            if (!cls.base_classes.empty()) {
                out << " : ";
                for (std::size_t b = 0; b < cls.base_classes.size(); ++b) {
                    if (b > 0) out << ", ";
                    out << "public " << cls.base_classes[b].name;
                }
            }
            out << "\n      Vftable: " << vf_buf << " | Locator: " << loc_buf
                << " | Methods: " << cls.methods.size() << "\n";

            if (!cls.base_classes.empty()) {
                out << "      Hierarchy: ";
                for (std::size_t b = 0; b < cls.base_classes.size(); ++b) {
                    if (b > 0) out << " -> ";
                    out << cls.base_classes[b].name << " (+0x" << std::hex << cls.base_classes[b].offset << std::dec << ")";
                }
                out << "\n";
            }
            if (!cls.methods.empty()) {
                std::size_t limit = std::min<std::size_t>(cls.methods.size(), 8);
                for (std::size_t m = 0; m < limit; ++m) {
                    char m_buf[32];
                    std::snprintf(m_buf, sizeof(m_buf), "0x%llX", static_cast<unsigned long long>(cls.methods[m].virtual_address));
                    out << "        slot[" << cls.methods[m].slot << "] " << m_buf << ": " << cls.methods[m].name << "()\n";
                }
                if (cls.methods.size() > limit) {
                    out << "        ... and " << (cls.methods.size() - limit) << " more virtual slots\n";
                }
            }
            out << "\n";
        }
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[ClassInformer] Reconstructed " + std::to_string(classes.size()) + " polymorphic classes.");
}

namespace {
struct GeneratedSig {
    std::uint64_t function_va = 0;
    std::string function_name;
    std::size_t length = 0;
    std::string pattern_ida;
    std::string pattern_yara;
    std::string pattern_bytes;
    std::string pattern_mask;
    std::size_t wildcard_count = 0;
};

GeneratedSig make_gui_signature(const core::ExecutableImage& image,
                                const core::BinaryView& view,
                                std::uint64_t func_va,
                                std::string func_name,
                                std::size_t desired_len) {
    GeneratedSig sig;
    sig.function_va = func_va;
    sig.function_name = std::move(func_name);

    auto off_res = image.va_to_offset(func_va);
    if (!off_res || off_res.value() >= view.size()) return sig;

    const std::uint64_t file_off = off_res.value();
    const std::size_t max_avail = static_cast<std::size_t>(view.size() - file_off);
    const std::size_t len = std::min<std::size_t>(desired_len, max_avail);
    sig.length = len;

    const std::uint8_t* bytes = view.data() + file_off;
    std::ostringstream ida_ss, yara_ss, bytes_ss, mask_ss;
    yara_ss << "{ ";

    for (std::size_t i = 0; i < len; ++i) {
        bool wildcard = false;
        if (i >= 1 && (bytes[i - 1] == 0xE8 || bytes[i - 1] == 0xE9) && i + 3 <= len) {
            wildcard = true;
        } else if (i >= 2 && i <= len && (bytes[i - 2] == 0xE8 || bytes[i - 2] == 0xE9)) {
            wildcard = true;
        } else if (i >= 3 && i <= len && (bytes[i - 3] == 0xE8 || bytes[i - 3] == 0xE9)) {
            wildcard = true;
        } else if (i >= 4 && i <= len && (bytes[i - 4] == 0xE8 || bytes[i - 4] == 0xE9)) {
            wildcard = true;
        }
        if (image.bits() == 64 && i >= 3 && i + 1 <= len) {
            if (bytes[i - 3] == 0x48 && (bytes[i - 2] == 0x8B || bytes[i - 2] == 0x8D) && (bytes[i - 1] & 0xC7) == 0x05) {
                wildcard = true;
            }
        }

        if (wildcard) {
            ++sig.wildcard_count;
            if (i > 0) ida_ss << " ";
            ida_ss << "??";
            yara_ss << "?? ";
            bytes_ss << "\\x00";
            mask_ss << "?";
        } else {
            char hex_byte[8];
            std::snprintf(hex_byte, sizeof(hex_byte), "%02X", bytes[i]);
            if (i > 0) ida_ss << " ";
            ida_ss << hex_byte;
            std::snprintf(hex_byte, sizeof(hex_byte), "%02x ", bytes[i]);
            yara_ss << hex_byte;
            std::snprintf(hex_byte, sizeof(hex_byte), "\\x%02X", bytes[i]);
            bytes_ss << hex_byte;
            mask_ss << "x";
        }
    }
    yara_ss << "}";

    sig.pattern_ida = ida_ss.str();
    sig.pattern_yara = yara_ss.str();
    sig.pattern_bytes = bytes_ss.str();
    sig.pattern_mask = mask_ss.str();
    return sig;
}
}  // namespace

void StudioApp::run_sigmaker() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    auto img = core::ExecutableImage::parse(view.value());
    if (!img) {
        LogMessage("[SigMaker] Requires valid executable binary.");
        return;
    }

    abi::AbiClassifier classifier;
    auto abi_rep = classifier.analyze(img.value());

    std::vector<GeneratedSig> sigs;
    std::size_t limit = std::min<std::size_t>(abi_rep.signatures.size(), 20);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& fn = abi_rep.signatures[i];
        sigs.push_back(make_gui_signature(img.value(), view.value(), fn.entry_va, fn.name, 32));
    }

    std::ostringstream out;
    out << "TypeMorph Signature Maker (SigMaker)\n"
        << "====================================\n"
        << "Target: " << current_file_ << "\n"
        << "Generated " << sigs.size() << " signature pattern(s):\n\n";

    for (const auto& s : sigs) {
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(s.function_va));
        out << "Function: " << s.function_name << " (" << va_buf << ", len: " << s.length
            << ", wildcards: " << s.wildcard_count << ")\n"
            << "  IDA   : " << s.pattern_ida << "\n"
            << "  YARA  : " << s.pattern_yara << "\n"
            << "  Bytes : \"" << s.pattern_bytes << "\"\n"
            << "  Mask  : \"" << s.pattern_mask << "\"\n\n";
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[SigMaker] Generated " + std::to_string(sigs.size()) + " function signatures.");
}

void StudioApp::run_infer() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    infer::DiffOptions options;
    options.confidence_threshold = 0.50;
    infer::DiffEngine engine(options);
    auto sample = infer::Sample{view.value(), current_file_, std::nullopt};
    auto result = engine.infer(std::span<const infer::Sample>(&sample, 1));
    if (!result) {
        LogMessage("[Infer] Failed to infer structure: " + result.error().message);
        return;
    }

    emit::EmitOptions emit_opt;
    emit_opt.format_name = result.value().format_name.empty() ? "recovered" : result.value().format_name;
    emit_opt.root_type_name = "RecoveredBinaryFile";
    emit_opt.file_size = result.value().max_size;
    emit_opt.endian = result.value().endian;
    emit_opt.emit_comments = true;
    emit_opt.emit_instances = true;

    auto cpp_code = emit::CppEmitter{}.generate(*result.value().root, emit_opt);
    auto rust_code = emit::RustEmitter{}.generate(*result.value().root, emit_opt);
    auto kaitai_code = emit::KaitaiEmitter{}.generate(*result.value().root, emit_opt);

    std::ostringstream out;
    out << "// TypeMorph Differential Binary Format & Schema Inference\n"
        << "// Target: " << current_file_ << "\n"
        << "// Format: " << emit_opt.format_name << " (Confidence: "
        << std::fixed << std::setprecision(2) << (result.value().confidence * 100.0) << "%)\n"
        << "// Fields: " << result.value().fields.size() << " | Evidence count: " << result.value().evidence.size() << "\n\n"
        << "================================================================================\n"
        << "--- RECONSTRUCTED C++20 SCHEMA ---\n"
        << "================================================================================\n"
        << (cpp_code ? cpp_code.value() : "// C++ generation failed") << "\n\n"
        << "================================================================================\n"
        << "--- RECONSTRUCTED RUST STRUCT SCHEMA ---\n"
        << "================================================================================\n"
        << (rust_code ? rust_code.value() : "// Rust generation failed") << "\n\n"
        << "================================================================================\n"
        << "--- KAITAI STRUCT SPECIFICATION (.ksy) ---\n"
        << "================================================================================\n"
        << (kaitai_code ? kaitai_code.value() : "// Kaitai generation failed") << "\n";

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[Infer] Reconstructed format schema (" + std::to_string(result.value().fields.size()) + " fields, C++/Rust/Kaitai).");
}

void StudioApp::run_dumpsubs() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    auto img = core::ExecutableImage::parse(view.value());
    if (!img) {
        LogMessage("[DumpSubs] Requires valid executable binary.");
        return;
    }

    abi::AbiClassifier classifier;
    auto rep = classifier.analyze(img.value());

    std::ostringstream out;
    out << "Address,Name,Convention,ReturnType,StackFrame,StackPurge,Arguments,Prototype\n";
    for (const auto& sig : rep.signatures) {
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(sig.entry_va));
        out << va_buf << ",\"" << sig.name << "\"," << to_string(sig.convention) << ",\""
            << sig.return_type_hint << "\"," << sig.stack_frame_size << ","
            << sig.stack_purge_bytes << "," << sig.arguments.size() << ",\""
            << sig.prototype << "\"\n";
    }

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[DumpSubs] Dumped " + std::to_string(rep.signatures.size()) + " subroutines to table.");
}

void StudioApp::run_applycalletype() {
    if (current_file_.empty()) return;
    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    auto img = core::ExecutableImage::parse(view.value());
    if (!img) {
        LogMessage("[ApplyCalleeType] Requires valid executable binary.");
        return;
    }

    abi::AbiClassifier classifier;
    auto rep = classifier.analyze(img.value());

    std::ostringstream out;
    out << "TypeMorph ApplyCalleeType - Call Site Type & Prototype Propagator\n"
        << "================================================================\n"
        << "Target: " << current_file_ << "\n"
        << "Classified " << rep.signatures.size() << " callee signature(s) across "
        << rep.total_functions << " analyzed functions:\n\n";

    for (const auto& sig : rep.signatures) {
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(sig.entry_va));
        out << "  [" << va_buf << "] " << sig.prototype << "\n"
            << "     Convention: " << to_string(sig.convention)
            << " | Arguments: " << sig.arguments.size()
            << " | Frame: " << sig.stack_frame_size << "B";
        if (sig.stack_purge_bytes > 0) out << " | Purge: " << sig.stack_purge_bytes << "B";
        out << "\n";
        for (const auto& arg : sig.arguments) {
            out << "       arg[" << arg.index << "] " << arg.location << " (" << arg.type_hint << ")\n";
        }
        out << "\n";
    }
    out << "(Status: Ready to propagate to IDA / Ghidra / Binary Ninja via typemorph_sync)\n";

    SetWindowTextW(g_hwndCode, normalize_crlf(out.str()).c_str());
    LogMessage("[ApplyCalleeType] Reconstructed " + std::to_string(rep.signatures.size()) + " callee prototypes.");
}

void StudioApp::save_decompiled_output() {
    if (!g_hwndCode) return;
    int len = GetWindowTextLengthW(g_hwndCode);
    if (len <= 0) {
        LogMessage("[Save] Nothing to save: code view is empty.");
        return;
    }

    std::wstring buffer(static_cast<std::size_t>(len) + 1, 0);
    GetWindowTextW(g_hwndCode, &buffer[0], len + 1);
    buffer.resize(static_cast<std::size_t>(len));

    wchar_t szSaveFile[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwndMain;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0C# Source (*.cs)\0*.cs\0C/C++ Source (*.cpp;*.c;*.h)\0*.cpp;*.c;*.h\0Rust Source (*.rs)\0*.rs\0Python / Script (*.py;*.au3;*.lua)\0*.py;*.au3;*.lua\0Text / Report (*.txt;*.csv)\0*.txt;*.csv\0";
    ofn.lpstrFile = szSaveFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileNameW(&ofn)) {
        char path_mb[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, szSaveFile, -1, path_mb, MAX_PATH, nullptr, nullptr);

        int sz = WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string content(static_cast<std::size_t>(sz), 0);
        WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), -1, &content[0], sz, nullptr, nullptr);
        if (!content.empty() && content.back() == '\0') content.pop_back();

        std::ofstream fos(path_mb, std::ios::binary);
        if (fos.is_open()) {
            fos.write(content.data(), static_cast<std::streamsize>(content.size()));
            fos.close();
            LogMessage(std::string("[Save] Exported ") + std::to_string(content.size()) + " bytes to " + path_mb);
        } else {
            LogMessage(std::string("[Save Error] Failed to write file: ") + path_mb);
        }
    }
}

int StudioApp::run(const std::string& initial_file) {
    g_pApp = this;

    HINSTANCE hInstance = GetModuleHandleW(nullptr);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"TypeMorphStudioClass";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(kClrHeader);
    RegisterClassExW(&wc);

    g_hwndMain = CreateWindowExW(
        0, L"TypeMorphStudioClass",
        L"TypeMorph Studio - Multi-Language Decompiler & Semantic Analyzer",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1200, 750,
        nullptr, nullptr, hInstance, nullptr);

    SetupMenus(g_hwndMain);
    ShowWindow(g_hwndMain, SW_SHOW);
    UpdateWindow(g_hwndMain);

    if (!initial_file.empty()) {
        open_file(initial_file);
    }

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

int run_native_studio(int argc, char** argv) {
    std::string target_file;
    if (argc > 1) {
        target_file = argv[1];
    }
    StudioApp app;
    return app.run(target_file);
}

}  // namespace typemorph::gui

#endif  // _WIN32

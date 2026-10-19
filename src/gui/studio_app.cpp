// TypeMorph - Standalone Native Desktop GUI Application Implementation (dnSpy / dotPeek style)
#ifdef _WIN32

#include "typemorph/gui/studio_app.hpp"
#include "typemorph/core/executable.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include <algorithm>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")

namespace typemorph::gui {

namespace {

// Control IDs
constexpr int IDM_FILE_OPEN       = 1001;
constexpr int IDM_FILE_EXIT       = 1002;
constexpr int IDM_ACTION_DEOBF    = 1003;
constexpr int IDM_VIEW_CSHARP     = 1004;
constexpr int IDM_VIEW_IL         = 1005;
constexpr int IDM_HELP_ABOUT      = 1006;

constexpr int IDC_TREEVIEW        = 2001;
constexpr int IDC_CODE_EDITOR     = 2002;
constexpr int IDC_LOG_LIST        = 2003;
constexpr int IDC_STATUS_BAR      = 2004;

constexpr COLORREF kClrDarkBg     = RGB(30, 30, 30);
constexpr COLORREF kClrTreeBg     = RGB(37, 37, 38);
constexpr COLORREF kClrText       = RGB(212, 212, 212);
constexpr COLORREF kClrHeader     = RGB(45, 45, 48);

HWND g_hwndMain = nullptr;
HWND g_hwndTree = nullptr;
HWND g_hwndCode = nullptr;
HWND g_hwndLog  = nullptr;
HWND g_hwndStatus = nullptr;

HFONT g_hFontCode = nullptr;
HFONT g_hFontUI = nullptr;
HBRUSH g_hBrushDark = nullptr;
HBRUSH g_hBrushTree = nullptr;

StudioApp* g_pApp = nullptr;

std::wstring to_wide(const std::string& str) {
    if (str.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring out(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &out[0], sz);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
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

void PopulateAssemblyTree(const dotnet::DotNetReport& report, const std::string& filename) {
    if (!g_hwndTree) return;
    SendMessageW(g_hwndTree, TVM_DELETEITEM, 0, reinterpret_cast<LPARAM>(TVI_ROOT));

    // Root node: Assembly
    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

    std::wstring wfile = to_wide(filename.empty() ? "Assembly.dll" : filename);
    tvis.item.pszText = const_cast<LPWSTR>(wfile.c_str());
    tvis.item.lParam = 0;
    HTREEITEM hRoot = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

    // Group types by namespace
    std::map<std::string, std::vector<const dotnet::DotNetType*>> by_ns;
    for (const auto& t : report.types) {
        by_ns[t.namespace_name].push_back(&t);
    }

    LPARAM type_index = 1;
    for (const auto& [ns, types] : by_ns) {
        HTREEITEM hNs = hRoot;
        if (!ns.empty()) {
            std::wstring wns = to_wide(ns);
            tvis.hParent = hRoot;
            tvis.item.pszText = const_cast<LPWSTR>(wns.c_str());
            tvis.item.lParam = 0;
            hNs = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));
        }

        for (const auto* t : types) {
            std::wstring wtname = to_wide(t->name);
            tvis.hParent = hNs;
            tvis.item.pszText = const_cast<LPWSTR>(wtname.c_str());
            tvis.item.lParam = type_index++;
            HTREEITEM hType = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

            // Add methods as sub-items
            for (const auto& m : t->methods) {
                std::string mdesc = m.name + "(";
                for (std::size_t p = 0; p < m.parameters.size(); ++p) {
                    if (p > 0) mdesc += ", ";
                    mdesc += m.parameters[p].type_name;
                }
                mdesc += ") : " + m.return_type;

                std::wstring wmname = to_wide(mdesc);
                TVINSERTSTRUCTW m_ins = {};
                m_ins.hParent = hType;
                m_ins.hInsertAfter = TVI_LAST;
                m_ins.item.mask = TVIF_TEXT;
                m_ins.item.pszText = const_cast<LPWSTR>(wmname.c_str());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&m_ins));
            }
        }
    }

    SendMessageW(g_hwndTree, TVM_EXPAND, TVE_EXPAND, reinterpret_cast<LPARAM>(hRoot));
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icex = {sizeof(icex), ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES};
        InitCommonControlsEx(&icex);

        // Fonts
        g_hFontUI = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        g_hFontCode = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        g_hBrushDark = CreateSolidBrush(kClrDarkBg);
        g_hBrushTree = CreateSolidBrush(kClrTreeBg);

        // Assembly Explorer (TreeView)
        g_hwndTree = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
            WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
            0, 0, 260, 400, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_TREEVIEW)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndTree, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontUI), TRUE);

        // Code Decompiler View (Multiline Edit)
        g_hwndCode = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            260, 0, 600, 400, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CODE_EDITOR)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndCode, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontCode), TRUE);

        // Deobfuscation Log / Token Inspector (ListBox)
        g_hwndLog = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            0, 400, 860, 150, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOG_LIST)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndLog, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontCode), TRUE);

        // Status Bar
        g_hwndStatus = CreateWindowExW(
            0, STATUSCLASSNAMEW, L"",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS_BAR)),
            GetModuleHandleW(nullptr), nullptr);

        int parts[] = {300, 550, -1};
        SendMessageW(g_hwndStatus, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
        SetStatusBarText(0, "Ready - TypeMorph Decompiler Studio");
        SetStatusBarText(1, "dnSpy / dotPeek Architecture");
        SetStatusBarText(2, "TypeMorph v0.7.0 C++20");

        LogMessage("// TypeMorph Studio native Win32 desktop UI initialized.");
        LogMessage("// Open a .NET / PE / ELF binary to decompile and reconstruct assembly code.");
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);

        RECT rcStatus;
        SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
        GetWindowRect(g_hwndStatus, &rcStatus);
        int status_h = rcStatus.bottom - rcStatus.top;

        int log_h = 130;
        int tree_w = 260;
        int main_h = h - status_h - log_h;

        if (main_h < 50) main_h = 50;

        MoveWindow(g_hwndTree, 0, 0, tree_w, main_h, TRUE);
        MoveWindow(g_hwndCode, tree_w, 0, w - tree_w, main_h, TRUE);
        MoveWindow(g_hwndLog, 0, main_h, w, log_h, TRUE);
        return 0;
    }

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
            ofn.lpstrFilter = L"Executables & Assemblies (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0";
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
        if (id == IDM_ACTION_DEOBF) {
            if (g_pApp) g_pApp->deobfuscate_current();
            return 0;
        }
        if (id == IDM_FILE_EXIT) {
            DestroyWindow(hwnd);
            return 0;
        }
        if (id == IDM_HELP_ABOUT) {
            MessageBoxW(hwnd,
                L"TypeMorph Studio v0.7.0\n\n"
                L"A pure C++20 reverse engineering decompiler & deobfuscator\n"
                L"inspired by dnSpy and JetBrains dotPeek.\n\n"
                L"Features:\n"
                L"• Assembly Explorer & Metadata Inspector\n"
                L"• C# Decompiler & CIL Disassembly\n"
                L"• ConfuserEx / .NET Reactor Proxy Inliner\n"
                L"• String Decryptor & Control Flow Flattening Switch Killer",
                L"About TypeMorph Studio", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;
    }

    case WM_NOTIFY: {
        LPNMHDR pnm = reinterpret_cast<LPNMHDR>(lParam);
        if (pnm->idFrom == IDC_TREEVIEW && pnm->code == TVN_SELCHANGEDW) {
            LPNMTREEVIEWW pnmtv = reinterpret_cast<LPNMTREEVIEWW>(lParam);
            wchar_t text_buf[256] = L"";
            TVITEMW item = {};
            item.hItem = pnmtv->itemNew.hItem;
            item.mask = TVIF_TEXT;
            item.pszText = text_buf;
            item.cchTextMax = 256;
            SendMessageW(g_hwndTree, TVM_GETITEMW, 0, reinterpret_cast<LPARAM>(&item));

            char mb[256];
            WideCharToMultiByte(CP_UTF8, 0, text_buf, -1, mb, 256, nullptr, nullptr);
            LogMessage(std::string("Selected assembly member: ") + mb);
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
    AppendMenuW(hFile, MF_STRING, IDM_FILE_OPEN, L"&Open Assembly...\tCtrl+O");
    AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFile, MF_STRING, IDM_FILE_EXIT, L"E&xit");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFile), L"&File");

    // Deobfuscate Menu
    HMENU hDeobf = CreatePopupMenu();
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_DEOBF, L"&Clean & Deobfuscate (ConfuserEx / .NET Reactor)\tF5");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDeobf), L"&Deobfuscate");

    // View Menu
    HMENU hView = CreatePopupMenu();
    AppendMenuW(hView, MF_STRING, IDM_VIEW_CSHARP, L"&C# Decompiled Code");
    AppendMenuW(hView, MF_STRING, IDM_VIEW_IL, L"&CIL Disassembly");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hView), L"&View");

    // Help Menu
    HMENU hHelp = CreatePopupMenu();
    AppendMenuW(hHelp, MF_STRING, IDM_HELP_ABOUT, L"&About TypeMorph Studio...");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelp), L"&Help");

    SetMenu(hwnd, hMenuBar);
}

}  // namespace

void StudioApp::open_file(const std::string& path) {
    current_file_ = path;
    is_deobfuscated_ = false;

    auto view = core::BinaryView::open(path);
    if (!view) {
        LogMessage("[Error] Failed to open binary file: " + path);
        return;
    }

    dotnet::DotNetAnalyzer analyzer;
    current_report_ = analyzer.analyze_view(view.value());

    if (!current_report_.is_dotnet) {
        LogMessage("[Warn] " + path + " is not a .NET CLI executable. Showing raw assembly preview.");
        std::wstring raw_info = L"// Binary File: " + to_wide(path) + L"\r\n// Size: " +
                                std::to_wstring(view.value().size()) + L" bytes\r\n// Format: Non-.NET Binary";
        SetWindowTextW(g_hwndCode, raw_info.c_str());
        SetStatusBarText(0, "Loaded: " + path);
        SetStatusBarText(1, "Format: Native/Binary");
        return;
    }

    current_report_.csharp_source = dotnet::DotNetAnalyzer::to_csharp(current_report_);

    // Update UI
    std::string filename = path;
    auto last_slash = filename.find_last_of("\\/");
    if (last_slash != std::string::npos) filename = filename.substr(last_slash + 1);

    PopulateAssemblyTree(current_report_, filename);

    std::wstring wcode = to_wide(current_report_.csharp_source);
    // Replace \n with \r\n for Win32 EDIT control
    std::wstring crlf_code;
    crlf_code.reserve(wcode.size() + 1024);
    for (wchar_t ch : wcode) {
        if (ch == L'\n') crlf_code += L"\r\n";
        else crlf_code.push_back(ch);
    }
    SetWindowTextW(g_hwndCode, crlf_code.c_str());

    SetStatusBarText(0, "Loaded: " + filename);
    SetStatusBarText(1, "Runtime: " + current_report_.runtime_version);
    SetStatusBarText(2, "Types: " + std::to_string(current_report_.types.size()) +
                        " | Methods: " + std::to_string(current_report_.method_count));

    LogMessage("[TypeMorph] Successfully loaded assembly: " + filename);
    LogMessage("[TypeMorph] Extracted " + std::to_string(current_report_.types.size()) +
               " types, " + std::to_string(current_report_.method_count) + " methods.");
}

void StudioApp::deobfuscate_current() {
    if (current_file_.empty() || !current_report_.is_dotnet) {
        LogMessage("[Error] No valid .NET assembly loaded to deobfuscate.");
        return;
    }

    auto view = core::BinaryView::open(current_file_);
    if (!view) return;

    dotnet::DotNetDeobfuscator deobfuscator;
    current_deobf_report_ = deobfuscator.deobfuscate_view(view.value());
    is_deobfuscated_ = true;

    std::wstring wcode = to_wide(current_deobf_report_.clean_csharp_source);
    std::wstring crlf_code;
    crlf_code.reserve(wcode.size() + 1024);
    for (wchar_t ch : wcode) {
        if (ch == L'\n') crlf_code += L"\r\n";
        else crlf_code.push_back(ch);
    }
    SetWindowTextW(g_hwndCode, crlf_code.c_str());

    LogMessage("[Deobfuscation] --- Deobfuscation Complete ---");
    LogMessage("[Deobfuscation] Protector: " + std::string(to_string(current_deobf_report_.detected_protector)));
    LogMessage("[Deobfuscation] Inlined Proxy Calls: " + std::to_string(current_deobf_report_.total_proxies_inlined));
    LogMessage("[Deobfuscation] Decrypted Strings: " + std::to_string(current_deobf_report_.total_strings_decrypted));
    LogMessage("[Deobfuscation] Flattened Switch Blocks: " + std::to_string(current_deobf_report_.total_switches_killed));

    SetStatusBarText(1, "Deobfuscated: " + std::string(to_string(current_deobf_report_.detected_protector)));
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
        L"TypeMorph Studio - .NET Decompiler & Deobfuscator (dnSpy / dotPeek Architecture)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 700,
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

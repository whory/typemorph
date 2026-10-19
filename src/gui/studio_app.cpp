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

// Menu & Action IDs
constexpr int IDM_FILE_OPEN          = 1001;
constexpr int IDM_FILE_EXIT          = 1002;
constexpr int IDM_ACTION_DEOBF       = 1003;
constexpr int IDM_ACTION_DETECT      = 1004;
constexpr int IDM_ACTION_VMPROFILE   = 1005;
constexpr int IDM_ACTION_UNPACK      = 1006;
constexpr int IDM_ACTION_VFS         = 1007;
constexpr int IDM_ACTION_IATFIX      = 1008;

// Decompiler Modes
constexpr int IDM_VIEW_CSHARP        = 1010;
constexpr int IDM_VIEW_C             = 1011;
constexpr int IDM_VIEW_RUST          = 1012;
constexpr int IDM_VIEW_JAVA          = 1013;
constexpr int IDM_VIEW_DELPHI        = 1014;
constexpr int IDM_VIEW_VB            = 1015;
constexpr int IDM_VIEW_AUTOIT        = 1016;

constexpr int IDM_HELP_ABOUT         = 1020;

// Child Controls
constexpr int IDC_TREEVIEW           = 2001;
constexpr int IDC_CODE_EDITOR        = 2002;
constexpr int IDC_LOG_LIST           = 2003;
constexpr int IDC_STATUS_BAR         = 2004;

constexpr COLORREF kClrDarkBg        = RGB(30, 30, 30);
constexpr COLORREF kClrTreeBg        = RGB(37, 37, 38);
constexpr COLORREF kClrText          = RGB(212, 212, 212);
constexpr COLORREF kClrHeader        = RGB(45, 45, 48);

HWND g_hwndMain   = nullptr;
HWND g_hwndTree   = nullptr;
HWND g_hwndCode   = nullptr;
HWND g_hwndLog    = nullptr;
HWND g_hwndStatus = nullptr;

HFONT g_hFontCode   = nullptr;
HFONT g_hFontUI     = nullptr;
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

void PopulateTree(const std::string& filename,
                  const dotnet::DotNetReport& dotnet_rep,
                  const delphi::DelphiReport& delphi_rep,
                  const dex::DexReport& dex_rep,
                  const vb::VbReport& vb_rep,
                  const vm::VmProfileReport& vm_rep) {
    if (!g_hwndTree) return;
    SendMessageW(g_hwndTree, TVM_DELETEITEM, 0, reinterpret_cast<LPARAM>(TVI_ROOT));

    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

    std::wstring wfile = to_wide(filename.empty() ? "Assembly.dll" : filename);
    tvis.item.pszText = const_cast<LPWSTR>(wfile.c_str());
    tvis.item.lParam = 0;
    HTREEITEM hRoot = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

    // 1. .NET Types & Namespaces
    if (dotnet_rep.is_dotnet) {
        std::map<std::string, std::vector<const dotnet::DotNetType*>> by_ns;
        for (const auto& t : dotnet_rep.types) by_ns[t.namespace_name].push_back(&t);

        for (const auto& [ns, types] : by_ns) {
            HTREEITEM hNs = hRoot;
            if (!ns.empty()) {
                std::wstring wns = to_wide("Namespace: " + ns);
                tvis.hParent = hRoot;
                tvis.item.pszText = const_cast<LPWSTR>(wns.c_str());
                hNs = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));
            }

            for (const auto* t : types) {
                std::wstring wtname = to_wide("class " + t->name);
                tvis.hParent = hNs;
                tvis.item.pszText = const_cast<LPWSTR>(wtname.c_str());
                HTREEITEM hType = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

                for (const auto& m : t->methods) {
                    std::string mdesc = m.name + "() : " + m.return_type;
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
    }

    // 2. Delphi VCL Forms & Units
    if (delphi_rep.is_delphi) {
        std::wstring wdelphi = L"Delphi VCL Architecture (" + to_wide(delphi_rep.compiler_version) + L")";
        tvis.hParent = hRoot;
        tvis.item.pszText = const_cast<LPWSTR>(wdelphi.c_str());
        HTREEITEM hDelphi = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

        for (const auto& form : delphi_rep.forms) {
            std::wstring wform = to_wide("Form: " + form.form_name + " (" + form.class_name + ")");
            tvis.hParent = hDelphi;
            tvis.item.pszText = const_cast<LPWSTR>(wform.c_str());
            HTREEITEM hForm = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

            for (const auto& ev : form.root_component.events) {
                std::ostringstream ss;
                ss << ev.event_name << " -> " << ev.handler_name << " [VA: 0x" << std::hex << ev.handler_va << "]";
                std::wstring wev = to_wide(ss.str());
                TVINSERTSTRUCTW ev_ins = {};
                ev_ins.hParent = hForm;
                ev_ins.hInsertAfter = TVI_LAST;
                ev_ins.item.mask = TVIF_TEXT;
                ev_ins.item.pszText = const_cast<LPWSTR>(wev.c_str());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ev_ins));
            }
        }
    }

    // 3. Android Dalvik DEX Classes
    if (dex_rep.is_dex) {
        std::wstring wdex = L"Dalvik DEX Packages (" + std::to_wstring(dex_rep.classes.size()) + L" classes)";
        tvis.hParent = hRoot;
        tvis.item.pszText = const_cast<LPWSTR>(wdex.c_str());
        HTREEITEM hDex = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

        for (const auto& cls : dex_rep.classes) {
            std::wstring wcls = to_wide(cls.name);
            tvis.hParent = hDex;
            tvis.item.pszText = const_cast<LPWSTR>(wcls.c_str());
            HTREEITEM hC = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

            for (const auto& m : cls.methods) {
                std::wstring wm = to_wide(m.name + " (" + std::to_string(m.instructions.size()) + " insns)");
                TVINSERTSTRUCTW m_ins = {};
                m_ins.hParent = hC;
                m_ins.hInsertAfter = TVI_LAST;
                m_ins.item.mask = TVIF_TEXT;
                m_ins.item.pszText = const_cast<LPWSTR>(wm.c_str());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&m_ins));
            }
        }
    }

    // 4. Visual Basic 5/6 Forms & Events
    if (vb_rep.is_vb) {
        std::string mode_str = vb_rep.is_pcode ? "P-Code" : "Native Code";
        std::wstring wvb = to_wide("VB6 Project (" + mode_str + ")");
        tvis.hParent = hRoot;
        tvis.item.pszText = const_cast<LPWSTR>(wvb.c_str());
        HTREEITEM hVb = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

        for (const auto& mod : vb_rep.modules) {
            std::wstring wmod = to_wide(mod.kind + ": " + mod.name);
            tvis.hParent = hVb;
            tvis.item.pszText = const_cast<LPWSTR>(wmod.c_str());
            HTREEITEM hMod = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

            for (const auto& ev : mod.events) {
                std::ostringstream ss;
                ss << ev.object_name << "_" << ev.event_name << " [VA: 0x" << std::hex << ev.code_va << "]";
                std::wstring wev = to_wide(ss.str());
                TVINSERTSTRUCTW ev_ins = {};
                ev_ins.hParent = hMod;
                ev_ins.hInsertAfter = TVI_LAST;
                ev_ins.item.mask = TVIF_TEXT;
                ev_ins.item.pszText = const_cast<LPWSTR>(wev.c_str());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ev_ins));
            }
        }
    }

    // 5. VM Architecture & Handlers
    if (vm_rep.is_virtualized) {
        std::wstring wvm = to_wide("VM Virtualization: " + vm_rep.detected_protector);
        tvis.hParent = hRoot;
        tvis.item.pszText = const_cast<LPWSTR>(wvm.c_str());
        HTREEITEM hVm = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

        for (std::size_t i = 0; i < vm_rep.vm_entries.size(); ++i) {
            const auto& e = vm_rep.vm_entries[i];
            std::ostringstream ss;
            ss << "VM Entry [0x" << std::hex << e.entry_va << "] Handlers (" << std::dec << e.identified_handlers.size() << ")";
            std::wstring we = to_wide(ss.str());
            tvis.hParent = hVm;
            tvis.item.pszText = const_cast<LPWSTR>(we.c_str());
            HTREEITEM hEntry = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

            for (const auto& h : e.identified_handlers) {
                std::ostringstream hss;
                hss << h.type << " [0x" << std::hex << h.address << "] (" << std::dec << h.size << " B)";
                std::wstring wh = to_wide(hss.str());
                TVINSERTSTRUCTW h_ins = {};
                h_ins.hParent = hEntry;
                h_ins.hInsertAfter = TVI_LAST;
                h_ins.item.mask = TVIF_TEXT;
                h_ins.item.pszText = const_cast<LPWSTR>(wh.c_str());
                SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&h_ins));
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
            0, 0, 280, 400, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_TREEVIEW)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndTree, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontUI), TRUE);

        // Multi-Language Code & Disassembly View
        g_hwndCode = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            280, 0, 600, 400, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CODE_EDITOR)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndCode, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontCode), TRUE);

        // Deobfuscation & Diagnostic Console
        g_hwndLog = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            0, 400, 880, 150, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOG_LIST)),
            GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_hwndLog, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontCode), TRUE);

        // Status Bar
        g_hwndStatus = CreateWindowExW(
            0, STATUSCLASSNAMEW, L"",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS_BAR)),
            GetModuleHandleW(nullptr), nullptr);

        int parts[] = {320, 600, -1};
        SendMessageW(g_hwndStatus, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
        SetStatusBarText(0, "Ready - TypeMorph Decompiler Studio");
        SetStatusBarText(1, "dnSpy / dotPeek Architecture");
        SetStatusBarText(2, "TypeMorph v0.7.0 C++20");

        LogMessage("// TypeMorph Studio native Win32 desktop UI initialized.");
        LogMessage("// Supports .NET, C/C++, Rust, Dalvik DEX, Delphi, VB6, AutoIt, UPX, VFS & VMProtect.");
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);

        RECT rcStatus;
        SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
        GetWindowRect(g_hwndStatus, &rcStatus);
        int status_h = rcStatus.bottom - rcStatus.top;

        int log_h = 140;
        int tree_w = 280;
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

        // View Mode Switches
        if (id == IDM_VIEW_CSHARP) { if (g_pApp) g_pApp->set_mode(DecompilerMode::csharp); return 0; }
        if (id == IDM_VIEW_C)      { if (g_pApp) g_pApp->set_mode(DecompilerMode::c_source); return 0; }
        if (id == IDM_VIEW_RUST)   { if (g_pApp) g_pApp->set_mode(DecompilerMode::rust_source); return 0; }
        if (id == IDM_VIEW_JAVA)   { if (g_pApp) g_pApp->set_mode(DecompilerMode::dex_java); return 0; }
        if (id == IDM_VIEW_DELPHI) { if (g_pApp) g_pApp->set_mode(DecompilerMode::delphi_pascal); return 0; }
        if (id == IDM_VIEW_VB)     { if (g_pApp) g_pApp->set_mode(DecompilerMode::vb_source); return 0; }
        if (id == IDM_VIEW_AUTOIT) { if (g_pApp) g_pApp->set_mode(DecompilerMode::autoit_script); return 0; }

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
                L"• Delphi & C++Builder VCL Form Rescuer (IDR/DeDe)\n"
                L"• Android Dalvik DEX & Java Engine (JADX style)\n"
                L"• Visual Basic 5/6 Native & P-Code Reconstructor\n"
                L"• AutoIt v3 Token Decompiler (Exe2Aut)\n"
                L"• Virtual Machine Profiler (VMProtect / Themida / NoVmp)\n"
                L"• Universal PE Unpacker (UPX / ASPack / PECompact)\n"
                L"• VFS Container Extractor (Spoon Studio / Enigma Virtual Box)",
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
    AppendMenuW(hFile, MF_STRING, IDM_FILE_OPEN, L"&Open Binary / Assembly...\tCtrl+O");
    AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFile, MF_STRING, IDM_FILE_EXIT, L"E&xit");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFile), L"&File");

    // Decompile Language Menu
    HMENU hDecompile = CreatePopupMenu();
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_CSHARP, L"&C# Decompiler (.NET)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_C,      L"Structured &C Pseudocode (Native x86/x64)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_RUST,   L"&Rust Semantic Source Reconstructor");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_JAVA,   L"&Java Source (Android Dalvik DEX)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_DELPHI, L"&Pascal Units (Delphi VCL Forms)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_VB,     L"&Visual Basic 5/6 Source (.frm / .bas)");
    AppendMenuW(hDecompile, MF_STRING, IDM_VIEW_AUTOIT, L"&AutoIt v3 Script (.au3)");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDecompile), L"&Decompile");

    // Deobfuscate & Clean Menu
    HMENU hDeobf = CreatePopupMenu();
    AppendMenuW(hDeobf, MF_STRING, IDM_ACTION_DEOBF, L"&Clean .NET Assembly (ConfuserEx / .NET Reactor)\tF5");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDeobf), L"De&obfuscate");

    // Protection & Analysis Menu
    HMENU hAnalysis = CreatePopupMenu();
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_DETECT,    L"&Compiler & Packer Detection (DIE Engine)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_VMPROFILE, L"&Virtual Machine Profiler (VMProtect / Themida)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_UNPACK,    L"&Universal PE Unpacker & Header Fix (UPX / ASPack)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_VFS,       L"&Virtual Filesystem Payload Extractor (Spoon/Enigma)");
    AppendMenuW(hAnalysis, MF_STRING, IDM_ACTION_IATFIX,    L"&Import Address Table (IAT) Reconstructor");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hAnalysis), L"&Analysis");

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

    const auto& v = view.value();

    // 1. Run detectors across all subsystems
    dotnet::DotNetAnalyzer dotnet_an;
    dotnet_report_ = dotnet_an.analyze_view(v);

    delphi_report_ = delphi::DelphiAnalyzer::analyze(v);
    dex_report_    = dex::DexAnalyzer::analyze(v);
    vb_report_     = vb::VbAnalyzer::analyze(v);
    autoit_report_ = autoit::AutoItDecompiler::analyze(v);
    vfs_report_    = unpack::VfsExtractor::analyze(v);
    unpack_target_ = unpack::UniversalUnpacker::detect(v);
    vm_report_     = vm::VmProfiler::analyze(v);

    // 2. Identify primary engine
    std::string filename = path;
    auto last_slash = filename.find_last_of("\\/");
    if (last_slash != std::string::npos) filename = filename.substr(last_slash + 1);

    PopulateTree(filename, dotnet_report_, delphi_report_, dex_report_, vb_report_, vm_report_);

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
    } else {
        // Native PE / ELF / Mach-O binary -> Native C pseudocode
        set_mode(DecompilerMode::c_source);
        SetStatusBarText(1, "Native Binary");
        SetStatusBarText(2, "Size: " + std::to_string(v.size()) + " B");
    }

    SetStatusBarText(0, "Loaded: " + filename);
    LogMessage("[TypeMorph] Successfully loaded: " + filename);
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
        L"TypeMorph Studio - Multi-Language Decompiler & Deobfuscator (dnSpy / dotPeek Architecture)",
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

// TypeMorph - Standalone Native Desktop GUI Application Implementation (dnSpy / dotPeek style)
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
                  const vm::VmProfileReport& vm_rep,
                  const golang::GoAnalysisReport& go_rep,
                  const lua::LuaDecompileReport& lua_rep) {
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

    // 6. Go pclntab & Metadata (if present)
    if (go_rep.detected) {
        std::wstring wgo = to_wide("Go Runtime (" + std::string(golang::to_string(go_rep.version)) + ")");
        tvis.hParent = hRoot;
        tvis.item.pszText = const_cast<LPWSTR>(wgo.c_str());
        HTREEITEM hGo = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

        for (const auto& s : go_rep.structs) {
            std::wstring ws = to_wide("type " + s.name + " struct");
            TVINSERTSTRUCTW s_ins = {};
            s_ins.hParent = hGo;
            s_ins.hInsertAfter = TVI_LAST;
            s_ins.item.mask = TVIF_TEXT;
            s_ins.item.pszText = const_cast<LPWSTR>(ws.c_str());
            SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&s_ins));
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(go_rep.functions.size(), 50); ++i) {
            std::wstring wf = to_wide("func " + go_rep.functions[i].name);
            TVINSERTSTRUCTW f_ins = {};
            f_ins.hParent = hGo;
            f_ins.hInsertAfter = TVI_LAST;
            f_ins.item.mask = TVIF_TEXT;
            f_ins.item.pszText = const_cast<LPWSTR>(wf.c_str());
            SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&f_ins));
        }
    }

    // 7. Lua Bytecode Functions
    if (lua_rep.is_lua_bytecode) {
        std::wstring wlua = to_wide("Lua Bytecode (" + std::string(lua::to_string(lua_rep.flavor)) + ")");
        tvis.hParent = hRoot;
        tvis.item.pszText = const_cast<LPWSTR>(wlua.c_str());
        HTREEITEM hLua = reinterpret_cast<HTREEITEM>(SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&tvis)));

        std::wstring wr = to_wide("main (root chunk) [" + std::to_string(lua_rep.root_function.instructions.size()) + " insns]");
        TVINSERTSTRUCTW r_ins = {};
        r_ins.hParent = hLua;
        r_ins.hInsertAfter = TVI_LAST;
        r_ins.item.mask = TVIF_TEXT;
        r_ins.item.pszText = const_cast<LPWSTR>(wr.c_str());
        SendMessageW(g_hwndTree, TVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&r_ins));
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

    golang::GoAnalyzer go_an;
    auto img_res_go = core::ExecutableImage::parse(v);
    go_report_ = img_res_go ? go_an.analyze(img_res_go.value()) : go_an.analyze_view(v);

    // 2. Identify primary engine
    std::string filename = path;
    auto last_slash = filename.find_last_of("\\/");
    if (last_slash != std::string::npos) filename = filename.substr(last_slash + 1);

    PopulateTree(filename, dotnet_report_, delphi_report_, dex_report_, vb_report_, vm_report_, go_report_, lua_report_);

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

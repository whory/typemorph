// TypeMorph - Standalone Native Desktop GUI Application (dnSpy / dotPeek style)
//
// Pure C++20 Win32 native implementation:
// - Left pane: Hierarchical Explorer TreeView (Assemblies, Delphi Forms, DEX Packages, Functions, Strings, Classes, Handlers)
// - Center pane: Multi-language Decompiler & Disassembly Editor (C#, C, Rust, Dalvik, Pascal, VB, Lua)
// - Right/Bottom pane: Diagnostic Inspector, Token List, Log, Security & VM Profiler
// - Comprehensive Menu: File, Decompile, Deobfuscate, Analysis, Tools, View, Help
#pragma once

#ifdef _WIN32

#include "typemorph/core/binary_view.hpp"
#include "typemorph/dotnet/dotnet_analyzer.hpp"
#include "typemorph/dotnet/dotnet_deobf.hpp"
#include "typemorph/delphi/delphi_analyzer.hpp"
#include "typemorph/dex/dex_analyzer.hpp"
#include "typemorph/vb/vb_analyzer.hpp"
#include "typemorph/autoit/autoit_decompiler.hpp"
#include "typemorph/unpack/vfs_extractor.hpp"
#include "typemorph/unpack/universal_unpacker.hpp"
#include "typemorph/vm/vm_analyzer.hpp"
#include "typemorph/decompile/c_decompiler.hpp"
#include "typemorph/derust/rust_source.hpp"
#include "typemorph/detect/detect_engine.hpp"
#include "typemorph/pe/iat_reconstructor.hpp"
#include "typemorph/dump/dump_fixer.hpp"

#include <string>
#include <vector>

namespace typemorph::gui {

enum class DecompilerMode {
    csharp,
    c_source,
    rust_source,
    dex_java,
    delphi_pascal,
    vb_source,
    autoit_script,
    vm_profile,
    unpack_summary,
    vfs_summary,
    raw_disasm
};

class StudioApp {
public:
    StudioApp() = default;
    ~StudioApp() = default;

    int run(const std::string& initial_file = "");

    void open_file(const std::string& path);
    void deobfuscate_current();
    void set_mode(DecompilerMode mode);
    void run_detection();
    void run_vm_analysis();
    void run_unpack();
    void run_vfs_extract();
    void run_iat_fix();
    void run_memdump_fix();

private:
    std::string current_file_;
    DecompilerMode mode_ = DecompilerMode::csharp;

    dotnet::DotNetReport dotnet_report_;
    dotnet::DotNetDeobfReport dotnet_deobf_report_;
    delphi::DelphiReport delphi_report_;
    dex::DexReport dex_report_;
    vb::VbReport vb_report_;
    autoit::AutoItReport autoit_report_;
    unpack::VfsContainerReport vfs_report_;
    unpack::UnpackTarget unpack_target_;
    vm::VmProfileReport vm_report_;
    detect::DetectionReport detect_result_;

    bool is_deobfuscated_ = false;
};

// Global entry point for launching the native dnSpy-style GUI
int run_native_studio(int argc, char** argv);

}  // namespace typemorph::gui

#endif  // _WIN32

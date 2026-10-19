// TypeMorph - Standalone Native Desktop GUI Application (dnSpy / dotPeek style)
//
// Pure C++20 Win32 native implementation:
// - Left pane: Assembly Explorer TreeView (Assemblies, Namespaces, Types, Members)
// - Center pane: Multi-tab C# Decompiler & CIL Disassembly Editor
// - Bottom pane: Deobfuscation Log, Token Inspector & Output
// - Top toolbar & menu: File, Deobfuscate (ConfuserEx inliner, string decryptor, switch killer)
#pragma once

#ifdef _WIN32

#include "typemorph/core/binary_view.hpp"
#include "typemorph/dotnet/dotnet_analyzer.hpp"
#include "typemorph/dotnet/dotnet_deobf.hpp"

#include <string>
#include <vector>

namespace typemorph::gui {

class StudioApp {
public:
    StudioApp() = default;
    ~StudioApp() = default;

    int run(const std::string& initial_file = "");

    void open_file(const std::string& path);
    void deobfuscate_current();

private:
    std::string current_file_;
    dotnet::DotNetReport current_report_;
    dotnet::DotNetDeobfReport current_deobf_report_;
    bool is_deobfuscated_ = false;
};

// Global entry point for launching the native dnSpy-style GUI
int run_native_studio(int argc, char** argv);

}  // namespace typemorph::gui

#endif  // _WIN32
